use crate::commands::CliOpts;
use crate::commands::*;
use crate::utils::{open_main_database, prepare_home_dir};

use bdk::bitcoin::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, Fingerprint, KeySource};
use bdk::bitcoin::psbt::PartiallySignedTransaction;
use bdk::bitcoin::secp256k1::{All, PublicKey, Secp256k1};
use bdk::bitcoin::{key::XOnlyPublicKey, Address, Network, PrivateKey};

use bdk::keys::bip39::{Language, Mnemonic, WordCount};
use bdk::keys::DescriptorKey::Secret;
use bdk::keys::KeyError::{InvalidNetwork, Message};
use bdk::keys::{
    DerivableKey, DescriptorKey, DescriptorSecretKey, ExtendedKey, GeneratableKey, GeneratedKey,
    SinglePriv, SinglePubKey,
};

use bdk::miniscript::{BareCtx, DescriptorPublicKey, Tap};
use bdk::signer::{InputSigner, SignerContext, SignerError, SignerWrapper};
use bdk::{Error, SignOptions};

use serde::{Deserialize, Serialize};
use serde_json::json;
use sled::transaction::abort;
use std::cell::RefCell;
use std::collections::HashMap;
use std::str::FromStr;
use std::vec;

const WALLET_NAMES_DB_KEY: &str = "wallet_names";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeritagePrivateWallet {
    name: String,
    mnemonic: Mnemonic,
    network: Network,
    fingerprint: Fingerprint,
    with_passphrase: bool,
    #[serde(skip)]
    cached_passphrase: RefCell<Option<String>>,
}

impl HeritagePrivateWallet {
    fn xprv(&self, secp: &Secp256k1<All>) -> Result<ExtendedPrivKey, Error> {
        let xprv = if self.with_passphrase {
            if self.cached_passphrase.borrow().is_none() {
                let passphrase = prompt_user_for_passphrase(false)?;
                let _ = self.cached_passphrase.borrow_mut().insert(passphrase);
            };
            xprv_from_mnemonic(
                &self.mnemonic,
                Some(self.cached_passphrase.borrow().as_ref().unwrap()),
                self.network,
            )?
        } else {
            xprv_from_mnemonic(&self.mnemonic, None, self.network)?
        };

        if xprv.fingerprint(secp) != self.fingerprint {
            return Err(Error::Generic(
                "Recovered incorrect xprv. Is the passphrase correct?".to_owned(),
            ));
        }
        Ok(xprv)
    }
}

pub(crate) fn handle_command(cli_opts: CliOpts) -> Result<String, Error> {
    log::debug!("Processing {:?}", cli_opts);
    let network = cli_opts.network;
    let home_dir = prepare_home_dir(&cli_opts.datadir)?;
    let db = open_main_database(&home_dir, network)?;
    let secp = Secp256k1::new();
    let result = match cli_opts.subcommand {
        CliSubCommand::ListWallets => {
            log::debug!("Processing ListWallets sub-command");
            let wallet_names = list_wallet_names(&db)?;
            let wallet_names = json!(wallet_names).to_string();
            log::debug!("wallet_names={}", &wallet_names);
            wallet_names
        }
        CliSubCommand::Generate {
            wallet_opts,
            mnemo_opts,
            word_count,
            entropy,
        } => {
            println!("entropy={entropy:?}");
            log::debug!("Processing Generate sub-command with: {:?}", wallet_opts);
            if db_key_exist(&db, &wallet_opts.wallet_name)? {
                return Err(Error::Generic(format!(
                    "Wallet with name {} already exists",
                    wallet_opts.wallet_name
                )));
            }
            let word_count = crate::utils::mnemo_word_count_parser(&word_count)
                .map_err(|e| Error::Generic(e))?;

            let mnemonic = if let Some(entropy_string) = entropy {
                let entropy_bytes = crate::utils::hex_string_to_bytes(&entropy_string)
                    .map_err(|e| Error::Generic(e))?;
                let entropy_needed = word_count as usize;
                let entropy_provided = entropy_bytes.len() * 8;
                if entropy_needed != entropy_provided {
                    return Err(Error::Generic(format!(
                        "Mnemonic word count is equivalent to {} bits but provided entropy is {} bits",
                        entropy_needed, entropy_provided
                    )));
                }
                Mnemonic::from_entropy(&entropy_bytes).map_err(|e| Error::Generic(e.to_string()))?
            } else {
                generate_mnemonic(word_count)?
            };

            let passphrase = if mnemo_opts.with_passphrase {
                Some(prompt_user_for_passphrase(true)?)
            } else {
                None
            };

            let new_wallet = heritage_wallet_from_mnemonic(
                &wallet_opts.wallet_name,
                mnemonic,
                passphrase.as_ref().map(|s| s.as_str()),
                network,
                &secp,
            )?;
            log::debug!(
                "New wallet generated (fingerprint={})",
                new_wallet.fingerprint
            );
            add_wallet(&db, &new_wallet)?;
            serde_json::to_string_pretty(&new_wallet)?
        }
        CliSubCommand::ShowWalletInfo { wallet_opts } => {
            log::debug!("Processing GetMnemonic sub-command with: {:?}", wallet_opts);
            if !db_key_exist(&db, &wallet_opts.wallet_name)? {
                return Err(Error::Generic(format!(
                    "Wallet with name {} does not exist",
                    wallet_opts.wallet_name
                )));
            }
            let wallet = get_wallet(&db, &wallet_opts.wallet_name)?;
            format!(
                "{:#}",
                json!({"name": wallet.name, "fingerprint": wallet.fingerprint, "network": wallet.network, "with_passphrase": wallet.with_passphrase,})
            )
        }
        CliSubCommand::ShowPrivateWalletInfo {
            wallet_opts,
            i_understand_what_i_am_doing: _,
        } => {
            log::debug!("Processing GetMnemonic sub-command with: {:?}", wallet_opts);
            if !db_key_exist(&db, &wallet_opts.wallet_name)? {
                return Err(Error::Generic(format!(
                    "Wallet with name {} does not exist",
                    wallet_opts.wallet_name
                )));
            }
            let wallet = get_wallet(&db, &wallet_opts.wallet_name)?;
            serde_json::to_string_pretty(&wallet)?
        }
        CliSubCommand::Restore {
            words,
            wallet_opts,
            mnemo_opts,
        } => {
            let mnemonic = words.join(" ");
            log::debug!(
                "Processing Restore sub-command with: {:?}, mnemonic: {}",
                wallet_opts,
                mnemonic
            );
            if db_key_exist(&db, &wallet_opts.wallet_name)? {
                return Err(Error::Generic(format!(
                    "Wallet with name {} already exists",
                    wallet_opts.wallet_name
                )));
            }
            let mnemonic = parse_mnemonic(&mnemonic)?;
            let passphrase = if mnemo_opts.with_passphrase {
                Some(prompt_user_for_passphrase(true)?)
            } else {
                None
            };
            let new_wallet = heritage_wallet_from_mnemonic(
                &wallet_opts.wallet_name,
                mnemonic,
                passphrase.as_ref().map(|s| s.as_str()),
                network,
                &secp,
            )?;
            log::debug!("Wallet restored (fingerprint={})", new_wallet.fingerprint);
            add_wallet(&db, &new_wallet)?;
            serde_json::to_string_pretty(&new_wallet)?
        }
        CliSubCommand::GetXpubs { wallet_opts, count } => {
            log::debug!(
                "Processing GetXpubs sub-command with: {:?}, count: {}",
                wallet_opts,
                count
            );
            if !db_key_exist(&db, &wallet_opts.wallet_name)? {
                return Err(Error::Generic(format!(
                    "Wallet with name {} does not exist",
                    wallet_opts.wallet_name
                )));
            }
            let wallet = get_wallet(&db, &wallet_opts.wallet_name)?;
            let xpubs = derive_accounts_xpubs(&wallet, count, network, &secp)?;
            let xpubs: Vec<String> = xpubs.into_iter().map(|xp| xp.to_string()).collect();
            xpubs.join("\n")
        }
        CliSubCommand::GetHeirPubkey { wallet_opts, index } => {
            log::debug!(
                "Processing GetHeirPubkey sub-command with: {:?}, index: {}",
                wallet_opts,
                index
            );
            if !db_key_exist(&db, &wallet_opts.wallet_name)? {
                return Err(Error::Generic(format!(
                    "Wallet with name {} does not exist",
                    wallet_opts.wallet_name
                )));
            }
            let wallet = get_wallet(&db, &wallet_opts.wallet_name)?;
            let xpub = derive_descriptor_public_key(&wallet, index, network, &secp)?;
            xpub.to_string()
        }
        CliSubCommand::Sign { wallet_opts, psbt } => {
            log::debug!(
                "Processing Sign sub-command with: {:?}, psbt: {}",
                wallet_opts,
                psbt
            );
            let wallet = get_wallet(&db, &wallet_opts.wallet_name)?;

            let mut psbt = PartiallySignedTransaction::from_str(&psbt)?;
            log::debug!("{:?}", psbt);

            let psbt_modified = sign_psbt_tap_inputs(&mut psbt, wallet.xprv(&secp)?, &secp)?;
            if psbt_modified {
                psbt.to_string()
            } else {
                return Err(Error::Generic(format!(
                    "No input can be signed with wallet {}",
                    wallet_opts.wallet_name
                )));
            }
        }
        CliSubCommand::DisplayPsbt { psbt, full } => {
            log::debug!(
                "Processing DisplayPsbt sub-command with: psbt: {} full: {}",
                psbt,
                full
            );

            let psbt = PartiallySignedTransaction::from_str(&psbt)?;

            if full {
                serde_json::to_string_pretty(&psbt)?
            } else {
                let wallet_fingerprints = fingerprint_to_wallet_name_map(&db)?;
                let summary = generate_psbt_summary(&psbt, wallet_fingerprints, network)?;
                serde_json::to_string_pretty(&summary)?
            }
        }
    };
    Ok(result)
}

fn list_wallet_names(db: &sled::Tree) -> Result<Vec<String>, Error> {
    let res = db.get(WALLET_NAMES_DB_KEY)?;
    Ok(match res {
        Some(ivec) => {
            log::debug!("Key `{WALLET_NAMES_DB_KEY}` exist in DB");
            serde_json::from_slice(&ivec)?
        }
        None => {
            log::debug!("Key `{WALLET_NAMES_DB_KEY}` does not exist in DB");
            [].to_vec()
        }
    })
}

fn fingerprint_to_wallet_name_map(db: &sled::Tree) -> Result<HashMap<Fingerprint, String>, Error> {
    let wallet_names = list_wallet_names(db)?;

    wallet_names
        .into_iter()
        .map(|name| {
            let wallet = get_wallet(db, &name)?;
            Ok((wallet.fingerprint, name))
        })
        .collect()
}

fn db_key_exist(db: &sled::Tree, key: &str) -> Result<bool, Error> {
    Ok(db.get(key)?.is_some())
}

fn add_wallet(db: &sled::Tree, wallet: &HeritagePrivateWallet) -> Result<(), Error> {
    let wallet_name: &str = &wallet.name;
    let db_wallet_value: Vec<u8> = serde_json::to_vec(wallet)?;
    let db_wallet_value: &[u8] = db_wallet_value.as_ref();

    let current_wallet_list = db.get(WALLET_NAMES_DB_KEY)?;

    if db_key_exist(db, wallet_name)? {
        return Err(Error::Generic(format!(
            "Wallet with name {wallet_name} already exists"
        )));
    }

    let new_wallet_list = match &current_wallet_list {
        Some(ivec) => {
            let mut wallets_names: Vec<String> = serde_json::from_slice(ivec)?;
            wallets_names.push(wallet.name.clone());
            wallets_names
        }
        None => vec![wallet.name.clone()],
    };
    let new_wallet_list: Vec<u8> = serde_json::to_vec(&new_wallet_list)?;
    let new_wallet_list: &[u8] = new_wallet_list.as_ref();

    db.transaction(|tx_db| {
        tx_db.insert(wallet_name, db_wallet_value)?;
        let wallets_names = tx_db.remove(WALLET_NAMES_DB_KEY)?;
        if wallets_names != current_wallet_list {
            abort("Wallet list changed")?;
        }
        tx_db.insert(WALLET_NAMES_DB_KEY, new_wallet_list)?;
        Ok(())
    })
    .map_err(|e| Error::Generic(e.to_string()))?;

    Ok(())
}

fn get_wallet(db: &sled::Tree, wallet_name: &str) -> Result<HeritagePrivateWallet, Error> {
    let res = db
        .get(wallet_name)?
        .expect("wallet should be in DB at this point");
    Ok(serde_json::from_slice(&res)?)
}

fn generate_mnemonic(word_count: WordCount) -> Result<Mnemonic, Error> {
    let mnemonic: GeneratedKey<_, BareCtx> = Mnemonic::generate((word_count, Language::English))
        .map_err(|_| Error::Generic("Mnemonic generation error".to_string()))?;
    let mnemonic = mnemonic.into_key();
    Ok(mnemonic)
}

fn parse_mnemonic(mnemonic: &str) -> Result<Mnemonic, Error> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)
        .map_err(|e| Error::Generic(e.to_string()))?;
    Ok(mnemonic)
}

fn prompt_user_for_passphrase(double_check: bool) -> Result<String, Error> {
    let passphrase1 = rpassword::prompt_password("Please enter the passphrase: ")
        .map_err(|e| Error::Generic(e.to_string()))?;
    if double_check {
        let passphrase2 = rpassword::prompt_password("Please re-enter the passphrase: ")
            .map_err(|e| Error::Generic(e.to_string()))?;
        if passphrase1 != passphrase2 {
            return Err(Error::Generic("Passphrases did not match".to_owned()));
        }
    }
    Ok(passphrase1)
}

fn xprv_from_mnemonic(
    mnemo: &Mnemonic,
    passphrase: Option<&str>,
    network: Network,
) -> Result<ExtendedPrivKey, Error> {
    let xkey: ExtendedKey =
        (mnemo.clone(), passphrase.map(|s| s.to_owned())).into_extended_key()?;
    let xprv = xkey.into_xprv(network).ok_or_else(|| {
        Error::Generic("Privatekey info not found (should not happen)".to_string())
    })?;
    Ok(xprv)
}

fn heritage_wallet_from_mnemonic(
    name: &str,
    mnemonic: Mnemonic,
    passphrase: Option<&str>,
    network: Network,
    secp: &Secp256k1<All>,
) -> Result<HeritagePrivateWallet, Error> {
    let xprv = xprv_from_mnemonic(&mnemonic, passphrase, network)?;
    let fingerprint = xprv.fingerprint(secp);
    Ok(HeritagePrivateWallet {
        name: name.to_string(),
        mnemonic,
        network,
        fingerprint,
        with_passphrase: passphrase.is_some(),
        cached_passphrase: RefCell::new(None),
    })
}

fn sign_psbt_tap_inputs(
    psbt: &mut PartiallySignedTransaction,
    xprv: ExtendedPrivKey,
    secp: &Secp256k1<All>,
) -> Result<bool, Error> {
    let sign_options = SignOptions::default();
    let fingerprint = &xprv.fingerprint(&secp);
    let network = xprv.network;
    let cointype_path_segment = match network {
        Network::Bitcoin => "0",
        _ => "1",
    };
    let base_derivation_path = format!("m/86'/{cointype_path_segment}'");
    let base_derivation_path = DerivationPath::from_str(&base_derivation_path)?;
    let xkey = xprv.derive_priv(secp, &base_derivation_path)?;

    log::debug!("PSBT has {} input(s)", psbt.inputs.len());
    let mut signed_inputs = 0usize;
    let mut signatures_count = 0usize;
    for input_index in 0..psbt.inputs.len() {
        // We completly ignore the bip32_derivation property of the PSBT
        // and go straight for the tap_key_origins as we are not expecting
        // to handle anything else
        let input = &psbt.inputs[input_index];
        let signing_keys = input
            .tap_key_origins
            .iter()
            .map(|(pk, (_, keysource))| (SinglePubKey::XOnly(*pk), keysource))
            .filter_map(|(pk, keysource)| {
                // Verify that the key source matches the current wallet
                // Extract the fingerprint and derivation path of the input
                let (input_key_fingerprint, input_key_derivationpath) = keysource;
                // Verify that the fingerprint match the one of our wallet
                // and the derivation path is a sub-path of our xprv (we only consider m/86'/{cointype}'/*)
                if *input_key_fingerprint == *fingerprint
                    && is_common_derivation_path(input_key_derivationpath, &base_derivation_path)
                {
                    Some((pk, input_key_derivationpath.clone()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if signing_keys.len() == 0 {
            log::debug!("Input #{input_index} is not for our wallet");
            continue;
        };

        if input.final_script_sig.is_some() || input.final_script_witness.is_some() {
            log::debug!("Input #{input_index} is for our wallet but already signed");
            continue;
        }

        let internalkey = input.tap_internal_key.ok_or(Error::Generic(
            "With can only sign Taproot inputs".to_owned(),
        ))?;

        let mut input_signed = false;
        for (public_key, full_path) in signing_keys {
            let derived_key = {
                let deriv_path = DerivationPath::from(
                    &full_path.into_iter().cloned().collect::<Vec<ChildNumber>>()
                        [base_derivation_path.len()..],
                );
                xkey.derive_priv(secp, &deriv_path).unwrap()
            };

            let computed_pk = PublicKey::from_secret_key(secp, &derived_key.private_key);
            let valid_key = match public_key {
                SinglePubKey::FullKey(pk) if pk.inner == computed_pk => true,
                SinglePubKey::XOnly(x_only) if XOnlyPublicKey::from(computed_pk) == x_only => true,
                _ => false,
            };

            if !valid_key {
                return Err(Error::Signer(SignerError::InvalidKey));
            } else {
                log::debug!(
                    "Signing input #{input_index} with privatekey derived at [{fingerprint}/{full_path}]"
                );

                let ctx = SignerContext::Tap {
                    is_internal_key: XOnlyPublicKey::from(computed_pk) == internalkey,
                };

                // HD wallets imply compressed keys
                let priv_key = PrivateKey {
                    compressed: true,
                    network: network,
                    inner: derived_key.private_key,
                };

                SignerWrapper::new(priv_key, ctx).sign_input(
                    psbt,
                    input_index,
                    &sign_options,
                    secp,
                )?;

                signatures_count += 1;
                input_signed = true;
            }
        }
        if input_signed {
            signed_inputs += 1;
        }
    }
    log::debug!("Applied {signatures_count} signature(s) to {signed_inputs} input(s)");
    Ok(signatures_count > 0)
}

fn derive_accounts_xpubs(
    wallet: &HeritagePrivateWallet,
    count: usize,
    network: Network,
    secp: &Secp256k1<All>,
) -> Result<Vec<DescriptorPublicKey>, Error> {
    let xprv = wallet.xprv(secp)?;
    if xprv.network != network {
        return Err(Error::Key(InvalidNetwork));
    }
    let cointype_path_segment = match network {
        Network::Bitcoin => 0,
        _ => 1,
    };
    let base_derivation_path = vec![
        ChildNumber::from_hardened_idx(86)?,
        ChildNumber::from_hardened_idx(cointype_path_segment)?,
    ];
    let base_derivation_path = DerivationPath::from(base_derivation_path);

    let xpubs: Result<Vec<DescriptorPublicKey>, Error> = base_derivation_path
        .hardened_children()
        .take(count)
        .map(|derivation_path| {
            let derived_xprv = &xprv.derive_priv(secp, &derivation_path)?;
            let origin: KeySource = (xprv.fingerprint(secp), derivation_path);
            let derived_xprv_desc_key: DescriptorKey<Tap> =
                derived_xprv.into_descriptor_key(Some(origin), DerivationPath::default())?;
            if let Secret(desc_seckey, _, _) = derived_xprv_desc_key {
                let desc_pubkey = desc_seckey
                    .to_public(&secp)
                    .map_err(|e| Error::Generic(e.to_string()))?;
                Ok(desc_pubkey)
            } else {
                Err(Error::Key(Message("Invalid key variant".to_string())))
            }
        })
        .collect();
    xpubs
}

fn derive_descriptor_public_key(
    wallet: &HeritagePrivateWallet,
    index: u32,
    network: Network,
    secp: &Secp256k1<All>,
) -> Result<DescriptorPublicKey, Error> {
    let xprv = wallet.xprv(secp)?;
    if xprv.network != network {
        return Err(Error::Key(InvalidNetwork));
    }
    let cointype_path_segment = match network {
        Network::Bitcoin => 0u32,
        _ => 1u32,
    };
    let derivation_path = vec![
        ChildNumber::from_hardened_idx(86)?,
        ChildNumber::from_hardened_idx(cointype_path_segment)?,
        ChildNumber::from_hardened_idx(u32::from_be_bytes(*b"heir"))?,
        ChildNumber::from_normal_idx(0)?,
        ChildNumber::from_normal_idx(index)?,
    ];
    let derivation_path = DerivationPath::from(derivation_path);
    let derived_xprv = &xprv.derive_priv(secp, &derivation_path)?;
    let origin: KeySource = (xprv.fingerprint(secp), derivation_path);
    let derived_xprv_desc_key = DescriptorSecretKey::Single(SinglePriv {
        origin: Some(origin),
        key: derived_xprv.to_priv(),
    });
    derived_xprv_desc_key
        .to_public(secp)
        .map_err(|e| Error::Generic(e.to_string()))
}

fn is_common_derivation_path(d1: &DerivationPath, d2: &DerivationPath) -> bool {
    d1.into_iter().zip(d2.into_iter()).all(|(l, r)| *l == *r)
}

#[derive(Debug, Serialize)]
struct InputSummary {
    previous_output: String,
    address: String,
    amount: u64,
    wallet_that_can_spend: Vec<String>,
}
#[derive(Debug, Serialize)]
struct OutputSummary {
    address: String,
    amount: u64,
    owned_by_wallet: Option<String>,
}
#[derive(Debug, Serialize)]
struct PsbtSummary {
    inputs: Vec<InputSummary>,
    outputs: Vec<OutputSummary>,
    total_spend: u64,
    send_out: u64,
    change: u64,
    fee: u64,
}

// Create a text describing the PSBT and highlighting:
// Number of inputs
// For each input, can be signed and with which wallet, amount
// Number of ouputs
// For each output, does it belong to us and which wallet, amount
// Fees
fn generate_psbt_summary(
    psbt: &PartiallySignedTransaction,
    wallet_fingerprints: HashMap<Fingerprint, String>,
    network: Network,
) -> Result<PsbtSummary, Error> {
    let cointype_path_segment = match network {
        Network::Bitcoin => "0",
        _ => "1",
    };
    let base_derivation_path = format!("m/86'/{cointype_path_segment}'");
    let base_derivation_path = DerivationPath::from_str(&base_derivation_path)?;

    let inputs = psbt
        .unsigned_tx
        .input
        .iter()
        .zip(psbt.inputs.iter())
        .map(|(i1, i2)| {
            let (address, amount) = if let Some(witness) = &i2.witness_utxo {
                (
                    Address::from_script(&witness.script_pubkey, network)
                        .map_err(|e| Error::Generic(e.to_string()))?,
                    witness.value,
                )
            } else if let Some(prev_tx) = &i2.non_witness_utxo {
                let txout = &prev_tx.output[i1.previous_output.vout as usize];
                (
                    Address::from_script(&txout.script_pubkey, network)
                        .map_err(|e| Error::Generic(e.to_string()))?,
                    txout.value,
                )
            } else {
                unreachable!("PSBT input should always have either witness or non_witness UTXO");
            };
            let address = address.to_string();
            let wallet_that_can_spend = i2
                .tap_key_origins
                .iter()
                .filter_map(|(_, (_, (f, dp)))| {
                    if is_common_derivation_path(dp, &base_derivation_path) {
                        wallet_fingerprints.get(f)
                    } else {
                        None
                    }
                })
                .cloned()
                .collect();
            Ok(InputSummary {
                previous_output: i1.previous_output.to_string(),
                address,
                amount,
                wallet_that_can_spend,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let outputs = psbt
        .unsigned_tx
        .output
        .iter()
        .zip(psbt.outputs.iter())
        .map(|(o1, o2)| {
            let address = Address::from_script(&o1.script_pubkey, network)
                .map_err(|e| Error::Generic(e.to_string()))?;
            let address = address.to_string();
            let amount = o1.value;

            let owned_by_wallet = if let Some(xkey) = o2.tap_internal_key {
                o2.tap_key_origins
                    .get(&xkey)
                    .filter(|(_, (f, dp))| {
                        is_common_derivation_path(dp, &base_derivation_path)
                            && wallet_fingerprints.contains_key(f)
                    })
                    .map(|(_, (f, _))| wallet_fingerprints.get(f).unwrap().clone())
            } else {
                None
            };

            Ok(OutputSummary {
                address,
                amount,
                owned_by_wallet,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let total_spend: u64 = inputs.iter().map(|is| is.amount).sum();
    let mut send_out = 0u64;
    let mut change = 0u64;
    for o in outputs.iter() {
        if o.owned_by_wallet.is_some() {
            change += o.amount;
        } else {
            send_out += o.amount;
        }
    }
    let fee = total_spend
        .checked_sub(send_out + change)
        .ok_or(Error::Generic(
            "Invalid PSBT. Fee cannot be negative".to_owned(),
        ))?;

    Ok(PsbtSummary {
        inputs,
        outputs,
        total_spend,
        send_out,
        change,
        fee,
    })
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use crate::utils::hex_string_to_bytes;

    use super::*;
    const NETWORK: Network = Network::Regtest;

    /// In order:
    /// - Owner/Recipients
    /// - Owner/Drain
    /// - Backup/Drain - Present
    /// - Wife/Drain - Present
    /// - Backup/Drain - Future
    /// - Wife/Drain - Future
    /// - Brother/Drain - Future
    const UNSIGNED_PSBTS: [&str; 7] = [
        "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",
    ];
    #[derive(Debug, Clone, Copy)]
    pub enum TestPsbt {
        OwnerRecipients,
        OwnerDrain,
        BackupPresent,
        WifePresent,
        BackupFuture,
        WifeFuture,
        BrotherFuture,
    }

    fn get_test_unsigned_psbt_str(tp: TestPsbt) -> &'static str {
        UNSIGNED_PSBTS[tp as usize]
    }
    fn get_test_unsigned_psbt(tp: TestPsbt) -> PartiallySignedTransaction {
        PartiallySignedTransaction::from_str(get_test_unsigned_psbt_str(tp)).unwrap()
    }

    const WALLETS: [[&str; 2]; 5] = [
        [
            "owner_wallet",
            "owner owner owner owner owner owner owner owner owner owner owner panther"
        ],
        [
            "backup_wallet",
            "save save save save save save save save save save save same"
        ],
        [
            "wife_wallet",
            "wife wife wife wife wife wife wife wife wife wife wife wide"
        ],
        [
            "brother_wallet",
            "brother brother brother brother brother brother brother brother brother brother brother bronze"
        ],
        [
            "random_wallet",
            ""
        ],
    ];

    enum TestWallet {
        Owner = 0,
        Backup = 1,
        Wife = 2,
        Brother = 3,
        Random = 4,
    }

    fn get_test_wallet_name(tw: TestWallet) -> &'static str {
        WALLETS[tw as usize][0]
    }
    fn get_test_wallet_mnemo(tw: TestWallet) -> Mnemonic {
        parse_mnemonic(WALLETS[tw as usize][1]).unwrap()
    }

    struct TestEnv {
        db: sled::Db,
        secp: Secp256k1<All>,
        _tmpdir: tempfile::TempDir,
    }

    // Utilitary function that create a temp database that will be removed at the end
    fn setup_test_env() -> TestEnv {
        let tmpdir = tempfile::tempdir().unwrap();
        let db = open_main_database(tmpdir.path(), NETWORK).unwrap();
        let secp = Secp256k1::new();
        add_wallet(
            &db,
            &heritage_wallet_from_mnemonic(
                get_test_wallet_name(TestWallet::Owner),
                get_test_wallet_mnemo(TestWallet::Owner),
                None,
                NETWORK,
                &secp,
            )
            .unwrap(),
        )
        .unwrap();
        add_wallet(
            &db,
            &heritage_wallet_from_mnemonic(
                get_test_wallet_name(TestWallet::Backup),
                get_test_wallet_mnemo(TestWallet::Backup),
                None,
                NETWORK,
                &secp,
            )
            .unwrap(),
        )
        .unwrap();
        add_wallet(
            &db,
            &heritage_wallet_from_mnemonic(
                get_test_wallet_name(TestWallet::Wife),
                get_test_wallet_mnemo(TestWallet::Wife),
                None,
                NETWORK,
                &secp,
            )
            .unwrap(),
        )
        .unwrap();
        add_wallet(
            &db,
            &heritage_wallet_from_mnemonic(
                get_test_wallet_name(TestWallet::Brother),
                get_test_wallet_mnemo(TestWallet::Brother),
                None,
                NETWORK,
                &secp,
            )
            .unwrap(),
        )
        .unwrap();
        add_wallet(
            &db,
            &heritage_wallet_from_mnemonic(
                get_test_wallet_name(TestWallet::Random),
                generate_mnemonic(WordCount::Words12).unwrap(),
                None,
                NETWORK,
                &secp,
            )
            .unwrap(),
        )
        .unwrap();
        TestEnv {
            db,
            secp,
            _tmpdir: tmpdir,
        }
    }

    fn bytes_to_hex_string<B: AsRef<[u8]>>(bytes: B) -> String {
        let bytes = bytes.as_ref();
        let mut s = String::with_capacity(2 * bytes.len());
        for byte in bytes {
            write!(s, "{:02x}", byte).unwrap();
        }
        s
    }

    // Verify mnemonic BIP39 English test vectors
    #[test]
    fn mnemonic_test_vectors() {
        // From https://github.com/trezor/python-mnemonic/blob/master/vectors.json
        let test_vectors = [
            [
                "00000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
                "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
                "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
                "xprv9s21ZrQH143K2gA81bYFHqU68xz1cX2APaSq5tt6MFSLeXnCKV1RVUJt9FWNTbrrryem4ZckN8k4Ls1H6nwdvDTvnV7zEXs2HgPezuVccsq"
            ],
            [
                "80808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
                "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
                "xprv9s21ZrQH143K2shfP28KM3nr5Ap1SXjz8gc2rAqqMEynmjt6o1qboCDpxckqXavCwdnYds6yBHZGKHv7ef2eTXy461PXUjBFQg6PrwY4Gzq"
            ],
            [
                "ffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
                "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
                "xprv9s21ZrQH143K2V4oox4M8Zmhi2Fjx5XK4Lf7GKRvPSgydU3mjZuKGCTg7UPiBUD7ydVPvSLtg9hjp7MQTYsW67rZHAXeccqYqrsx8LcXnyd"
            ],
            [
                "000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
                "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
                "xprv9s21ZrQH143K3mEDrypcZ2usWqFgzKB6jBBx9B6GfC7fu26X6hPRzVjzkqkPvDqp6g5eypdk6cyhGnBngbjeHTe4LsuLG1cCmKJka5SMkmU"
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
                "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
                "xprv9s21ZrQH143K3Lv9MZLj16np5GzLe7tDKQfVusBni7toqJGcnKRtHSxUwbKUyUWiwpK55g1DUSsw76TF1T93VT4gz4wt5RM23pkaQLnvBh7"
            ],
            [
                "808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
                "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
                "xprv9s21ZrQH143K3VPCbxbUtpkh9pRG371UCLDz3BjceqP1jz7XZsQ5EnNkYAEkfeZp62cDNj13ZTEVG1TEro9sZ9grfRmcYWLBhCocViKEJae"
            ],
            [
                "ffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
                "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
                "xprv9s21ZrQH143K36Ao5jHRVhFGDbLP6FCx8BEEmpru77ef3bmA928BxsqvVM27WnvvyfWywiFN8K6yToqMaGYfzS6Db1EHAXT5TuyCLBXUfdm"
            ],
            [
                "0000000000000000000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
                "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
                "xprv9s21ZrQH143K32qBagUJAMU2LsHg3ka7jqMcV98Y7gVeVyNStwYS3U7yVVoDZ4btbRNf4h6ibWpY22iRmXq35qgLs79f312g2kj5539ebPM"
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
                "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
                "xprv9s21ZrQH143K3Y1sd2XVu9wtqxJRvybCfAetjUrMMco6r3v9qZTBeXiBZkS8JxWbcGJZyio8TrZtm6pkbzG8SYt1sxwNLh3Wx7to5pgiVFU"
            ],
            [
                "8080808080808080808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
                "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
                "xprv9s21ZrQH143K3CSnQNYC3MqAAqHwxeTLhDbhF43A4ss4ciWNmCY9zQGvAKUSqVUf2vPHBTSE1rB2pg4avopqSiLVzXEU8KziNnVPauTqLRo"
            ],
            [
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
                "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
                "xprv9s21ZrQH143K2WFF16X85T2QCpndrGwx6GueB72Zf3AHwHJaknRXNF37ZmDrtHrrLSHvbuRejXcnYxoZKvRquTPyp2JiNG3XcjQyzSEgqCB"
            ],
            [
                "9e885d952ad362caeb4efe34a8e91bd2",
                "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
                "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
                "xprv9s21ZrQH143K2oZ9stBYpoaZ2ktHj7jLz7iMqpgg1En8kKFTXJHsjxry1JbKH19YrDTicVwKPehFKTbmaxgVEc5TpHdS1aYhB2s9aFJBeJH"
            ],
            [
                "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
                "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
                "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
                "xprv9s21ZrQH143K3uT8eQowUjsxrmsA9YUuQQK1RLqFufzybxD6DH6gPY7NjJ5G3EPHjsWDrs9iivSbmvjc9DQJbJGatfa9pv4MZ3wjr8qWPAK"
            ],
            [
                "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
                "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
                "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
                "xprv9s21ZrQH143K2XTAhys3pMNcGn261Fi5Ta2Pw8PwaVPhg3D8DWkzWQwjTJfskj8ofb81i9NP2cUNKxwjueJHHMQAnxtivTA75uUFqPFeWzk"
            ],
            [
                "c0ba5a8e914111210f2bd131f3d5e08d",
                "scheme spot photo card baby mountain device kick cradle pact join borrow",
                "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
                "xprv9s21ZrQH143K3FperxDp8vFsFycKCRcJGAFmcV7umQmcnMZaLtZRt13QJDsoS5F6oYT6BB4sS6zmTmyQAEkJKxJ7yByDNtRe5asP2jFGhT6"
            ],
            [
                "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
                "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
                "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
                "xprv9s21ZrQH143K3R1SfVZZLtVbXEB9ryVxmVtVMsMwmEyEvgXN6Q84LKkLRmf4ST6QrLeBm3jQsb9gx1uo23TS7vo3vAkZGZz71uuLCcywUkt"
            ],
            [
                "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
                "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
                "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
                "xprv9s21ZrQH143K2WNnKmssvZYM96VAr47iHUQUTUyUXH3sAGNjhJANddnhw3i3y3pBbRAVk5M5qUGFr4rHbEWwXgX4qrvrceifCYQJbbFDems"
            ],
            [
                "23db8160a31d3e0dca3688ed941adbf3",
                "cat swing flag economy stadium alone churn speed unique patch report train",
                "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
                "xprv9s21ZrQH143K4G28omGMogEoYgDQuigBo8AFHAGDaJdqQ99QKMQ5J6fYTMfANTJy6xBmhvsNZ1CJzRZ64PWbnTFUn6CDV2FxoMDLXdk95DQ"
            ],
            [
                "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
                "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
                "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
                "xprv9s21ZrQH143K3wtsvY8L2aZyxkiWULZH4vyQE5XkHTXkmx8gHo6RUEfH3Jyr6NwkJhvano7Xb2o6UqFKWHVo5scE31SGDCAUsgVhiUuUDyh"
            ],
            [
                "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
                "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
                "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
                "xprv9s21ZrQH143K3rEfqSM4QZRVmiMuSWY9wugscmaCjYja3SbUD3KPEB1a7QXJoajyR2T1SiXU7rFVRXMV9XdYVSZe7JoUXdP4SRHTxsT1nzm"
            ],
            [
                "f30f8c1da665478f49b001d94c5fc452",
                "vessel ladder alter error federal sibling chat ability sun glass valve picture",
                "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
                "xprv9s21ZrQH143K2QWV9Wn8Vvs6jbqfF1YbTCdURQW9dLFKDovpKaKrqS3SEWsXCu6ZNky9PSAENg6c9AQYHcg4PjopRGGKmdD313ZHszymnps"
            ],
            [
                "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
                "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
                "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
                "xprv9s21ZrQH143K4aERa2bq7559eMCCEs2QmmqVjUuzfy5eAeDX4mqZffkYwpzGQRE2YEEeLVRoH4CSHxianrFaVnMN2RYaPUZJhJx8S5j6puX"
            ],
            [
                "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
                "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
                "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
                "xprv9s21ZrQH143K39rnQJknpH1WEPFJrzmAqqasiDcVrNuk926oizzJDDQkdiTvNPr2FYDYzWgiMiC63YmfPAa2oPyNB23r2g7d1yiK6WpqaQS"
            ]
        ];
        let passphrase = "TREZOR";
        for test_vector in test_vectors {
            let [v_entropy, v_mnemostr, v_key, v_xpriv] = test_vector;
            //let m = parse_mnemonic(v_mnemostr).unwrap();
            let mnemo = Mnemonic::from_entropy(&hex_string_to_bytes(v_entropy).unwrap()).unwrap();
            let mnemostr = mnemo.to_string();
            let key = bytes_to_hex_string(mnemo.to_seed(passphrase));
            let xkey: ExtendedKey = (mnemo, Some(passphrase.to_string()))
                .into_extended_key()
                .unwrap();
            let xpriv = xkey.into_xprv(Network::Bitcoin).unwrap().to_string();
            assert_eq!(mnemostr, v_mnemostr);
            assert_eq!(key, v_key);
            assert_eq!(xpriv, v_xpriv);
        }
    }

    // Verify we cannot override an existing wallet
    #[test]
    fn cannot_override_existing_wallet() {
        let test_env = setup_test_env();
        let wallet = get_wallet(&test_env.db, get_test_wallet_name(TestWallet::Random)).unwrap();
        add_wallet(&test_env.db, &wallet).expect_err("this should not work");
    }

    // For the particular PSBT, verify properties
    #[test]
    fn psbt_summary_1() {
        let test_env = setup_test_env();
        let psbt = get_test_unsigned_psbt(TestPsbt::OwnerRecipients);
        let wallet_fingerprints = fingerprint_to_wallet_name_map(&test_env.db).unwrap();
        let summary = generate_psbt_summary(&psbt, wallet_fingerprints, NETWORK).unwrap();
        let PsbtSummary {
            inputs,
            outputs,
            total_spend,
            send_out,
            change,
            fee,
        } = summary;

        // This PSBT has 4 input
        assert_eq!(inputs.len(), 4);
        // All are spendable inputs, only for the owner
        assert!(inputs.iter().all(|input| {
            input
                .wallet_that_can_spend
                .iter()
                .all(|e| e == get_test_wallet_name(TestWallet::Owner))
        }));
        // 4 outputs
        assert_eq!(outputs.len(), 4);
        // the ouputs with amount < 300_000_000 are not owned by us
        assert!(outputs
            .iter()
            .filter(|e| e.amount < 300_000_000)
            .all(|e| e.owned_by_wallet.is_none()));
        // the ouput with amount > 300_000_000 is owned by owner
        assert!(outputs.iter().filter(|e| e.amount > 300_000_000).all(|e| e
            .owned_by_wallet
            .as_ref()
            .is_some_and(|v| v == get_test_wallet_name(TestWallet::Owner))));

        // Spend 400_000_000 sat total
        assert_eq!(total_spend, 400_000_000);
        // Send 60_000_000 sat to external wallet
        assert_eq!(send_out, 60_000_000);
        // Send 339_996_080 sat of change
        assert_eq!(change, 339_996_080);
        // Fee is always amount inputs - outputs
        assert_eq!(fee, total_spend - send_out - change);
    }

    // Verify the xpub generation
    #[test]
    fn xpub_generation() {
        let test_env = setup_test_env();
        let wallet = get_wallet(&test_env.db, get_test_wallet_name(TestWallet::Owner)).unwrap();
        let xpubs = derive_accounts_xpubs(&wallet, 20, NETWORK, &test_env.secp)
            .unwrap()
            .into_iter()
            .map(|dpubk| dpubk.to_string())
            .collect::<Vec<_>>();

        assert_eq!(xpubs, vec![
            "[9c7088e3/86'/1'/0']tpubDD2pKf3K2M2oukBVyGLVBKhqMV2MC5jQ3ABYNY17tFUgkq8Y2M65yBmeZHiz9gwrYfYkCZqipP9pL5NGwkSSsS2dijy7Nus1DLJLr6FQyWv/*",
            "[9c7088e3/86'/1'/1']tpubDD2pKf3K2M2oygc9tQX4ze9o9sMmn738oHEiRTwxAWJyW7HyPYjYQKMrxznXmgWncr416q1htkCszdHg3tbGseUUQXoxFZmjdAbwU8HY9QX/*",
            "[9c7088e3/86'/1'/2']tpubDD2pKf3K2M2p2MS1LdNxnNPKY61JgpGp9VTHf1k3e8coJk4ud2BhkrxYQifa8buLnrCyUbJke4US5cVobaZLr9qU554oMdwucWZpYZj5t13/*",
            "[9c7088e3/86'/1'/3']tpubDD2pKf3K2M2p32v62yjk7gHUzr8Nsu7oz2KE7rAyPpNRfdiaGcaFpAgBZMXACByAiw85jBJCuEsiKxumh9zrS6KUNK3BTXuKSTCFzEzfYAr/*",
            "[9c7088e3/86'/1'/4']tpubDD2pKf3K2M2p77GVTKs7PJfPtqzRLKSJ9DsbZeYDmFKAJEqsDmeiBbiM63Usg48UYxyT3ZZGjE66683KaG7vDRSzvWWDejhkWG8VeHrL65d/*",
            "[9c7088e3/86'/1'/5']tpubDD2pKf3K2M2p9CrcSUDT5kZqhTw8WEG2E93wZiWgjYFdAMuBSAf1SvQY1UnHk9J4xFgcoMNziJsMyzhCxkpi5f9ivgdxGVQTnNuaLMBFnX2/*",
            "[9c7088e3/86'/1'/6']tpubDD2pKf3K2M2pBBMnCozXtNKMLmUvZVaVSYrtVcSqajc9XzQeyymLsRkCpkL8QP3cp7LKcrpb9D97n39gZ539zZ4ambwSUBLYoupwpXptv3X/*",
            "[9c7088e3/86'/1'/7']tpubDD2pKf3K2M2pDvwTsF57CaFck5btMQCXA4DMqHhWddcWZT5Fou6poCdE5iokEsZDkyJGsKhsPSuJ6QkoDuygZndvoEDFsutPKVV2vLdeYvE/*",
            "[9c7088e3/86'/1'/8']tpubDD2pKf3K2M2pHfUPiY626U2uh4fcsw5oBo7co5UUCZp1TetbjRNBax6szSxm4MzbQyAKdiRcYKV2xLMXnLfDDCJRkS3NgWT9LZYV1xwhGyQ/*",
            "[9c7088e3/86'/1'/9']tpubDD2pKf3K2M2pJWX51vGsEghdjCVeyT7Hv1e794ehZ7uJKn2zieD7u1VsbH9J5CJQYZQ7L4hkfU1HqEYbYd8fmKRG3V3t7NHfFDfFn9667tj/*",
            "[9c7088e3/86'/1'/10']tpubDD2pKf3K2M2pMbAdHCchpGb5s7Nm4vUBQHReDubziTowFAxEAKV6swJVDCDYwQZaxYiN4fk83BmHEoZbTNLRiCwCqYCdYKDykPyMzpEZN6h/*",
            "[9c7088e3/86'/1'/11']tpubDD2pKf3K2M2pNtnBBdpkyXEGjvZna3XBGxVT3Zj4u2DreNz2EJJJjqN5f5sDDdgQ1FHPWSEinG9QNVZC8uU8RgDacAoVCjQF3ZXy6aduMQj/*",
            "[9c7088e3/86'/1'/12']tpubDD2pKf3K2M2pSygWGZCvFE6ro8EmAojbGbTTVjDZzKM45KDKgHn4naLCFSJZLSQP2gL1YaLAAmYVRQh8rxwPPCEaGFdtvfPWDeV6cge2ytx/*",
            "[9c7088e3/86'/1'/13']tpubDD2pKf3K2M2pV5nuQ4Kn3awpL2UAfv28amHat8Mb9eFHnyw2iwEuTC58q73cVqoZ9FEgQ9yJiC79y44Q2aqysTWPX6ZSsvLo9gLunPwogr7/*",
            "[9c7088e3/86'/1'/14']tpubDD2pKf3K2M2pYjXBctMmYakTC4Sxc1jzsGGAVXdPz4raMj2oVUHSSDCtRVPbNHQVrMry6Updt65T6pg6igo4c1HSTN1AwnAWgoQs5gtMUCW/*",
            "[9c7088e3/86'/1'/15']tpubDD2pKf3K2M2pZK6tVcDjvHy9BG26xVGPrdd8a7QwBJWyVqCYQjtqBG9mH7iSfyb4dzhNBE4qvTEPfnZg4sqJca7ZPRuL6rP5j7AMkGkqhyt/*",
            "[9c7088e3/86'/1'/16']tpubDD2pKf3K2M2pcpczWN95dG2eUpqKKk9aQFWWxqvjmQwkVQbt9MJhrcS6Eq7oLYb6uKY8p3PEwVvCBy9pe7eKCXjYPeGZe6iXSWhVFAGFe43/*",
            "[9c7088e3/86'/1'/17']tpubDD2pKf3K2M2pg8oiXb2pcdz9QYgexBa43U2Wt1EDX2w8SoY9p8p55SZsdsABUJLbHy6Hfi19nHsRrELJ6L6ZYA9VuYb6FAryhxonDwf3YFL/*",
            "[9c7088e3/86'/1'/18']tpubDD2pKf3K2M2pidehdGHhWgQxbwK26FxGgZi7viZGJSyugbZNJgvhb5H1F6GHx817x6wpJ5bKjfP7XmXHyetu6ZVTi7fLxkAASWjohjzwSiM/*",
            "[9c7088e3/86'/1'/19']tpubDD2pKf3K2M2pm4JswF6uHWJMa4Radk1DEB5uEk5eKH145HefKLMKN71uCYFVLHU14JDaDNFERTN4yXzESP7tPpkeXTZm38girQors7bVmhh/*"
        ])
    }

    fn heir_xpub_generation(te: &TestEnv, tw: TestWallet) -> String {
        let wallet = get_wallet(&te.db, get_test_wallet_name(tw)).unwrap();
        let xpub = derive_descriptor_public_key(&wallet, 0, NETWORK, &te.secp)
            .unwrap()
            .to_string();
        xpub
    }
    // Verify the heirs xpub generation
    #[test]
    fn heirs_xpub_generation() {
        let test_env = setup_test_env();

        assert_eq!(heir_xpub_generation(&test_env, TestWallet::Backup), "[f0d79bf6/86'/1'/1751476594'/0/0]025dfb71d525758f58a22106a743b5dbed8f1af1ebee044c80eb7c381e3d3e8b20");
        assert_eq!(heir_xpub_generation(&test_env, TestWallet::Wife), "[c907dcb9/86'/1'/1751476594'/0/0]029d47adc090487692bc8c31729085be2ade1a80aa72962da9f1bb80d99d0cd7bf");
        assert_eq!(heir_xpub_generation(&test_env, TestWallet::Brother), "[767e581a/86'/1'/1751476594'/0/0]03f49679ef0089dda208faa970d7491cca8334bbe2ca541f527a6d7adf06a53e9e");
    }

    // Verify the wallet ability to sign their PSBT
    fn wallet_can_sign(te: &TestEnv, tw: TestWallet, tp: TestPsbt) -> bool {
        let wallet = get_wallet(&te.db, get_test_wallet_name(tw)).unwrap();
        let mut psbt = get_test_unsigned_psbt(tp);
        if sign_psbt_tap_inputs(&mut psbt, wallet.xprv(&te.secp).unwrap(), &te.secp).unwrap() {
            println!("{psbt}");
            true
        } else {
            false
        }
    }
    fn wallet_cannot_sign(te: &TestEnv, tw: TestWallet, tp: TestPsbt) -> bool {
        !wallet_can_sign(te, tw, tp)
    }

    #[test]
    fn owner_wallet_signature() {
        let test_env = setup_test_env();
        assert!(wallet_can_sign(
            &test_env,
            TestWallet::Owner,
            TestPsbt::OwnerDrain
        ));
        assert!(wallet_can_sign(
            &test_env,
            TestWallet::Owner,
            TestPsbt::OwnerRecipients
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Owner,
            TestPsbt::BackupPresent
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Owner,
            TestPsbt::WifePresent
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Owner,
            TestPsbt::BackupFuture
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Owner,
            TestPsbt::WifeFuture
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Owner,
            TestPsbt::BrotherFuture
        ));
    }

    #[test]
    fn backup_wallet_signature() {
        let test_env = setup_test_env();
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Backup,
            TestPsbt::OwnerDrain
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Backup,
            TestPsbt::OwnerRecipients
        ));
        assert!(wallet_can_sign(
            &test_env,
            TestWallet::Backup,
            TestPsbt::BackupPresent
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Backup,
            TestPsbt::WifePresent
        ));
        assert!(wallet_can_sign(
            &test_env,
            TestWallet::Backup,
            TestPsbt::BackupFuture
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Backup,
            TestPsbt::WifeFuture
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Backup,
            TestPsbt::BrotherFuture
        ));
    }

    #[test]
    fn wife_wallet_signature() {
        let test_env = setup_test_env();
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Wife,
            TestPsbt::OwnerDrain
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Wife,
            TestPsbt::OwnerRecipients
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Wife,
            TestPsbt::BackupPresent
        ));
        assert!(wallet_can_sign(
            &test_env,
            TestWallet::Wife,
            TestPsbt::WifePresent
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Wife,
            TestPsbt::BackupFuture
        ));
        assert!(wallet_can_sign(
            &test_env,
            TestWallet::Wife,
            TestPsbt::WifeFuture
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Wife,
            TestPsbt::BrotherFuture
        ));
    }

    #[test]
    fn brother_wallet_signature() {
        let test_env = setup_test_env();
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Brother,
            TestPsbt::OwnerDrain
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Brother,
            TestPsbt::OwnerRecipients
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Brother,
            TestPsbt::BackupPresent
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Brother,
            TestPsbt::WifePresent
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Brother,
            TestPsbt::BackupFuture
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Brother,
            TestPsbt::WifeFuture
        ));
        assert!(wallet_can_sign(
            &test_env,
            TestWallet::Brother,
            TestPsbt::BrotherFuture
        ));
    }

    #[test]
    fn random_wallet_signature() {
        let test_env = setup_test_env();
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Random,
            TestPsbt::OwnerDrain
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Random,
            TestPsbt::OwnerRecipients
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Random,
            TestPsbt::BackupPresent
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Random,
            TestPsbt::WifePresent
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Random,
            TestPsbt::BackupFuture
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Random,
            TestPsbt::WifeFuture
        ));
        assert!(wallet_cannot_sign(
            &test_env,
            TestWallet::Random,
            TestPsbt::BrotherFuture
        ));
    }
}
