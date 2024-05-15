use bdk::bitcoin::Network;
use clap::{Parser, Subcommand};

#[derive(PartialEq, Clone, Debug, Parser)]
/// The Heritage Cold Wallet CLI App
///
/// heritage-cli is a light weight command line bitcoin cold-wallet, powered by BDK, rust-bitcoin and rust-miniscript.
/// This is the offline counterpart of the Heritage service, used to hold secrets keys and sign transactions
#[command(author= option_env ! ("CARGO_PKG_AUTHORS").unwrap_or(""), version = option_env ! ("CARGO_PKG_VERSION").unwrap_or("unknown"), about, long_about = None)]
pub struct CliOpts {
    #[arg(short, long, default_value_t = Network::Bitcoin)]
    /// Sets the network.
    pub network: Network,

    #[arg(short, long, value_hint = clap::ValueHint::DirPath, default_value = "~/.heritage-wallet")]
    /// Sets the wallet data directory.
    pub datadir: String,

    #[arg(short, long, default_value = "default_wallet")]
    /// The name of the wallet to use.
    pub wallet_name: String,

    #[command(subcommand)]
    /// Top level cli sub-commands.
    pub subcommand: CliSubCommand,
}

/// Top level cli sub-commands.
#[derive(Debug, Subcommand, Clone, PartialEq)]
pub enum CliSubCommand {
    /// List wallets
    ListWallets,
    /// Generate a new wallet
    Generate {
        #[command(flatten)]
        wallet_opts: WalletOpts,
        #[command(flatten)]
        mnemo_opts: MnemoOpts,
        #[arg(short='c', long, default_value="12", value_parser=["12", "15", "18", "21", "24"])]
        /// The number of words in the mnemonic.
        word_count: String,
        #[arg(short, long)]
        /// Use the given entropy instead of the local PRNG. The given entropy must
        /// {n}be encoded in hexadecimal, its length between 128 and 256 bits and a
        /// {n}multiple of 32bits, depending on the configured number of words.
        entropy: Option<String>,
    },
    /// Display informations about a wallet
    ShowWalletInfo {
        #[command(flatten)]
        wallet_opts: WalletOpts,
    },
    /// Display the all the private informations of the wallet for backup purpose
    /// {n}/!\ BEWARE THOSE INFORMATIONS WILL ALLOW SPENDING OF YOUR COINS{n}unless the wallet is passphrase-protected /!\
    ShowPrivateWalletInfo {
        #[command(flatten)]
        wallet_opts: WalletOpts,
        #[arg(long, required = true, action)]
        /// Confirm that you know what you are doing
        i_understand_what_i_am_doing: bool,
    },
    /// Delete a wallet from the internal database
    /// {n}/!\ BEWARE THAT YOUR BITCOINS MAY BE LOST FOREVER IF YOU HAVE NO BACKUP OF YOU SEED /!\
    DeleteWallet {
        #[command(flatten)]
        wallet_opts: WalletOpts,
        #[arg(long, required = true, action)]
        /// Confirm that you understand that you will loose your bitcoins you have no backup
        i_understand_that_i_will_lost_my_keys_forever_if_i_have_no_backup: bool,
    },
    /// Restore a wallet from its mnemonic
    Restore {
        /// The mnemonic from which to restore
        words: Vec<String>,
        #[command(flatten)]
        wallet_opts: WalletOpts,
        #[command(flatten)]
        mnemo_opts: MnemoOpts,
    },
    /// Return the eXtended public keys of the accounts needed by the public part of an Heritage wallet
    GetXpubs {
        #[command(flatten)]
        wallet_opts: WalletOpts,
        #[arg(short, long, default_value_t = 20)]
        /// The number of XPubs (accounts) to generate
        count: usize,
    },
    /// Return a Public Key Descriptor used to declare an heir in another wallet.
    /// {n}Statically uses the derivation path m/86'/0'/1751476594'/0/0, with 1751476594
    /// {n}corresponding to the binary representation of 'heir' in ASCII.
    GetHeirPubkey {
        #[command(flatten)]
        wallet_opts: WalletOpts,
        #[arg(short, long, default_value_t = 0)]
        /// The index of the key to generate
        index: u32,
    },
    /// Return the given PSBT after signing everything the wallet can in it
    Sign {
        #[command(flatten)]
        wallet_opts: WalletOpts,
        /// The PSBT to sign
        psbt: String,
    },
    /// Display infos on the PSBT
    DisplayPsbt {
        /// The PSBT to extract infos from
        psbt: String,
        #[arg(short, long, action)]
        /// Display the full PSBT structure
        full: bool,
    },
}

/// Config options wallet operations can take.
#[derive(Debug, Parser, Clone, PartialEq, Eq)]
pub struct WalletOpts {
    #[arg(short, long)]
    /// The name of the wallet to use.
    pub wallet_name: Option<String>,
}

/// Config options mnemonic operations can take.
#[derive(Debug, Parser, Clone, PartialEq, Eq)]
pub struct MnemoOpts {
    #[arg(long, default_value_t = false)]
    /// Signals that the wallet is protected by a passphrase that will be prompted for.
    pub with_passphrase: bool,
}
