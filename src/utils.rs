use bdk::{bitcoin::Network, keys::bip39::WordCount, Error};
use clap::error::Result;
use std::path::{Path, PathBuf};

/// Prepare heritage-cli home directory
///
/// This function is called to check if [`crate::CliOpts`] datadir is set.
/// If not the default home directory is created at `~/.heritage-wallet`.
pub(crate) fn prepare_home_dir(home_path: &str) -> Result<PathBuf, Error> {
    let dir = {
        if !home_path.starts_with("~") {
            PathBuf::from(home_path)
        } else if home_path == "~" {
            dirs_next::home_dir()
                .ok_or_else(|| Error::Generic("home dir not found".to_string()))
                .unwrap()
        } else {
            let mut home = dirs_next::home_dir()
                .ok_or_else(|| Error::Generic("home dir not found".to_string()))
                .unwrap();
            home.push(home_path.strip_prefix("~/").unwrap());
            home
        }
    };

    log::debug!("{}", dir.as_path().display());

    if !dir.exists() {
        log::info!("Creating home directory {}", dir.as_path().display());
        std::fs::create_dir_all(&dir).map_err(|e| {
            Error::Generic(format!(
                "Cannot create {}: {}",
                dir.as_path().display(),
                e.to_string()
            ))
        })?;
    }

    Ok(dir)
}

/// Open the main database.
pub(crate) fn open_main_database(home_path: &Path, network: Network) -> Result<sled::Db, Error> {
    let mut database_path = home_path.to_owned();

    let database_name = network.to_string().to_lowercase();
    database_path.push(format!("{database_name}.sled"));

    let db = sled::open(database_path.as_path()).map_err(|e| {
        Error::Generic(format!(
            "Cannot create Sled database at {}: {}",
            database_path.as_path().display(),
            e.to_string()
        ))
    })?;

    log::debug!("Main database opened successfully");

    Ok(db)
}

pub(crate) fn mnemo_word_count_parser(arg: &str) -> Result<WordCount, String> {
    let word_count = arg.parse::<u8>().map_err(|e| e.to_string())?;
    match word_count {
        12 => Ok(WordCount::Words12),
        15 => Ok(WordCount::Words15),
        18 => Ok(WordCount::Words18),
        21 => Ok(WordCount::Words21),
        24 => Ok(WordCount::Words24),
        _ => Err("Must be 12, 15, 18, 21 or 24".to_owned()),
    }
}

pub(crate) fn hex_string_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("Invalid hexstring length: {}", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            Ok(u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| format!("{} is not valid hexa", &s[i..i + 2]))?)
        })
        .collect::<Result<_, _>>()
}

#[cfg(test)]
mod tests {

    use bdk::bitcoin::psbt::PartiallySignedTransaction;
    use std::str::FromStr;

    // Make sure sur PSBT encoder/decoder is working as expected
    // For a valid PSBT, we should be able to decode and re-encode to fall back on the same initial string
    #[test]
    fn psbt_decode_encode() {
        let psbt = "cHNidP8BAH0BAAAAAcaB48e7y2VbIMLS6Yzx5Z3JUcxaXwBcFRE/nURtzt3yAAAAAAD+////AugDAAAAAAAAFgAUBTcYDfDSjHWzO4fLKmjVEt4mrFr6HQAAAAAAACJRICchM4h1J7JjLAF+h1R217ztsnzmSuwR//HAV8gzNMGiMqkmAAABASuFIgAAAAAAACJRIJtNiZBebBFRj78UlqpUkT9Rd+jrPKOBWF/BPrw5bCQCIhXAavT/+hsR7JA6/BtVihyUkONUcEd3JeABo1TD/cWDem4uIEI90EDRPmmkjWAJlq5gU9pfBS4dsIWQHqyg/QV9RysBrQKgMrJpBEDAimWxwCEWQj3QQNE+aaSNYAmWrmBT2l8FLh2whZAerKD9BX1HKwE5AW7HBCrqauSJY+xub80rLxpnTHoLSwglCgA+5yUEcK4mc8XaClYAAIABAACAcmll6AAAAAAAAAAAIRZq9P/6GxHskDr8G1WKHJSQ41RwR3cl4AGjVMP9xYN6bhkAc8XaClYAAIABAACAAAAAgAEAAAAKAAAAARcgavT/+hsR7JA6/BtVihyUkONUcEd3JeABo1TD/cWDem4BGCBuxwQq6mrkiWPsbm/NKy8aZ0x6C0sIJQoAPuclBHCuJgAAAQUgYi+I/4VbEFhAzNw/lEMWrZ46UAGY+mF/L6GPtoZn2sYBBjAAwC0gQj3QQNE+aaSNYAmWrmBT2l8FLh2whZAerKD9BX1HKwGtAqAysmkEQMCKZbEhB0I90EDRPmmkjWAJlq5gU9pfBS4dsIWQHqyg/QV9RysBOQFuxwQq6mrkiWPsbm/NKy8aZ0x6C0sIJQoAPuclBHCuJnPF2gpWAACAAQAAgHJpZegAAAAAAAAAACEHYi+I/4VbEFhAzNw/lEMWrZ46UAGY+mF/L6GPtoZn2sYZAHPF2gpWAACAAQAAgAAAAIABAAAACwAAAAA=";
        assert_eq!(
            &PartiallySignedTransaction::from_str(psbt)
                .unwrap()
                .to_string(),
            psbt
        );
    }

    // Invalid PSBT
    #[test]
    fn psbt_decode_invalid_string() {
        let psbt = "cHNidP8BAH0BAAAAAcaB48e7y2VbIMLS6YzxUcxaXwBcFRE/nURtzt3yAAAAAAD+////AugDAAAAAAAAFgAUBTcYDfDSjHWzO4fLKmjVEt4mrFr6HQAAAAAAACJRICchM4h1J7JjLAF+h1R217ztsnzmSuwR//HAV8gzNMGiMqkmAAABASuFIgAAAAAAACJRIJtNiZBebBFRj78UlqpUkT9Rd+jrPKOBWF/BPrw5bCQCIhXAavT/+hsR7JA6/BtVihyUkONUcEd3JeABo1TD/cWDem4uIEI90EDRPmmkjWAJlq5gU9pfBS4dsIWQHqyg/QV9RysBrQKgMrJpBEDAimWxwCEWQj3QQNE+aaSNYAmWrmBT2l8FLh2whZAerKD9BX1HKwE5AW7HBCrqauSJY+xub80rLxpnTHoLSwglCgA+5yUEcK4mc8XaClYAAIABAACAcmll6AAAAAAAAAAAIRZq9P/6GxHskDr8G1WKHJSQ41RwR3cl4AGjVMP9xYN6bhkAc8XaClYAAIABAACAAAAAgAEAAAAKAAAAARcgavT/+hsR7JA6/BtVihyUkONUcEd3JeABo1TD/cWDem4BGCBuxwQq6mrkiWPsbm/NKy8aZ0x6C0sIJQoAPuclBHCuJgAAAQUgYi+I/4VbEFhAzNw/lEMWrZ46UAGY+mF/L6GPtoZn2sYBBjAAwC0gQj3QQNE+aaSNYAmWrmBT2l8FLh2whZAerKD9BX1HKwGtAqAysmkEQMCKZbEhB0I90EDRPmmkjWAJlq5gU9pfBS4dsIWQHqyg/QV9RysBOQFuxwQq6mrkiWPsbm/NKy8aZ0x6C0sIJQoAPuclBHCuJnPF2gpWAACAAQAAgHJpZegAAAAAAAAAACEHYi+I/4VbEFhAzNw/lEMWrZ46UAGY+mF/L6GPtoZn2sYZAHPF2gpWAACAAQAAgAAAAIABAAAACwAAAAA=";
        assert!(PartiallySignedTransaction::from_str(psbt).is_err());
    }
}
