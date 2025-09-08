//! Configuration management
//!
//! This module handles loading configuration from environment variables,
//! including database connection strings and encryption keys. It also
//! manages automatic generation and persistence of encryption keys.

use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
};

use crate::APP_PREFIX;
use anyhow::{Context, Result};
use base64::{Engine, prelude::BASE64_STANDARD};
use const_format::formatcp;

use crate::encryption::generate_root_key;

/// Application configuration loaded from environment variables.
#[derive(Clone, Debug)]
pub struct Config {
    /// `SQLite` database connection URL.
    pub database_url: String,
    /// Root encryption key for password hashing and token generation.
    pub root_key: Vec<u8>,
}

// TODO: if you inline app name here, you can drop `const_format` crate
const ROOT_KEY_NAME: &str = formatcp!("{APP_PREFIX}_KEY_BASE_64");

impl Config {
    /// Initializes the configuration from environment variables.
    ///
    /// This function:
    /// 1. Loads the `DATABASE_URL` environment variable (required)
    /// 2. Loads or generates the encryption key from `{APP_PREFIX}_KEY_BASE_64`
    /// 3. If the encryption key doesn't exist, generates one and saves it to `.env`
    ///
    /// # Panics
    ///
    /// - If `DATABASE_URL` environment variable is not set
    /// - If the encryption key exists but is not valid base64
    /// - If a new encryption key cannot be written to the `.env` file
    pub fn try_init() -> Result<Self> {
        let database_url = std::env::var("DATABASE_URL").with_context(|| "🔥 DATABASE_URL must be set.")?;
        let root_key = std::env::var(ROOT_KEY_NAME).map_or_else(
            |error| {
                println!("Encryption key not found in '{ROOT_KEY_NAME}'. Writing one to .env file and using it. Error: {error}");
                let key = generate_root_key();
                write_to_dotenv(ROOT_KEY_NAME, &BASE64_STANDARD.encode(&key)).with_context(|| "🔥 could not write key to .env file")?;
                Ok(key)
            },
            |s| {
                BASE64_STANDARD
                    .decode(s)
                    .with_context(|| "🔥 Found an encryption key but it was not valid base64.")
            },
        )?;

        println!("✅ Successfully read in all needed config.");

        Ok(Self { database_url, root_key })
    }
}

/// Writes a key-value pair to the `.env` file.
///
/// This function appends a new environment variable to the `.env` file,
/// creating the file if it doesn't exist. It checks to ensure the key
/// doesn't already exist in the file before writing.
///
/// # Errors
///
/// Returns an error if:
/// - The `.env` file cannot be read or written
/// - The key already exists in the `.env` file
fn write_to_dotenv(key: &str, val: &str) -> Result<()> {
    let path = Path::new("./.env");

    if path.exists() {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;

            if let Some(existing_key) = line.split('=').next()
                && existing_key == key
            {
                anyhow::bail!("🔥 Cannot write key '{key}' with value '{val}' to .env file as the key already exists!");
            }
        }
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    writeln!(file, "\n{key}={val}")?;
    println!("📝 Wrote key={key} with value={val} to .env");

    Ok(())
}
