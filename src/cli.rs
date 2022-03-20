use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[clap(name = "wcb")]
#[clap(about = "Webcryptobox - WebCrypto compatible cryptography CLI", long_about = None)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(clap::ArgEnum, Clone)]
pub enum ShaType {
    Sha1,
    Sha256,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate EC key
    PrivateKey {
        /// Output filename to write private key pem to. If omitted, print to STDOUT
        #[clap(short, long, parse(from_os_str), value_name = "FILENAME")]
        output_filename: Option<PathBuf>,
    },
    /// Get public key form private key
    PublicKey {
        /// Private key pem filename. If omitted, read STDIN
        #[clap(index = 1, parse(from_os_str), value_name = "FILENAME")]
        filename: Option<PathBuf>,

        /// Output filename to write public key pem to. If omitted, print to STDOUT
        #[clap(short, long, parse(from_os_str), value_name = "FILENAME")]
        output_filename: Option<PathBuf>,
    },
    /// Calculate EC key fingerprint
    Fingerprint {
        /// Key pem filename (private or public). If omitted, read STDIN
        #[clap(index = 1, parse(from_os_str), value_name = "FILENAME")]
        filename: Option<PathBuf>,

        /// SHA Type
        #[clap(arg_enum, short, long, default_value_t = ShaType::Sha256)]
        sha_type: ShaType,

        /// Output filename to write hex encoded fingerprint to. If omitted, print to STDOUT
        #[clap(short, long, parse(from_os_str), value_name = "FILENAME")]
        output_filename: Option<PathBuf>,
    },
    /// Generate AES key
    Key {
        /// Output filename to write hex encoded key to. If omitted, print to STDOUT
        #[clap(short, long, parse(from_os_str), value_name = "FILENAME")]
        output_filename: Option<PathBuf>,
    },
    /// Derive shared AES key
    DeriveKey {
        /// Private key pem filename.
        #[clap(
            index = 1,
            required = true,
            parse(from_os_str),
            value_name = "PRIVATE_KEY"
        )]
        private_key_filename: PathBuf,

        /// Public key pem filename. If omitted, read STDIN
        #[clap(index = 2, parse(from_os_str), value_name = "PUBLIC_KEY")]
        public_key_filename: Option<PathBuf>,

        /// Output filename to write hex encoded key to. If omitted, print to STDOUT
        #[clap(short, long, parse(from_os_str), value_name = "FILENAME")]
        output_filename: Option<PathBuf>,
    },
    /// Derive password
    DerivePassword {
        /// Private key pem filename.
        #[clap(
            index = 1,
            required = true,
            parse(from_os_str),
            value_name = "PRIVATE_KEY"
        )]
        private_key_filename: PathBuf,

        /// Public key pem filename. If omitted, read STDIN
        #[clap(index = 2, parse(from_os_str), value_name = "PUBLIC_KEY")]
        public_key_filename: Option<PathBuf>,

        // TODO validate max size
        /// Password length
        #[clap(short, long, default_value_t = 16)]
        length: usize,

        /// Output filename to write password to. If omitted, print to STDOUT
        #[clap(short, long, parse(from_os_str), value_name = "FILENAME")]
        output_filename: Option<PathBuf>,
    },

    /// Encrypt private key pem
    EncryptPrivateKey {
        /// Passphrase
        #[clap(index = 1, value_name = "PASSPHRASE")]
        passphrase: String,

        /// Private key pem input filename. If omitted, read STDIN
        #[clap(index = 2, parse(from_os_str), value_name = "FILENAME")]
        filename: Option<PathBuf>,

        /// Output filename to write encrypted private key pem to. If omitted, print to STDOUT
        #[clap(short, long, parse(from_os_str), value_name = "FILENAME")]
        output_filename: Option<PathBuf>,
    },
    /// Decrypt private key pem
    DecryptPrivateKey {
        /// Passphrase
        #[clap(index = 1, value_name = "PASSPHRASE")]
        passphrase: String,

        /// Encrypted private key pem input filename. If omitted, read STDIN
        #[clap(index = 2, parse(from_os_str), value_name = "FILENAME")]
        filename: Option<PathBuf>,

        /// Output filename to write private key pem. If omitted, print to STDOUT
        #[clap(short, long, parse(from_os_str), value_name = "FILENAME")]
        output_filename: Option<PathBuf>,
    },

    /// Encrypt private key pem with key pair
    EncryptPrivateKeyTo {
        /// Private key pem filename.
        #[clap(
            index = 1,
            required = true,
            parse(from_os_str),
            value_name = "PRIVATE_KEY"
        )]
        private_key_filename: PathBuf,

        /// Public key pem filename. If omitted, read STDIN
        #[clap(index = 2, parse(from_os_str), value_name = "PUBLIC_KEY")]
        public_key_filename: PathBuf,

        /// Private key pem input filename. If omitted, read STDIN
        #[clap(index = 3, parse(from_os_str), value_name = "FILENAME")]
        filename: Option<PathBuf>,

        /// Output filename to write encrypted private key pem to. If omitted, print to STDOUT
        #[clap(short, long, parse(from_os_str), value_name = "FILENAME")]
        output_filename: Option<PathBuf>,
    },
    /// Decrypt private key pem with key pair
    DecryptPrivateKeyFrom {
        /// Private key pem filename.
        #[clap(
            index = 1,
            required = true,
            parse(from_os_str),
            value_name = "PRIVATE_KEY"
        )]
        private_key_filename: PathBuf,

        /// Public key pem filename. If omitted, read STDIN
        #[clap(index = 2, parse(from_os_str), value_name = "PUBLIC_KEY")]
        public_key_filename: PathBuf,

        /// Encrypted private key pem input filename. If omitted, read STDIN
        #[clap(index = 3, parse(from_os_str), value_name = "FILENAME")]
        filename: Option<PathBuf>,

        /// Output filename to write private key pem. If omitted, print to STDOUT
        #[clap(short, long, parse(from_os_str), value_name = "FILENAME")]
        output_filename: Option<PathBuf>,
    },

    /// Encrypt message
    Encrypt {
        /// AES key, hex encoded
        #[clap(index = 1, value_name = "KEY")]
        key: String,

        /// Message input filename. If omitted, read STDIN
        #[clap(index = 2, parse(from_os_str), value_name = "FILENAME")]
        filename: Option<PathBuf>,

        /// Output filename to write base64 encoded encrypted message to. If omitted, print to STDOUT
        #[clap(short, long, parse(from_os_str), value_name = "FILENAME")]
        output_filename: Option<PathBuf>,
    },
    /// Decrypt message
    Decrypt {
        /// AES key, hex encoded
        #[clap(index = 1, value_name = "KEY")]
        key: String,

        /// Encrypted message input filename. Input must be base64 encoded. If omitted, read STDIN
        #[clap(index = 2, parse(from_os_str), value_name = "FILENAME")]
        filename: Option<PathBuf>,

        /// Output filename to write decrypted message to. If omitted, print to STDOUT
        #[clap(short, long, parse(from_os_str), value_name = "FILENAME")]
        output_filename: Option<PathBuf>,
    },
    /// Encrypt message with key pair
    EncryptTo {
        /// Private key pem filename.
        #[clap(
            index = 1,
            required = true,
            parse(from_os_str),
            value_name = "PRIVATE_KEY"
        )]
        private_key_filename: PathBuf,

        /// Public key pem filename. If omitted, read STDIN
        #[clap(index = 2, parse(from_os_str), value_name = "PUBLIC_KEY")]
        public_key_filename: PathBuf,

        /// Message input filename. If omitted, read STDIN
        #[clap(index = 3, parse(from_os_str), value_name = "FILENAME")]
        filename: Option<PathBuf>,

        /// Output filename to write base64 encoded encrypted message to. If omitted, print to STDOUT
        #[clap(short, long, parse(from_os_str), value_name = "FILENAME")]
        output_filename: Option<PathBuf>,
    },
    /// Decrypt message with key pair
    DecryptFrom {
        /// Private key pem filename.
        #[clap(
            index = 1,
            required = true,
            parse(from_os_str),
            value_name = "PRIVATE_KEY"
        )]
        private_key_filename: PathBuf,

        /// Public key pem filename. If omitted, read STDIN
        #[clap(index = 2, parse(from_os_str), value_name = "PUBLIC_KEY")]
        public_key_filename: PathBuf,

        /// Encrypted message input filename. Input must be base64 encoded. If omitted, read STDIN
        #[clap(index = 3, parse(from_os_str), value_name = "FILENAME")]
        filename: Option<PathBuf>,

        /// Output filename to write decrypted message to. If omitted, print to STDOUT
        #[clap(short, long, parse(from_os_str), value_name = "FILENAME")]
        output_filename: Option<PathBuf>,
    },
}
