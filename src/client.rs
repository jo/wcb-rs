use crate::cli;

use webcryptobox::*;

use std::io::{Error, Read, Write};
use std::path::PathBuf;
use std::{fs, io};

fn read_file(filename: &PathBuf) -> Vec<u8> {
    fs::read(&filename).unwrap()
}

fn read_hex(key: &String) -> Vec<u8> {
    hex::decode(key).unwrap()
}

fn read_file_or_stdin(filename: &Option<PathBuf>) -> Vec<u8> {
    match &filename {
        Some(path) => read_file(&path),
        None => {
            let mut data = Vec::new();
            io::stdin().read_to_end(&mut data).unwrap();
            data
        }
    }
}

fn read_base64_file_or_stdin(filename: &Option<PathBuf>) -> Vec<u8> {
    let mut data = read_file_or_stdin(&filename);

    // trim non base64 chars
    //   +: 43
    //   /: 47
    // 0-9: 48 - 57
    //   =: 61
    // A-Z: 65 - 90
    // a-z: 97 - 122
    data.retain(|&x| {
        x == 43 || (x >= 47 && x <= 57) || x == 61 || (x >= 65 && x <= 90) || (x >= 97 && x <= 122)
    });

    base64::decode(&data).unwrap()
}

fn write_file_or_stdout(filename: &Option<PathBuf>, data: &Vec<u8>) {
    match &filename {
        Some(path) => fs::write(path, data).expect("Unable to write file"),
        None => io::stdout().write_all(data).expect("Unable to write to stdout")
    }
}

fn write_hex_file_or_stdout(filename: &Option<PathBuf>, data: &Vec<u8>) {
    let data_hex = hex::encode(data);
    match &filename {
        Some(path) => fs::write(path, data_hex).expect("Unable to write file"),
        None => println!("{}", data_hex),
    }
}

fn write_base64_file_or_stdout(filename: &Option<PathBuf>, data: &Vec<u8>) {
    let data_base64 = base64::encode(data);
    match &filename {
        Some(path) => fs::write(path, data_base64).expect("Unable to write file"),
        None => println!("{}", data_base64),
    }
}

pub struct Wcb {
    args: cli::Args,
}

impl Wcb {
    pub fn new(args: cli::Args) -> Self {
        Wcb { args }
    }

    pub fn run(&self) -> Result<(), Error> {
        match &self.args.command {
            cli::Commands::PrivateKey { output_filename } => {
                let key = generate_private_key().unwrap();
                let pem = export_private_key_pem(key).unwrap();

                write_file_or_stdout(&output_filename, &pem);
            }
            cli::Commands::Key { output_filename } => {
                let key = generate_key().unwrap();

                write_hex_file_or_stdout(&output_filename, &key)
            }
            cli::Commands::PublicKey {
                filename,
                output_filename,
            } => {
                let pem = read_file_or_stdin(&filename);
                let key = import_private_key_pem(&pem).unwrap();
                let public_key = get_public_key(&key).unwrap();
                let pem = export_public_key_pem(&public_key).unwrap();

                write_file_or_stdout(&output_filename, &pem);
            }
            cli::Commands::Fingerprint {
                filename,
                sha_type,
                output_filename,
            } => {
                let pem = read_file_or_stdin(&filename);

                let data = match pem.starts_with(b"-----BEGIN PRIVATE KEY-----") {
                    true => {
                        let key = import_private_key_pem(&pem).unwrap();
                        match sha_type {
                            cli::ShaType::Sha1 => sha1_fingerprint_from_private_key(&key).unwrap(),
                            cli::ShaType::Sha256 => {
                                sha256_fingerprint_from_private_key(&key).unwrap()
                            }
                        }
                    }
                    _ => {
                        let key = import_public_key_pem(&pem).unwrap();
                        match sha_type {
                            cli::ShaType::Sha1 => sha1_fingerprint_from_public_key(&key).unwrap(),
                            cli::ShaType::Sha256 => {
                                sha256_fingerprint_from_public_key(&key).unwrap()
                            }
                        }
                    }
                };

                write_hex_file_or_stdout(&output_filename, &data)
            }
            cli::Commands::DeriveKey {
                private_key_filename,
                public_key_filename,
                output_filename,
            } => {
                let private_key_pem = read_file(&private_key_filename);
                let private_key = import_private_key_pem(&private_key_pem).unwrap();

                let public_key_pem = read_file_or_stdin(&public_key_filename);
                let public_key = import_public_key_pem(&public_key_pem).unwrap();

                let key = derive_key(private_key, public_key).unwrap();

                write_hex_file_or_stdout(&output_filename, &key)
            }
            cli::Commands::DerivePassword {
                private_key_filename,
                public_key_filename,
                length,
                output_filename,
            } => {
                let private_key_pem = read_file(&private_key_filename);
                let private_key = import_private_key_pem(&private_key_pem).unwrap();

                let public_key_pem = read_file_or_stdin(&public_key_filename);
                let public_key = import_public_key_pem(&public_key_pem).unwrap();

                let password = derive_password(private_key, public_key, length).unwrap();

                write_hex_file_or_stdout(&output_filename, &password)
            }

            cli::Commands::EncryptPrivateKey {
                filename,
                passphrase,
                output_filename,
            } => {
                let private_key_pem = read_file_or_stdin(&filename);
                let private_key = import_private_key_pem(&private_key_pem).unwrap();

                let pem =
                    export_encrypted_private_key_pem(private_key, passphrase.as_bytes()).unwrap();

                write_file_or_stdout(&output_filename, &pem);
            }
            cli::Commands::DecryptPrivateKey {
                filename,
                passphrase,
                output_filename,
            } => {
                let encrypted_private_key_pem = read_file_or_stdin(&filename);
                let private_key = import_encrypted_private_key_pem(
                    &encrypted_private_key_pem,
                    passphrase.as_bytes(),
                )
                .unwrap();

                let pem = export_private_key_pem(private_key).unwrap();

                write_file_or_stdout(&output_filename, &pem);
            }

            cli::Commands::EncryptPrivateKeyTo {
                filename,
                private_key_filename,
                public_key_filename,
                output_filename,
            } => {
                let private_key_pem = read_file(&private_key_filename);
                let private_key = import_private_key_pem(&private_key_pem).unwrap();

                let public_key_pem = read_file(&public_key_filename);
                let public_key = import_public_key_pem(&public_key_pem).unwrap();

                let key_pem = read_file_or_stdin(&filename);
                let key = import_private_key_pem(&key_pem).unwrap();

                let pem =
                    export_encrypted_private_key_pem_to(key, private_key, public_key).unwrap();

                write_file_or_stdout(&output_filename, &pem);
            }
            cli::Commands::DecryptPrivateKeyFrom {
                private_key_filename,
                public_key_filename,
                filename,
                output_filename,
            } => {
                let private_key_pem = read_file(&private_key_filename);
                let private_key = import_private_key_pem(&private_key_pem).unwrap();

                let public_key_pem = read_file(&public_key_filename);
                let public_key = import_public_key_pem(&public_key_pem).unwrap();

                let encrypted_key_pem = read_file_or_stdin(&filename);
                let key = import_encrypted_private_key_pem_from(
                    &encrypted_key_pem,
                    private_key,
                    public_key,
                )
                .unwrap();

                let pem = export_private_key_pem(key).unwrap();

                write_file_or_stdout(&output_filename, &pem);
            }

            cli::Commands::Encrypt {
                key,
                filename,
                output_filename,
                base64,
            } => {
                let key = read_hex(&key);
                let data = read_file_or_stdin(&filename);

                let encrypted_data = encrypt(&key, &data).unwrap();

                if *base64 {
                    write_base64_file_or_stdout(&output_filename, &encrypted_data)
                } else {
                    write_file_or_stdout(&output_filename, &encrypted_data)
                }
            }
            cli::Commands::Decrypt {
                key,
                filename,
                output_filename,
                base64,
            } => {
                let key = read_hex(&key);
                let data = match base64 {
                    true => read_base64_file_or_stdin(&filename),
                    false => read_file_or_stdin(&filename)
                };

                let decrypted_data = decrypt(&key, &data).unwrap();

                write_file_or_stdout(&output_filename, &decrypted_data)
            }
            cli::Commands::EncryptTo {
                private_key_filename,
                public_key_filename,
                filename,
                output_filename,
                base64,
            } => {
                let private_key_pem = read_file(&private_key_filename);
                let private_key = import_private_key_pem(&private_key_pem).unwrap();

                let public_key_pem = read_file(&public_key_filename);
                let public_key = import_public_key_pem(&public_key_pem).unwrap();

                let data = read_file_or_stdin(&filename);

                let encrypted_data = derive_and_encrypt(private_key, public_key, &data).unwrap();

                if *base64 {
                    write_base64_file_or_stdout(&output_filename, &encrypted_data)
                } else {
                    write_file_or_stdout(&output_filename, &encrypted_data)
                }
            }
            cli::Commands::DecryptFrom {
                private_key_filename,
                public_key_filename,
                filename,
                output_filename,
                base64,
            } => {
                let private_key_pem = read_file(&private_key_filename);
                let private_key = import_private_key_pem(&private_key_pem).unwrap();

                let public_key_pem = read_file(&public_key_filename);
                let public_key = import_public_key_pem(&public_key_pem).unwrap();

                let data = match base64 {
                    true => read_base64_file_or_stdin(&filename),
                    false => read_file_or_stdin(&filename)
                };

                let decrypted_data = derive_and_decrypt(private_key, public_key, &data).unwrap();

                write_file_or_stdout(&output_filename, &decrypted_data)
            }
        }

        Ok(())
    }
}
