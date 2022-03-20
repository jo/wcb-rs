# wcb
WebCrypto compatible encryption CLI in Rust.

This CLI handles the [Webcryptobox](https://github.com/jo/webcryptobox) encryption API.

Compatible packages:
* [wcb JavaScript](https://github.com/jo/wcb-js)
* [wcb Bash](https://github.com/jo/wcb-sh)

See [Webcryptobox Rust](https://github.com/jo/webcryptobox-rs) for the library.


## Installation

```sh
cargo install wcb
```


## Usage
wcb prints out usage information if you do not provide any command, or via `--help`.

```sh
$ wcb
wcb 
Webcryptobox - WebCrypto compatible cryptography CLI

USAGE:
    wcb <SUBCOMMAND>

OPTIONS:
    -h, --help    Print help information

SUBCOMMANDS:
    decrypt                     Decrypt message
    decrypt-from                Decrypt message with key pair
    decrypt-private-key         Decrypt private key pem
    decrypt-private-key-from    Decrypt private key pem with key pair
    derive-key                  Derive shared AES key
    derive-password             Derive password
    encrypt                     Encrypt message
    encrypt-private-key         Encrypt private key pem
    encrypt-private-key-to      Encrypt private key pem with key pair
    encrypt-to                  Encrypt message with key pair
    fingerprint                 Calculate EC key fingerprint
    help                        Print this message or the help of the given subcommand(s)
    key                         Generate AES key
    private-key                 Generate EC key
    public-key                  Get public key form private key

```

## License
This package is licensed under the [Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0).

© 2022 Johannes J. Schmidt
