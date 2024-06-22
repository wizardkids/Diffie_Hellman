# Diffie-Hellman Key Exchange and AES Encryption

This Python program implements the Diffie-Hellman key exchange algorithm for securely sharing a secret key between two parties, and then uses that key for AES encryption and decryption of text messages.

## Description

Unlike other encryption programs that I have written, this one includes a mechanism for secure transmission of the key required for decryption. The generate_DH() function generates keys for the sender or the recipient, separately. Both parties can then calculate the key to encrypt/decrypt text.

Encryption uses the sender's private key and the recipient's public key. From these data, a shared key is created and used for encryption. Decryption uses the sender's public key and the recipient's private key. The recipient then creates the same shared key to decrypt the message that was used by the sender to encrypt the text.

Key exchange with RSA encryption works differently. Keys for the sender and the recipient are generated independently of each other. With Diffie-Hellman, in contrast, both parties need to agree on and share a "base" and "modulus" but each party selects their own "secret number". With these values, a public key is generated using modular exponentiation [(base**secret_number) % modulus]. Clearly, the public keys for each party will be different, but they are related and this is what allows for encryption/decryption.

With Diffie-Hellman, parties must exchange their public keys. The sender uses their secret number and the recipient's public key to calculate a shared key to encrypt text with. The recipient uses their own secret number and the sender's public key to calculate the same shared key that is used to decrypt the encrypted text.

This program provides two main functionalities:

1. **Key Generation**: Generate Diffie-Hellman keys for both the sender and the recipient. These keys are stored in `sender.json` and `recipient.json` files, respectively.

2. **Encryption and Decryption**: Encrypt a given text message using AES encryption with the shared key derived from the Diffie-Hellman key exchange. The encrypted message is stored in `encrypted.json`. Conversely, decrypt the contents of `encrypted.json` using the shared key and save the decrypted text to `unencrypted.txt`.

## Usage

```
diffie_hellman.py [OPTIONS] [MESSAGE]

  This utility performs two functions:

  1. Generate keys for both the SENDER and the RECIPIENT

  2. Encrypt text using AES encryption using the "shared
  key".

  STEP 1: Use --generate to generate keys for SENDER and
  RECIPIENT.

  STEP 2: Provide a [MESSAGE] or [PATH] to encrypt using
  SENDER's private key and RECIPIENt's public key.

  STEP 3: Decrypt the encrypted text using RECIPIENt's
  private key and SENDER's public key.

  [MESSAGE] must be a quote-delimited string.

Options:
  -g, --generate   Generate Diffie-Hellman keys for sender
                   and recipient.
  -f, --file PATH  File to encrypt.
  -p, --printkeys  Print sender and recipient keys.
  --version        Show the version and exit.
  --help           Show this message and exit.

  Keys are stored in "sender.json" and "recipient.json".

  Text is encrypted using AES encryption and is written to
  "encrypted.json" and the content of that file is
  decrypted to "unencrypted.txt". If either file exists,
  it will be overwritten.

  EXAMPLE USAGE:

  diffie_hellman.py "The troops roll out at midnight." -->
  encrypts text to "encrypted.json"

  diffie_hellman.py --> decrypt "encrypted.json" to
  "unencrypted.txt".
  ```

## Notes

- The program uses the Diffie-Hellman key exchange algorithm to securely establish a shared secret key between the sender and the recipient.
- The shared key is then used for AES encryption and decryption of the text message.
- The encrypted message is stored in `encrypted.json`, and the decrypted text is saved in `unencrypted.txt`.
- If both a text message and a file are provided, the program will exit with an error.
- Non-ASCII characters (e.g., punctuation, accented letters) are supported.

## Dependencies

- [click](https://click.palletsprojects.com/en/8.1.x/) (for command-line interface)
- [pycryptodome](https://pycryptodome.readthedocs.io/en/latest/) (for cryptographic operations)