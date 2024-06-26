"""
    Filename: diffie_hellman.py
     Version: 0.1
      Author: Richard E. Rawson
        Date: 2024-06-05
 Description: This program includes two major functions:
                 (i) DH key exchange
                (ii) AES encryption

Unlike other encryption programs that I have written, this one includes a mechanism for secure transmission of the key required for decryption. The generate_DH() function generates keys for the sender or the recipient, separately. Both parties can then calculate the key to encrypt/decrypt text.

Encryption uses the sender's private key and the recipient's public key. From these data, a shared key is created and used for encryption. Decryption uses the sender's public key and the recipient's private key. The recipient then creates the same shared key to decrypt the message that was used by the sender to encrypt the text.

Key exchange with RSA encryption works differently. Keys for the sender and the recipient are generated independently of each other. With Diffie-Hellman, in contrast, both parties need to agree on and share a "base" and "modulus" but each party selects their own "secret number". With these values, a public key is generated using modular exponentiation [(base**secret_number) % modulus]. Clearly, the public keys for each party will be different, but they are related and this is what allows for encryption/decryption.

With Diffie-Hellman, parties must exchange their public keys. The sender uses their secret number and the recipient's public key to calculate a shared key to encrypt text with. The recipient uses their own secret number and the sender's public key to calculate the same shared key that is used to decrypt the encrypted text.
"""

import json
from pathlib import Path
from random import randint
from time import sleep

import click
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# from icecream import ic

VERSION = "0.1"


@click.command(help="This utility performs two functions:\n\n1. Generate keys for both the SENDER and the RECIPIENT\n\n2. Encrypt text using AES encryption using the \"shared key\".\n\nSTEP 1: Use --generate to generate keys for SENDER and RECIPIENT.\n\nSTEP 2: Provide a [MESSAGE] or [PATH] to encrypt using SENDER's private key and RECIPIENt's public key.\n\nSTEP 3: Decrypt the encrypted text using RECIPIENt's private key and SENDER's public key.\n\n[MESSAGE] must be a quote-delimited string.", epilog="\n\nKeys are stored in \"sender.json\" and \"recipient.json\".\n\nText is encrypted using AES encryption and is written to \"encrypted.json\" and the content of that file is decrypted to \"unencrypted.txt\". If either file exists, it will be overwritten.\n\nEXAMPLE USAGE:\n\ndiffie_hellman.py \"The troops roll out at midnight.\" --> encrypts text to \"encrypted.json\"\n\ndiffie_hellman.py --> decrypt \"encrypted.json\" to \"unencrypted.txt\".")
@click.argument("message", type=str, required=False)
@click.option("-g", "--generate", is_flag=True, default=False, help='Generate Diffie-Hellman keys for sender and recipient.')
@click.option("-f", "--file", type=click.Path(exists=False), help='File to encrypt.')
@click.option("-p", "--printkeys", is_flag=True, default=False, help="Print sender and recipient keys.")
@click.version_option(version=VERSION)
def cli(message: str, generate: bool, file: str, printkeys: bool) -> None:
    """
    Entry point for this CLI.

    Parameters
    ----------
    message : str -- text message to encrypt
    generate : bool -- if True, generate Diffie-Hellman keys
    file : click.Path -- file containing text to encrypt
    printkeys : bool -- if True, print encryption keys
    """

    # print()
    # ic(message)
    # ic(generate)
    # ic(file)
    # ic(printkeys)
    # print()

    # Trying to encrypt a [MESSAGE] and file contents at the same time is not permitted.
    if message is not None and file is not None:
        print('Providing both a text message and a filename is not allowed.')
        exit()
    else:
        main(message, generate, file, printkeys)


def encrypt(message: str) -> None:
    """
    Encrypt the text of message using AES encryption and the senders' key.

    Parameters
    ----------
    message : str -- message to encrypt
    """

    # To encrypt, keys will have already been generated and stored in sender.json and recipient.json. These keys must be share between sender and recipient. (Thus, we open both files to get access to both keys!)
    try:
        with open("sender.json", 'r', encoding='utf-8') as file:
            sender_keys = json.load(file)
        with open("recipient.json", 'r', encoding='utf-8') as file:
            recipient_keys = json.load(file)
    except FileNotFoundError as e:
        print(e)
        print("Use --generate option first to create sender\nand recipient keys.")
        exit()

    # The sender is encrypting this text, so the sender needs to have the recipient's public key and their own secret number. Use these values to calculate the "shared_secret" value.
    shared_key: int = (recipient_keys['public_number']**sender_keys['secret_number']) % sender_keys['modulus']

    # Convert "message" from a str to a byte string, as required by AES.
    data: bytes = message.encode(encoding='utf-8')

    # Generate iterations, key_length, and salt in bytes. This is a very big number!
    salt: bytes = get_random_bytes(16)
    iterations: int = 100_000
    key_length: int = 32

    # Use the shared secret key to generate a key using PBKDF2.
    key: bytes = PBKDF2(shared_key, salt, dkLen=key_length, count=iterations, hmac_hash_module=SHA256)

    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    iv: bytes = cipher.nonce

    # Bundle the encrypted and hexified data with the salt, iterations, and nonce
    encrypted_bundle: dict[str, str | int] = {
        'ciphertext': ciphertext.hex(),
        'salt': salt.hex(),
        'iterations': iterations,
        'iv': iv.hex(),
    }

    with open('encrypted.json', 'w', encoding='utf-8') as f:
        json.dump(encrypted_bundle, f)


def decrypt() -> None:
    """
    Decrypt the encrypted message saved in "encrypted.json". Decryption requires the public key from the sender and the recipient's private key (secret number).
    """

    # Retrieve information from "encrypted.json".
    try:
        with open('encrypted.json', 'rb') as file:
            info = json.load(file)
    except FileNotFoundError as e:
        print(e)
        print("Provide text to encrypt first.")
        exit()

    # Convert ciphertext, salt, and iv (from encrypted.json) to bytes.
    ciphertext: bytes = bytes.fromhex(info['ciphertext'])
    salt: bytes = bytes.fromhex(info['salt'])
    iterations: int = info['iterations']
    iv: bytes = bytes.fromhex(info['iv'])

    # Since it is the recipient who is decrypting this text, the recipient retrieves the sender's public key and uses recipient's private key.
    try:
        with open("sender.json", 'r', encoding='utf-8') as file:
            sender_keys = json.load(file)
        with open("recipient.json", 'r', encoding='utf-8') as file:
            recipient_keys = json.load(file)
    except FileNotFoundError as e:
        print(e)
        print("Use --generate option first to create sender\nand recipient keys.")
        exit()

    # Compute the same shared key that was used to encrypt the plaintext.
    shared_key: int = (sender_keys['public_number']**recipient_keys['secret_number']) % recipient_keys['modulus']

    # Derive the key using the provided salt and iterations
    key: bytes = PBKDF2(shared_key, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)
    cipher = AES.new(key, AES.MODE_EAX, iv)
    data_bytes: bytes = cipher.decrypt(ciphertext)
    data: str = data_bytes.decode(encoding='latin-1')

    with open("unencrypted.txt", "w", encoding='latin-1') as f:
        f.write(data)

    print('\nDecrypted text saved in "unencrypted.txt".')


def generate_DH() -> None:
    """
    "base"^"secret_number" mod "modulus". This formula is public. "base" and "modulus" are known to both parties. "modulus" must be a prime number.

    "secret_number" is known only to the parties and each party has a different "secret_number". In this function, a "secret_number" is selected randomly and assigned to each party. That number is used by each party to calculate a "public_number". Each party shares their "public_number" with the other party.

    Each party can calculate a "shared_key" by using THEIR "secret_number" and the OTHER party's "public_number".

    "base", "modulus", "secret_number", "public_number", are all values required to calculate a "shared_key". Both the sender and the recipient, with the correct information from the other party, will calculate the same shared key. Because this calculation depends on the "secret_number" that only one party knows, only the sender and recipient can calculate this shared number. That is the magic of Duffie-Hellman key exchange.

    CODENOTE
    Because adhering to the following guidelines results in very long computation times, I have chosen to deviate. But these guidelines are recommended selecting secure values for "b", "m", and the "secret number".
    "base":
        The base, it's often chosen to be a small prime number or a primitive root modulo "m". While "b" doesn't need to be as large as "m", it should be chosen to ensure the security properties of the Diffie-Hellman exchange are maintained. In many cases, "b" is simply set to 2 or another small number.

    "modulus":
        You need to generate a large prime number that is at least 2048 bits long for adequate security. This is not something you can do with a simple random byte generator, as the number must be prime, not just random. There are specialized algorithms and libraries designed to generate large prime numbers for cryptographic purposes. For example, OpenSSL provides functionality to generate such prime numbers1.

    "secret_number":
        Randomness: "secret_number" should be randomly generated to ensure that it cannot be guessed or predicted by an attacker.
        Size: The size of "secret_number" should be similar to the size of "m". If "m" is 2048 bits, then "secret_number" should also be a random number that is 2048 bits long.
        Range: "secret_number" should be in the range ( [1, m-2] ). It’s important that "secret_number" is not too small, as small values can weaken the security of the key exchange.
    """

    # Go two rounds of key construction, where the first round is for the sender and the second round is for the recipient. Since the recipient and sender need the same "b" and "m", the recipient gets those values from the sender.
    for rnd in range(2):
        party: str = "s" if rnd == 0 else "r"

        if party == 's':
            print('Generating common "base" and "modulus"...')
        else:
            print('Retrieving common "base" and "modulus" from sender...')
        sleep(2.5)

        # sender chooses a "b" and an "m". recipient uses the same values, which have been stored in "sender.json".
        if party == "s":
            base: int = 3
            while True:
                modulus: int = randint(10, 256)
                if is_prime(modulus):
                    break
        else:
            sender_keys: dict[str, int] = get_sender_info()
            base: int = sender_keys['base']
            modulus: int = sender_keys['modulus']

        if party == "s":
            print("Selecting secret number (private key) for sender...")
        else:
            print("Selecting secret number (private key) for recipient...")
        sleep(2.5)

        # sender and recipient each determine a secret number.
        secret_number: int = randint(1000, 10000)

        print("Using modular function (b**secret_number % m) to generate public key")
        if party == "s":
            print("for sender...", end='')
        else:
            print("for recipient", end='')
        print("")
        sleep(3.5)

        # modular function to create numbers that sender and recipient need to exchange with each other for encryption and decryption
        public_number: int = (base**secret_number) % modulus

        # Gather all the key parts (pun intended) into a dictionary.
        keys: dict[str, int] = {"base": base, "modulus": modulus, "public_number": public_number, "secret_number": secret_number}

        if party == "s":
            print("\nKeys for sender:")
            for k, v in keys.items():
                print(f"{k}: {v}")
        else:
            print("\nKeys for recipient:")
            for k, v in keys.items():
                print(f"{k}: {v}")
        sleep(0.8)

        filename: str = 'sender.json' if party == 's' else 'recipient.json'
        with open(filename, 'w', encoding="utf-8") as f:
            json.dump(keys, f)

        print(f'\nKeys for {filename[:-5]} saved in "{filename}".', sep='')
        if party == "s":
            print("\n============================\n")


def get_sender_info() -> dict[str, int]:
    """
    Retrieve the keys for the sender from the "sender.json" file.

    Returns
    -------
    dict[str, int] -- sender's keys
    """
    try:
        with open("sender.json", 'r', encoding='utf-8') as file:
            sender_keys = json.load(file)
        return sender_keys
    except FileNotFoundError as e:
        print(e)
        print("Use --generate option first to create sender\nand recipient keys.")
        exit()


def is_prime(n: int) -> bool:
    """
    Returns True if "n" is a prime number. A prime number is a positive integer greater than 1 that has no positive integer divisors other than 1 and itself.

    Called from generate_keys().

    Parameters
    ----------
    n : int -- any integer

    Returns
    -------
    bool -- True if "n" is a prime number.
    """
    if n <= 1:
        return False

    for i in range(2, n):
        if n % i == 0:
            return False

    return True


def print_keys() -> None:
    """
    Print the sender's and recipient's keys.
    """

    try:
        with open("sender.json", 'r', encoding='utf-8') as file:
            sender_keys = json.load(file)
        with open("recipient.json", 'r', encoding='utf-8') as file:
            recipient_keys = json.load(file)
    except FileNotFoundError as e:
        print(e)
        print("Use --generate option first to create sender\nand recipient keys.")
        exit()

    print('SENDER KEYS:')
    for k, v in sender_keys.items():
        print(f'{k}: {v}')

    print('\nRECIPIENT KEYS:', sep='')

    for k, v in recipient_keys.items():
        print(f'{k}: {v}')

    """
    shared_key: int = (recipient_keys['public_number']**sender_keys['secret_number']) % sender_keys['m']
    """

    h1: str = ' TROUBLESHOOTING ONLY '
    h2: str = 'SHARED KEYS SHOULD BE THE SAME'
    h3: str = 'AND SHOULD NEVER BE TRANSMITTED'
    print()
    print(h1.center(43, "="), sep='')
    print(h2.center(43))
    print(h3.center(43), "\n", sep="")

    print(f"   Shared key - sender: {recipient_keys['public_number'] ** sender_keys['secret_number'] % sender_keys['modulus']}")
    print(f"Shared key - recipient: {sender_keys['public_number'] ** recipient_keys['secret_number'] % recipient_keys['modulus']}")
    print("=".center(43, "="))

    return


def main(plaintext: str, generate: bool, file: str, printkeys: bool) -> None:
    """
    Main organizing function for the CLI.

    Parameters
    ----------
    plaintext : str -- message to encrypt
    file : str -- file containing text to encrypt
    printkeys : bool -- if True, print the sender's and recipient's keys and exit

    """

    if printkeys:
        print_keys()
        exit()

    if generate:
        generate_DH()
        exit()

    # If there's a file name on the command line, put its contents into "message".
    if file:
        p = Path(file)
        if p.exists():
            with open(p, 'r', encoding='utf-8') as f:
                message: str = f.read()
        else:
            print(f'Could not find file "{file}"')
            exit()
    else:
        message = plaintext

    # If there's a message, then encrypt it. If there are no arguments, decrypt the "ciphertext" in encrypted.json
    if message:
        # First, generate keys for both sender and recipient, so we have the keys to encrypt with.
        encrypt(message)
    else:
        # The keys for decryption are store in sender and recipient key files.
        decrypt()


if __name__ == '__main__':
    print()
    cli()
