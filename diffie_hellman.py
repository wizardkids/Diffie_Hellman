"""
    Filename: duffie.py
     Version: 0.1
      Author: Richard E. Rawson
        Date: 2024-06-05
 Description: This program includes two major functions:
     (i) DH key exchange
    (ii) AES encryption

Unlike other encryption programs that I have written, this one includes a mechanism for secure transmission of the key to decryption.  The generate_DH() function generates keys for BOTH the sender and the recipient. Both parties then have the key to encrypt/decrypt the text, since encryption uses the key that both parties have.

This introduces a potential confusion, since in real life, the sender would generate a public and private set of keys, and pass the public key to the recipient. The recipient would do the same, passing their key to the sender. Now each party has the other party's public key and, with their own secret number, both party's can generate a shared key to use for encryption and decryption.

Public keys are stored in "sender_key_file.json" and "recipient_key_file.json", along with each party's "secret" or private number. These data can be used to generate the shared key that is required to encrypt and decrypt text. Public keys are meant to be public or, at least, not secure. Obviously, storing the sender's and recipient's secret number alongside the public keys is the epitome of insecurity. But that is the only way this program can work!
"""

import json
from pathlib import Path
from random import randint
from typing import TypeVar

import click
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from icecream import ic

T = TypeVar("T")

VERSION = "0.1"


@click.command(help="Encrypt/decrypt [MESSAGE] or [PATH] using AES encryption and prepare Diffie-Hellman keys for sender and recipient for secure transmission of encrypted text.\n\n[MESSAGE] must be a quote-delimited string.\n\nThe encrypted content is written to \"encrypted.json\" and the content of that file is decrypted to \"unencrypted.txt\". If either file exists, it will be overwritten.", epilog="EXAMPLE USAGE:\n\ndiffie_hellman.py \"The troops roll out at midnight.\" --> sender encrypts the text using the shared key\n\ndiffie_hellman.py --> \"encrypted.json\" is decrypted by the recipient using the shared key\n\nPublic keys are stored in \"sender_key_file.json\" and \"recipient_key_file.json\" along with each party's \"secret\" or private number. These data are used to generate the shared key that is required to encrypt and decrypt text.")
@click.argument("message", type=str, required=False)
@click.option("-g", "--generate", is_flag=True, default=False, help='Generate Diffie-Hellman keys.')
@click.option("-f", "--file", type=click.Path(exists=False), help='File to encrypt.')
@click.option("-p", "--printkeys", is_flag=True, default=False, help="Print sender and recipient keys.")
@click.version_option(version=VERSION)
def cli(message: str, generate: bool, file: str, printkeys: bool) -> None:
    """
    Entry point for this CLI.

    Parameters
    ----------
    message : str -- text message to encrypt
    file : click.Path -- file containing text to encrypt
    printkeys : bool -- utility function to print encryption keys
    """

    print()
    ic(message)
    ic(generate)
    ic(file)
    ic(printkeys)
    print()

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

    # To encrypt, keys will have already been generated and stored in sender.json and recipient.json
    with open("sender.json", 'r', encoding='utf-8') as file:
        sender_keys = json.load(file)
    with open("recipient.json", 'r', encoding='utf-8') as file:
        recipient_keys = json.load(file)

    # Using the recipient's publick key and the sender's private key, calculate the "shared_secret" value.
    shared_key: int = (recipient_keys['public_number']**sender_keys['secret_number']) % sender_keys['m']

    # Convert "message" from a str to a byte string.
    data: bytes = message.encode(encoding='utf-8')

    # Generate iterations, key_length, and salt in bytes. This is a very big number!
    salt: bytes = get_random_bytes(16)
    iterations: int = 100_000
    key_length: int = 32

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
    with open('encrypted.json', 'rb') as file:
        info = json.load(file)

    ciphertext: bytes = bytes.fromhex(info['ciphertext'])
    salt: bytes = bytes.fromhex(info['salt'])
    iterations: int = info['iterations']
    iv: bytes = bytes.fromhex(info['iv'])

    # Retrieve the sender's and recipient's key information.
    with open("sender.json", 'r', encoding='utf-8') as file:
        sender_keys = json.load(file)
    with open("recipient.json", 'r', encoding='utf-8') as file:
        recipient_keys = json.load(file)

    shared_key = (sender_keys['public_number']**recipient_keys['secret_number']) % recipient_keys['m']

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
    b^secret_number mod m. This formula is public. b and m are known to both parties. m must be a prime number.

    "secret_number" is known only to the parties and each party has a different "secret_number". In this function, a "secret_number" is selected randomly and assigned to each party. That number is used by each party to calculate a "public_number". Each party shares their "public_number" with the other party.

    Each party can calculate a "shared_key" by using THEIR "secret_number" and the OTHER party's "public_number".

    "b", "m", "secret_number_A", "secret_number_B", "public_number_A", "public_number_B" are all values required to calculate a "shared_key"

    CODENOTE
    Because adhering to the following results in very long computation times, I have chosen to deviate. But following are the guidelines for selecting "b", "m", and the "secret number".
    "b":
        The base, it's often chosen to be a small prime number or a primitive root modulo "m". While "b" doesn't need to be as large as "m", it should be chosen to ensure the security properties of the Diffie-Hellman exchange are maintained. In many cases, "b" is simply set to 2 or another small number.

    "m":
        You need to generate a large prime number that is at least 2048 bits long for adequate security. This is not something you can do with a simple random byte generator, as the number must be prime, not just random. There are specialized algorithms and libraries designed to generate large prime numbers for cryptographic purposes. For example, OpenSSL provides functionality to generate such prime numbers1.

    "secret_number":
        Randomness: "secret_number" should be randomly generated to ensure that it cannot be guessed or predicted by an attacker.
        Size: The size of "secret_number" should be similar to the size of "m". If "m" is 2048 bits, then "secret_number" should also be a random number that is 2048 bits long.
        Range: "secret_number" should be in the range ( [1, m-2] ). It’s important that "secret_number" is not too small, as small values can weaken the security of the key exchange.
    """

    party = ""
    while party not in ['s', 'r']:
        party: str = input("Keys are for [s]ender or [r]ecipient: ").lower()

    # Bob and Alice must agree on "b" and "m". Bob already decided on "b" and "m". Because they are essentially public, Alice retrieves those values and uses them.
    if party == "r":
        sender_keys: dict[str, int] = get_sender_info()
        b: int = sender_keys['b']
        m: int = sender_keys['m']
    else:
        b: int = 2
        while True:
            m: int = randint(10, 256)
            # m: int = randint(10, 256)
            if is_prime(m):
                break

    # Bob and Alice each select a unique number that is a secret. The numbers shouldn't be the same.
    secret_number: int = randint(1000, 10000)
    # secret_number_B: int = randint(1000, 10000)
    # while secret_number_A == secret_number_B:
    #     secret_number_B: int = randint(1000, 10000)

    # modular function to create numbers that Bob and Alice need to exchange with each other.
    public_number: int = (b**secret_number) % m
    # public_number_B: int = (b**secret_number_B) % m

    """
    Each party can compute a shared number, based only on the public number of the OTHER party and THEIR OWN secret number. This way, computation of the valuable shared number only requires sharing a publically available number.

    shared_key_A: int = (public_number_B**secret_number_A) % m  # 12^5 mod 13 = 12
    shared_key_B: int = (public_number_A**secret_number_B) % m  # 7^6 mod 13 = 12
    """

    keys: dict[str, int] = {"b": b, "m": m, "secret_number": secret_number, "public_number": public_number}

    # recipient_keys: dict[str, int] = {"m": m, "secret_number_B": secret_number_B, "public_number_B": public_number_B}

    filename: str = 'sender.json' if party =='s' else 'recipient.json'

    with open(filename, 'w', encoding="utf-8") as f:
        json.dump(keys, f)

    print(f'Keys for {filename[:-5]} saved in "{filename}".')
    pass

    # with open("recipient_key_file.json", 'w', encoding="utf-8") as f:
    #     json.dump(recipient_keys, f)


def get_sender_info() -> dict[str, int]:
    with open("sender.json", 'r', encoding='utf-8') as file:
        sender_keys = json.load(file)
    return sender_keys

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

    with open("sender_key_file.json", 'r', encoding='utf-8') as file:
        sender_keys = json.load(file)
    with open("recipient_key_file.json", 'r', encoding='utf-8') as file:
        recipient_keys = json.load(file)

    for k, v in sender_keys.items():
        print(f'{k}: {v}')
    print()

    for k, v in recipient_keys.items():
        print(f'{k}: {v}')

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

    print()
    ic(plaintext)
    ic(generate)
    ic(file)
    ic(printkeys)
    print()

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
        # generate_DH()
        encrypt(message)
    else:
        # The keys for decryption are store in sender and recipient key files.
        decrypt()


if __name__ == '__main__':
    print()
    cli()
