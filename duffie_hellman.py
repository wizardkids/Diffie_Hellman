"""
    Filename: duffie.py
     Version: 0.1
      Author: Richard E. Rawson
        Date: 2024-06-05
 Description: Encryption using the Duffie-Hellman encryption scheme.

"""

import json
import math
from pathlib import Path
from random import randint

import click
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from icecream import ic

VERSION = "0.2"


@click.command(help="Encrypt or decrypt [MESSAGE] or [PATH] using Duffie-Hellman encryption. [MESSAGE] must be a quote-delimited string.\n\nThe encrypted content is written to \"encrypted.txt\" and the content of that file is decrypted to \"decrypted.txt\". If either file exists, it will be overwritten.", epilog="EXAMPLE USAGE:\n\nrsa_encryption.py \"The troops roll out at midnight.\" --> encrypts for a specified recipient\n\nrsa_encryption.py --> decrypts \"encrypted.txt\" for a specified recipient")
@click.argument("message", type=str, required=False)
@click.option("-f", "--file", type=click.Path(exists=False), help='File to encrypt.')
@click.option("-p", "--printkeys", is_flag=True, default=False, help="Print the keys for a specified recipient.")
@click.option("-g", "--generate", is_flag=True, default=False, help="Generate keys for a recipient.")
@click.version_option(version=VERSION)
def cli(message, file, printkeys, generate) -> None:

    print()
    ic(message)
    ic(file)
    ic(printkeys)
    ic(generate)
    print()

    main(message, file, printkeys, generate)


def main(message, file, printkeys, generate) -> None:

    generate_keys()
    encrypt("The troops roll out at midnight.")


def encrypt(msg):
    data = msg.encode()
    shared_secret, encrypted_bundle = generate_keys()
    salt = encrypted_bundle['salt']
    iterations = encrypted_bundle['iterations']
    key_length = 32

    key: bytes = PBKDF2(shared_secret, salt, dkLen=key_length, count=iterations, hmac_hash_module=SHA256)

    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    nonce: bytes = cipher.nonce
    # iv = cipher.iv

    # Bundle the encrypted data with the salt, iterations, and nonce
    encrypted_bundle = {
        'ciphertext': ciphertext.hex(),
        'salt': salt.hex(),
        'iterations': iterations,
        # 'iv': iv.hex(),
        'nonce': nonce.hex()
    }

    with open('encrypted.json', 'w') as f:
        json.dump(encrypted_bundle, f)

    return # json.dumps(encrypted_bundle)


def decrypt(encrypted_bundle, password) -> any:
    # Unpack the encrypted bundle
    bundle = json.loads(encrypted_bundle)
    ciphertext = bytes.fromhex(bundle['ciphertext'])
    salt = bytes.fromhex(bundle['salt'])
    iterations = bundle['iterations']
    iv = bytes.fromhex(bundle['iv'])
    # Derive the key using the provided salt and iterations
    key = PBKDF2(password, salt, dkLen=32, count=iterations)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = cipher.decrypt(ciphertext)
    return data


def generate_keys() -> tuple[bytes, dict]:
    """
    Generate key for both ends of an encrypted communication.

    Returns
    -------

    """

    # b should be a primitive root, but I will wait to implement that.
    b: int = randint(3, 10)

    while True:
        m: int = randint(10, 99)
        if is_prime(m):
            break

    # Create a private key for each end of the communication. The keys can't be the same.
    private_key_A: int = randint(10, 99)
    private_key_B = randint(10, 99)
    while private_key_A == private_key_B:
        private_key_B: int = randint(10, 99)

    # Create public keys for each end of the communication.
    public_key_A = (b**private_key_A) % m
    public_key_B = (b**private_key_B) % m

    # Calculate the shared secret number. _A and _B should be the same,
    # so with the following code, I can check that they are.
    shared_secret_A: int = (public_key_A**private_key_B) % m
    shared_secret_B: int = (public_key_B**private_key_A) % m
    shared_secret_int: int = shared_secret_A

    # 16 is the length of the bytes object, 'big' is the byte order
    shared_secret: bytes = shared_secret_int.to_bytes(16, 'big')

    # Generate a random salt.
    salt: bytes = get_random_bytes(16)

    # Number of iterations.
    iterations: int = 100_000

    # Desired key length.
    key_length: int = 32

    # Derive the key. Since "key" is based on the same "salt" and "shared_secret", it will be the same as long as both parties have the salt and the "shared_secret".
    # This requires sending "salt" and "iterations" along with then encrypted data.
    key: bytes = PBKDF2(shared_secret, salt, dkLen=key_length, count=iterations, hmac_hash_module=SHA256)

    encrypted_bundle = {
        'ciphertext': "",
        'salt': salt,
        'iterations': iterations,
        'iv': ""
    }

    # To convert "salt" from hex to binary string for decryption:
    # salt = bytes.fromhex(salt_hex)


    # ic(b)
    # ic(m)
    # ic(public_key_A)
    # ic(public_key_B)
    # ic(private_key_A)
    # ic(private_key_B)
    # ic(shared_secret_A)
    # ic(shared_secret_B)
    # ic(shared_secret)
    # ic(salt)
    # print(key)
    # pass

    return shared_secret, encrypted_bundle

    # Here, we save the public_key, private_key, p, and q:
    # print("The name you enter will be the filename for the\nfile holding the keys.")
    # user_name: str = input("To whom do these keys belong: ").lower()
    # if user_name:
    #     keys = {"public_key": public_key, "private_key": m}
    #     filename: str = user_name.strip() + ".json"
    #     with open(filename, 'w', encoding="utf-8") as f:
    #         json.dump(keys, f)
    # else:
    #     print("No recipient name entered.")
    #     exit()


def is_prime(n: int) -> bool:
    """
    Returns True if "n" is a prime number. A prime number is a positive integer greater than 1 that has no positive integer divisors other than 1 and itself.

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


if __name__ == '__main__':
    print()
    cli()
