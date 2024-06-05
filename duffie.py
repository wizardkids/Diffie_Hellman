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



if __name__ == '__main__':
    print()
    cli()
