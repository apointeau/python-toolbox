#! /usr/bin/env python

# @Author: Antoine Pointeau <kalif>
# @Date:   2018-01-10T00:35:01+01:00
# @Email:  web.pointeau@gmail.com
# @Filename: file_encryption.py
# @Last modified by:   kalif
# @Last modified time: 2018-01-10T01:14:13+01:00

""" This is a quick demo of file AES encryption. It requires the python module
    'pycrypto' to be installed with pip on you system.
    The sample is highly inspirated by:
    https://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
"""

import os
import random
import struct
import sys
import argparse
import hashlib

from Crypto.Cipher import AES


def encrypt_file(key, in_filename, out_filename=None, chunksize=64 * 1024):
    """ Encrypts a file using AES (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        in_filename:
            Name of the input file

        out_filename:
            If None, '<in_filename>.enc' will be used.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
    if not out_filename:
        out_filename = in_filename + '.enc'

    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)
                outfile.write(encryptor.encrypt(chunk))


def decrypt_file(key, in_filename, out_filename=None, chunksize=24 * 1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
    """
    if not out_filename:
        if in_filename.endswith(".enc"):
            out_filename = os.path.splitext(in_filename)[0]
        else:
            out_filename = in_filename + ".dec"

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'action', metavar="ACTION", choices=["encrypt", "decrypt"],
        help="Action to perform (choices: encrypt, decrypt)"
    )
    parser.add_argument(
        'password', metavar="PASSWORD",
        help="Secret key password to lock/unlock the encryption"
    )
    parser.add_argument(
        'in_filename', metavar="INFILE",
        help="Name of the file to use as input"
    )
    parser.add_argument(
        'out_filename', metavar='OUTFILE', nargs="?", default=None,
        help="Name of the file to output (default: please lookup at the code)"
    )
    args = parser.parse_args()
    key = hashlib.sha256(args.password).digest()
    if args.action == "encrypt":
        encrypt_file(key, args.in_filename, args.out_filename)
    else:
        decrypt_file(key, args.in_filename, args.out_filename)


if __name__ == "__main__":
    warn = "WARNING: This programm is a demonstration, use it carefully."
    sys.stderr.write(warn + "\n")
    main()
