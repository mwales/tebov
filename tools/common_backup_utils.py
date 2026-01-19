#!/usr/bin/env python3

import sys
#import crypt
import os
import logging
import paramiko

from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.KDF import scrypt
from Cryptodome.Cipher import AES

class ConfigFile:

    required_config = [ 
        "BACKUP_SERVER",
        "BACKUP_SERVER_USER",
        "BACKUP_SERVER_BACKUP_PATH",
        "BACKUP_SERVER_INDEX_PATH",
        "LOCAL_INDEX_PATH",
        "LOCAL_PATH_TO_BACKUP" ]

    def __init__(self, filepath):

        
        self.config = {}
        try:
            cf = open(filepath, "r")
            cfd = cf.read().split("\n")
        except FileNotFoundError as e:
            logging.error(f"Couldn't find config file {filepath}")
            return
        except PermissionError as e:
            logging.error(f"Couldn't read config file {filepath}, check permissions?")
            return

        for config_line in cfd:
            tokens = config_line.split("=")
            if len(tokens) != 2:
                continue
            self.config[tokens[0]] = tokens[1]

    def is_required_config_available(self):
        reqd = set(ConfigFile.required_config)
        present = set(self.config.keys())

        missing = reqd - present
        if missing:
            write(sys.stderr, "Missing configuration: {missing}")
            return False
        else:
            return True

    @classmethod
    def print_configuration_sample(cls):
        print("Sample configuration file contents:")
        print(" ")
        for key in ConfigFile.required_config:
            print(f"{key}=VALUE")

    def get(self, key):
        return self.config[key]

class BackupUtils:
    @classmethod
    def get_file_list(cls, directory_path):
        """
        Can't use built in glob stuff because I don't want to follow sym links
        """
        retval = []
        for dirpath, dirnames, filenames in os.walk(directory_path, followlinks=False):

            for fn in filenames:
                retval.append(os.path.join(dirpath, fn))

        return retval

class CryptoUtils:
    chunkSize = 16 * 1024 * 1024 # 16MB

    @classmethod
    def calc_file_hash(cls, filename):
        hash_ctx = SHA256.new()

        input_file = open(filename, "rb")
        
        while(True):
            chunk = input_file.read(CryptoUtils.chunkSize)

            if len(chunk):
                hash_ctx.update(chunk)
            else:
                # We are at the end of the file
                input_file.close()
                return hash_ctx.digest()

    @classmethod
    def deriveKey(cls, crypt_pass: str, salt: bytes) -> bytes:
        return scrypt(crypt_pass, salt, 64, N=2**20, r=8, p=1)

    @classmethod
    def encryptBytes(cls, key, inbytes: bytes):
        ctx = AES.new(key, AES.MODE_SIV)
        ct, tag = ctx.encrypt_and_digest(inbytes)
        print(f"Length of ct = {len(ct)} and tag = {len(tag)}")
        return tag + ct

    @classmethod
    def decryptBytes(cls, key: bytes, inbytes: bytes):
        if len(inbytes) < 16:
            raise ValueError("Bytes for decryption not long enough to even have tag")

        tag = inbytes[:16]
        ctx = AES.new(key, AES.MODE_SIV)
        pt = ctx.decrypt_and_verify(inbytes[16:], tag)
        return pt
    



    #@classmethod
    #def encyrptFileAndSend(cls, localfilename: str, crypt_pass: str, server: str, username: str, destpath: str) -> Tuple [ Boolean, bytes ]:
            

if __name__ == "__main__":
    print("Don't run this file directly")
