#!/usr/bin/env python3

import sys
import os
import logging
import paramiko # apt-get install python3-paramiko
import bz2
import struct

# apt-get install python3-pycryptodome
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
    def start_sftp(cls, hostname, username):
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
        ssh.connect(hostname=hostname, username=username)
        sftp = ssh.open_sftp()
        return ssh, sftp


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

    @classmethod
    def compress_crypt_txfer(cls, in_path, key, sftp_client, folder):
        input_file = open(in_path, "rb")

        output_file = sftp_client.open(folder + "/" + "txfer_in_progress", "wb")
        
        compressor = bz2.BZ2Compressor()
        hash_ctx = SHA256.new()

        total_bytes_read = 0
        total_bytes_written = 0
        compressed_data = bytes()
        while True: 
            chunk = input_file.read(CryptoUtils.chunkSize)

            if len(chunk) <= 0:
                break

            total_bytes_read += len(chunk)
            compressed_data += compressor.compress(chunk)

            if len(compressed_data) < CryptoUtils.chunkSize:
                # Want to feed the crypto chunkSize blocks, compress more until
                # we get to a full chunk size
                continue

            if len(compressed_data) > CryptoUtils.chunkSize:
                ct = CryptoUtils.encryptBytes(key, compressed_data[:CryptoUtils.chunkSize])
                compressed_data = compressed_data[CryptoUtils.chunkSize:]
            else:
                ct = CryptoUtils.encryptBytes(key, compressed_data)
                compressed_data = bytes()

            len_bytes = struct.pack(">I", len(ct))

            output_file.write(len_bytes + ct)
            hash_ctx.update(len_bytes + ct)

            total_bytes_written += len(ct) + 4

        # Edge case, empty file
        if total_bytes_read == 0:
            # File was empty to begin with, just ignore
            input_file.close()
            output_file.close()

            return None, 0, 0

        input_file.close()

        compressed_data += compressor.flush()
        while len(compressed_data) > 0:
    
            if len(compressed_data) > CryptoUtils.chunkSize:
                ct = CryptoUtils.encryptBytes(key, compressed_data[:CryptoUtils.chunkSize])
                compressed_data = compressed_data[CryptoUtils.chunkSize:]
            else:
                ct = CryptoUtils.encryptBytes(key, compressed_data)
                compressed_data = bytes()

            len_bytes = struct.pack(">I", len(ct))

            output_file.write(len_bytes + ct)
            hash_ctx.update(len_bytes + ct)

            total_bytes_written += len(ct) + 4

        output_file.close()

        hash_value = hash_ctx.digest()

        return hash_value, total_bytes_read, total_bytes_written





    

    #@classmethod
    #def encyrptFileAndSend(cls, localfilename: str, crypt_pass: str, server: str, username: str, destpath: str) -> Tuple [ Boolean, bytes ]:
            

if __name__ == "__main__":
    print("Don't run this file directly")
