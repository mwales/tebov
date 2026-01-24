#!/usr/bin/env python3

import sys
import os
import logging
import paramiko # apt-get install python3-paramiko
import bz2
import struct
import stat

from typing import Tuple, Dict

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

    remote_path_cache = set()

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
    def verify_remote_dir_or_create(cls, sftp_client, cur_path):
        # Simplify / normalize the path if possible
        cur_path = os.path.normpath(cur_path)
        logging.debug(f"verifying directory {cur_path}")

        # Check cache
        if cur_path in CryptoUtils.remote_path_cache:
            logging.debug(f"Path {cur_path} already in the cache")
            # We have already check this path once before
            return

        try:
            st = sftp_client.stat(cur_path)
            if stat.S_ISDIR(st.st_mode):
                # We confirm this path exists, add to cache and return
                CryptoUtils.remote_path_cache.add(cur_path)
                logging.debug(f"Path {cur_path} was found on remote system")
                return
        except IOError as e:
            logging.debug(f"Stat of {cur_path} generated an exception, must not be there")
         

        # Path doesn't exist, check directory (and create if neccessary) below us
        last_dir_marker = cur_path.rfind("/")
        if last_dir_marker > 0 and last_dir_marker < (len(cur_path) - 1):
            # The slash we found was neither at the end or beginning
            below_path = cur_path[:last_dir_marker]
            CryptoUtils.verify_remote_dir_or_create(sftp_client, below_path)

        # Now, lets make the current directory since it doesn't exists
        logging.debug(f"Making path {cur_path} and adding to the cache")
        sftp_client.mkdir(cur_path)
        CryptoUtils.remote_path_cache.add(cur_path)


    @classmethod
    def move_remote_file_mkpath(cls, sftp_client, original_path, new_path, filename):
        # Lets build the path if it isn't already there
        CryptoUtils.verify_remote_dir_or_create(sftp_client, new_path)
        sftp_client.rename(original_path, new_path + "/" + filename)

    @classmethod
    def hash_to_filepath(cls, folder: str, hash_bytes: bytes) -> Tuple [ str, str ]:
        hash_value_str = hash_bytes.hex()
        backup_folders = folder + "/" + hash_value_str[0:2] + "/" + hash_value_str[2:4]
        final_name = hash_value_str[4:]
        return (backup_folders, final_name)

    @classmethod
    def compress_crypt_txfer(cls, in_path, key, sftp_client, folder):
        input_file = open(in_path, "rb")

        temp_filename = folder + "/" + "txfer_in_progress"
        output_file = sftp_client.open(temp_filename, "wb")
        
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

        backup_folders, final_name = CryptoUtils.hash_to_filepath(folder, hash_value)

        logging.debug(f"Moving {temp_filename} to {backup_folders}/{final_name}")
        CryptoUtils.move_remote_file_mkpath(sftp_client, temp_filename, backup_folders, final_name)

        return hash_value, total_bytes_read, total_bytes_written

    @classmethod
    def compute_compress_crypt_hash(cls, in_path, key):
        """ Uses same compression and encryption method and returns the hash of the CT file"""
        input_file = open(in_path, "rb")
        
        compressor = bz2.BZ2Compressor()
        hash_ctx = SHA256.new()

        total_bytes_read = 0
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

            hash_ctx.update(len_bytes + ct)

        # Edge case, empty file
        if total_bytes_read == 0:
            # File was empty to begin with, just ignore
            input_file.close()

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

            hash_ctx.update(len_bytes + ct)

        hash_value = hash_ctx.digest()
        return hash_value



if __name__ == "__main__":
    print("Don't run this file directly")
