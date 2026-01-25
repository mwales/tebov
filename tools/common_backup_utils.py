#!/usr/bin/env python3

import sys
import os
import logging
import paramiko # apt-get install python3-paramiko
import bz2
import struct
import stat


from typing import Tuple, Dict, Set

# apt-get install python3-pycryptodome
from Cryptodome.Hash import SHA256, MD5
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
    def deriveKey(cls, crypt_pass: str) -> bytes:
        # Fixed salt
        salt_gen = MD5.new(b"\x7e\xb0" + crypt_pass.encode("utf-8") + b"\x7e\xb0")
        salt = salt_gen.digest()
        return scrypt(crypt_pass, salt, 64, N=2**20, r=8, p=1)

    @classmethod
    def calc_local_file_hash(cls, filename: str):
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
    def encryptBytes(cls, key: bytes, inbytes: bytes):
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
    def compute_compress_crypt_hash(cls, in_path: str, key: bytes) -> Tuple [ bytes, int ]:
        """ Uses same compression and encryption method and returns the hash of
        the CT file, and the file length of CT"""
        input_file = open(in_path, "rb")
        
        compressor = bz2.BZ2Compressor()
        hash_ctx = SHA256.new()

        total_bytes_read = 0
        final_size = 0
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
            final_size += 4 + len(ct)

        # Edge case, empty file
        if total_bytes_read == 0:
            # File was empty to begin with, just ignore
            input_file.close()

            return None, 0

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
            final_size += 4 + len(ct)

        hash_value = hash_ctx.digest()
        return hash_value, final_size




class RemoteServer:
    chunkSize = 16 * 1024 * 1024 # 16MB

    remote_path_cache: Set [ str ] = set()

    def __init__(self, hostname: str, username: str, remote_folder: str):
        # Keep a cache of all the directories that are present (don't need to
        # be rechecked each file transfer
        self.remote_path_cache = set()
        
        self.ssh = paramiko.SSHClient()
        self.ssh.load_system_host_keys()
        self.ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
        self.ssh.connect(hostname=hostname, username=username)
        self.sftp = self.ssh.open_sftp()

        self.remote_folder = remote_folder

        self.logger = logging.getLogger("RemoteServer")

    def close(self):
        self.sftp.close()
        self.ssh.close()

    def get_remote_file_size(self, filename: str):
        self.logger.debug(f"Getting remote filesize of {filename}")
        remote_full_path = self.remote_folder + "/" + filename
        self.logger.debug(f"remote full path {remote_full_path}")
        
        try:
            st = self.sftp.stat(remote_full_path)
            self.logger.debug(f"st = {st}")
            return st.st_size
        except Exception as e:
            self.logger.debug(f"Got an exception from stat: {e}")
            return 0

    def make_path(self, remote_subfolder):
        # Simplify / normalize the path if possible
        folder_normal = os.path.normpath(remote_subfolder)
        remote_full_path = self.remote_folder + "/" + folder_normal
        self.logger.debug(f"verifying directory {remote_full_path}")

        # Check cache
        if folder_normal in self.remote_path_cache:
            self.logger.debug(f"Folder {folder_normal} already in the cache")
            # We have already check this path once before
            return

        try:
            st = self.sftp.stat(remote_full_path)
            if stat.S_ISDIR(st.st_mode):
                # We confirm this path exists, add to cache and return
                self.remote_path_cache.add(folder_normal)
                self.logger.debug(f"Path {folder_normal} was found on remote system")
                return
        except IOError as e:
            self.logger.debug(f"Stat of {folder_normal} generated an exception, must not be there")
         

        # Path doesn't exist, check directory (and create if neccessary) below us
        last_dir_marker = folder_normal.rfind("/")
        if last_dir_marker > 0 and last_dir_marker < (len(folder_normal) - 1):
            # The slash we found was neither at the end or beginning
            below_path = folder_normal[:last_dir_marker]
            self.make_path(below_path)

        # Now, lets make the current directory since it doesn't exists
        self.logger.debug(f"Making path {folder_normal} and adding to the cache")
        self.sftp.mkdir(remote_full_path)
        self.remote_path_cache.add(folder_normal)

    def move_remote_file_mkpath(self, original_path, new_path, filename):
        # Lets build the path if it isn't already there
        self.make_path(new_path)
        self.sftp.rename(self.remote_folder + "/" + original_path, self.remote_folder + "/" + new_path + "/" + filename)
        

    @classmethod
    def hash_to_filepath(cls, hash_bytes: bytes) -> Tuple [ str, str ]:
        hash_value_str = hash_bytes.hex()
        backup_folders = hash_value_str[0:2] + "/" + hash_value_str[2:4]
        final_name = hash_value_str[4:]
        return (backup_folders, final_name)

    def compress_crypt_txfer(self, key: bytes, in_path: str):
        input_file = open(in_path, "rb")

        temp_filename = "txfer_in_progress"
        output_file = self.sftp.open(self.remote_folder + "/" + temp_filename, "wb")
        
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

        backup_folders, final_name = RemoteServer.hash_to_filepath(hash_value)

        logging.debug(f"Moving {temp_filename} to {backup_folders}/{final_name}")
        self.move_remote_file_mkpath(temp_filename, backup_folders, final_name)

        return hash_value, total_bytes_read, total_bytes_written



if __name__ == "__main__":
    print("Don't run this file directly")
