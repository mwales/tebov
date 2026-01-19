# tebov

Trust-no-one Encrypted Backup Offsite With Verification

# Format of local index

```
NUM_FILES=
DATE=
pathname:hash:flag:ct_hash
```

* NUM_FILES so we can tell if the index was completely written or was cut off before completion
* DATE: informational purposes.  Not sure format will even matter
* pathname will ignore newlines.  colons in filenames will be escaped as double colons in the pathname
* hash will be sha256 sum
* flag will be the following:
  * N for no compression
  * g for gzip
* ct_hash will be sha256 sum

# Encoding of cipher text

Files will be encrypted with AES_SIV (because it is OK to have nonce reuse and
deterministic ciphertext (won't change).  Where many forms of AES would have a
random nonce that would generate a completely different ciphertext each time.
This is usually not desireable because an attacker can see the same ciphertext
and know that it was from the same plaintext, but we want this feature to
reduce the size of archive data.

# Backup process

1. Gather a list of all the filenames in the path that is getting backed up
2. Load the last backup list as well as a cache of files that are already
   backed up
3. Compute the hash of each file.  You can then determine if the file is
   already been backed up / ciphertext hash information from history index
4. Write the entire index file to disk as an encrypted gzip
5. The list of files that don't already exist on the backup server based on
   hashes need to be copied to the backup server, and our new index file.
6. When files are transfered to offline backup server they are optionally
   compressed, encrypted, and the file name is based on the hash of the
   ciphertext.  The name will be /aa/bb/cc/xxxxx...xxx where aa, bb, and
   cc are the first bytes of the hash (creating a folder structure on the
   backup server with up to 256 subdirectories in each folder
7. A verification service on the backup server should periodically run to
   verify that the files in each index still match the hash of their path
   name

* Files that change path just end up with a new path in later indexes
* Files that are duplicated just end up with multiple path entries in the
  index but only need to be copied to the backup server once
* Don't delete files arbitrarily.  Thus a malware attack won't remove good
  historical files
* Index can be used to verify presence of files already on the filesystem.
  For instance, when backing up your personal camera flash memory to your
  system, which photos do you already have.  A program could hash each
  photo on camera flash and look in index to see if that hash already
  exists, and only leave behind the new photos to be organized / stored.

# Config file

Config file will be a list of key/value pairs

* BACKUP_SERVER: rsync will be used to transfer file to the backup server
* BACKUP_SERVER_USER: username for backup server user
* BACKUP_SERVER_BACKUP_PATH: path to put backup files
* BACKUP_SERVER_INDEX_PATH: path to put the index files
* LOCAL_INDEX_PATH: path where we should store index files
* LOCAL_PATH_TO_BACKUP: path to the files locally we want backed up

# Backup utilities

* create_backup_index config_file
* verify_backup_index config_file
* send_latest_index_to_server config_file

