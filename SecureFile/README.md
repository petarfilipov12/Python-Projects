SecureFile.py

The contents of the secure file are encrypted using AES algorithm and stored in file named "data".
It uses sha256 to store password hash (file named "passhash"), blake2s and md5, calculated from passphrase, for AES key and nonce.
Simple GUI, using PyQT.
