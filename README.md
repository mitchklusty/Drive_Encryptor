# Drive_Encryptor

This code uses Python to encrypt and decrypt files in the programs current directory(and all subdirectories). 

Usage
------
Run the program in the desired directory. The program determines if it needs to encrypt or decrypt the files based on the presence of the "LOCKER_PASS.key" file. If the file is present, it will attempt to decrypt the files. If it is not it will attempt to encrypt the data. 

Encryption
------------
The program will ask the user for a password and to confirm that password. Once the two match, the hash and salt of the password will be stored in "LOCKER_PASS.key" and use AES-256 to encrypt the files based on a key generated from the password.

Decryption
-----------
The program will ask the user to enter a password. If the hash of the password + the salt stored in "LOCKER_PASS.key" matches the hash in "LOCKER_PASS.key", the files will be decrypted based on that password. This requires the integrity of "LOCKER_PASS.key" be ensured between encryption and decryption.
