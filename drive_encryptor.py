from hashlib import md5
from Cryptodome.Cipher import AES
import os, sys
from os import urandom
import random
import string
import getpass

PASSWORD_FILE = "LOCKER_PASS.key"

def derive_key_and_iv(password, salt, key_length, iv_length): #derive key and IV from password and salt.
	d = d_i = b''
	while len(d) < key_length + iv_length:
		d_i = md5(d_i + str.encode(password) + salt).digest() #obtain the md5 hash value
		d += d_i
	return d[:key_length], d[key_length:key_length+iv_length]

def encrypt_file(file, password, key_length=32):
	file_read = open(file, 'rb')
	bs = AES.block_size #16 bytes
	salt = urandom(bs) #return a string of random bytes
	key, iv = derive_key_and_iv(password, salt, key_length, bs)
	cipher = AES.new(key, AES.MODE_CBC, iv)
	output = salt
	finished = False

	while not finished:
		chunk = file_read.read(1024 * bs) 
		if len(chunk) == 0 or len(chunk) % bs != 0:#final block/chunk is padded before encryption
			padding_length = (bs - len(chunk) % bs) or bs
			chunk += str.encode(padding_length * chr(padding_length))
			finished = True
		output += cipher.encrypt(chunk)
	file_read.close()

	with open(file, "wb") as file_out:
		file_out.write(output)


def decrypt_file(file, password, key_length=32):
	file_read = open(file, 'rb')
	bs = AES.block_size
	salt = file_read.read(bs)
	key, iv = derive_key_and_iv(password, salt, key_length, bs)
	cipher = AES.new(key, AES.MODE_CBC, iv)
	next_chunk = ''
	finished = False
	out_stream = b''
	while not finished:
		chunk, next_chunk = next_chunk, cipher.decrypt(file_read.read(1024 * bs))
		if len(next_chunk) == 0:
			padding_length = chunk[-1]
			chunk = chunk[:-padding_length]
			finished = True 
		out_stream += bytes(x for x in chunk)
	file_read.close()
	with open(file, 'wb') as file_write:
		file_write.write(out_stream)

def encrypt_file_tree(path, password, avoid_files=[]):
	if os.path.exists(path):
		if os.path.isfile(path):
			if path not in avoid_files:
				encrypt_file(path, password)
		elif os.path.isdir(path):
			print(f"Encrypting {path}")
			files = os.listdir(path)
			for file in files:
				encrypt_file_tree(f"{path}/{file}", password, avoid_files)

def decrypt_file_tree(path, password, avoid_files=[]):
	if os.path.exists(path):
		if os.path.isfile(path):
			if path not in avoid_files:
				print(f"Decrypting {path}")
				decrypt_file(path, password)
		elif os.path.isdir(path):
			files = os.listdir(path)
			for file in files:
				decrypt_file_tree(f"{path}/{file}", password, avoid_files)

# password = "asdf"
# encrypt("audio.wav", password)
# decrypt("audio.wav", password)
# encrypt_file_tree("test", password, ["audio.wav"])
# decrypt_file_tree("test", password)
# print(os.listdir("."))
# print(sys.argv[0])
# with open('audio.wav', 'rb') as in_file, open('out_audio.wav', 'wb') as out_file:
#     encrypt(in_file, out_file, password)

# with open('out_audio.wav', 'rb') as in_file, open('audio_decrypted.wav', 'wb') as out_file:
#     decrypt(in_file, out_file, password)



# on encryption:
	# make new file
	# file contains hash of password 
	# make file not readable or writable

def get_salt(size=16, chars=None):
	if not chars:
		chars = ''.join(
			[string.ascii_uppercase, 
			 string.ascii_lowercase, 
			 string.digits]
		)
	return ''.join(random.choice(chars) for x in range(size))

def encrypt_drive():
	print("==>   Encrypting Drive   <==")
	print("    Press Ctrl+C to exit ")
	print("============================")
	password, check_password = None, ""
	while True:
		try:
			password = getpass.getpass("Password: ")
			check_password = getpass.getpass("Confirm Password: ")
		except KeyboardInterrupt:
			exit(0)
		if password != check_password:
			print("Passwords do not match")
		else:
			break
	salt = get_salt()
	str2hash = password + salt
	hashed_password = md5(str2hash.encode()).hexdigest()
	del check_password
	with open(PASSWORD_FILE, 'w') as file:
		file.write(hashed_password + " " + salt)
	this_file = sys.argv[0]
	if "./" not in this_file:
		this_file = "./"+this_file
	encrypt_file_tree(".", password, avoid_files=[this_file, "./"+PASSWORD_FILE])
	os.chmod(PASSWORD_FILE, 0o444)
	del password


# on decryption:
	# check for hash file
	# make file writable
	# make file readable

def decrypt_drive():
	print("==>   Decrypting Drive   <==")
	print("    Press Ctrl+C to exit    ")
	print("============================")
	while True:
		try:
			password = getpass.getpass("Password: ")
		except KeyboardInterrupt:
			exit(0)
		hashed = ""
		os.chmod(PASSWORD_FILE, 0o644)
		with open(PASSWORD_FILE, 'r') as file:
			hashed = file.read()
		hashed = hashed.split(" ")
		hashed_password, salt = hashed[0], hashed[1] 
		str2hash = password + salt
		computed_hash = md5(str2hash.encode()).hexdigest()
		if computed_hash == hashed_password:
			this_file = sys.argv[0]
			if "./" not in this_file:
				this_file = "./"+this_file
			decrypt_file_tree(".", password, avoid_files=[this_file, "./"+PASSWORD_FILE])
			os.remove(PASSWORD_FILE)
			break
		else: 
			print("Incorrect password.")


if os.path.exists(PASSWORD_FILE):
	decrypt_drive()
else:
	encrypt_drive()

