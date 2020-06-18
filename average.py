import timeit
import numpy as np
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def aes_128():
	data = input("User-input message for AES 128-bit encryption/decryption: ")
	data_byte = bytes(data, 'utf-8')
	key = get_random_bytes(16)
	# iv = get_random_bytes()

	e_cipher = AES.new(key, AES.MODE_CBC)
	enc_rep = (timeit.timeit('e_data = e_cipher.encrypt(pad(data_byte, AES.block_size))',
		globals={'e_cipher':e_cipher,'pad':pad,'data_byte':data_byte,'AES':AES},number=100))

	e_data = e_cipher.encrypt(pad(data_byte,AES.block_size))
	d_cipher = AES.new(key, AES.MODE_CBC, e_cipher.iv)
	dec_rep = (timeit.timeit('d_data = d_cipher.decrypt(e_data)',
		globals={'d_cipher':d_cipher,'e_data':e_data},number =100))

	avg_enc = np.mean(enc_rep)
	avg_dec = np.mean(dec_rep)

	print("Average encryption time for AES 128-bit: ")
	print(avg_enc)
	print("Average decryption time for AES 128-bit: ")
	print(avg_dec)

def aes_192():
	data = input("User-input message for AES 192-bit encryption/decryption: ")
	data_byte = bytes(data, 'utf-8')
	key = get_random_bytes(24)
	# iv = get_random_bytes()

	e_cipher = AES.new(key, AES.MODE_CBC)
	enc_rep = (timeit.timeit('e_data = e_cipher.encrypt(pad(data_byte, AES.block_size))',
		globals={'e_cipher':e_cipher,'pad':pad,'data_byte':data_byte,'AES':AES},number=100))

	e_data = e_cipher.encrypt(pad(data_byte,AES.block_size))
	d_cipher = AES.new(key, AES.MODE_CBC, e_cipher.iv)
	dec_rep = (timeit.timeit('d_data = d_cipher.decrypt(e_data)',
		globals={'d_cipher':d_cipher,'e_data':e_data},number =100))

	avg_enc = np.mean(enc_rep)
	avg_dec = np.mean(dec_rep)

	print("Average encryption time for AES 192-bit: ")
	print(avg_enc)
	print("Average decryption time for AES 192-bit: ")
	print(avg_dec)

def aes_256():
	data = input("User-input message for AES 256-bit encryption/decryption: ")
	data_byte = bytes(data, 'utf-8')
	key = get_random_bytes(32)
	# iv = get_random_bytes()

	e_cipher = AES.new(key, AES.MODE_CBC)
	enc_rep = (timeit.timeit('e_data = e_cipher.encrypt(pad(data_byte, AES.block_size))',
		globals={'e_cipher':e_cipher,'pad':pad,'data_byte':data_byte,'AES':AES},number=100))
	e_data = e_cipher.encrypt(pad(data_byte,AES.block_size))

	d_cipher = AES.new(key, AES.MODE_CBC, e_cipher.iv)
	dec_rep = (timeit.timeit('d_data = d_cipher.decrypt(e_data)',
		globals={'d_cipher':d_cipher,'e_data':e_data},number =100))

	avg_enc = np.mean(enc_rep)
	avg_dec = np.mean(dec_rep)

	print("Average encryption time for AES 256-bit: ")
	print(avg_enc)
	print("Average decryption time for AES 256-bit: ")
	print(avg_dec)

def rsa_1024():
	keyPair = RSA.generate(1024)

	pubKey = keyPair.publickey()
	pubKeyPEM = pubKey.exportKey()

	privKeyPEM = keyPair.exportKey()

	data = input("User-input message for RSA 1024-bit encryption/decryption: ")
	data_byte = bytes(data, 'utf-8')

	encryptor = PKCS1_OAEP.new(pubKey)
	enc_rep = timeit.timeit('encrypted = encryptor.encrypt(data_byte)',
		globals={'encryptor':encryptor,'data_byte':data_byte},number = 100)

	encrypted = encryptor.encrypt(data_byte)
	decryptor = PKCS1_OAEP.new(keyPair)
	dec_rep = timeit.timeit('decrypted = decryptor.decrypt(encrypted)', 
		globals={'decryptor':decryptor,'encrypted':encrypted},number = 100)

	avg_enc = np.mean(enc_rep)
	avg_dec = np.mean(dec_rep)

	print("Average encryption time for RSA 1024-bit: ")
	print(avg_enc)
	print("Average decryption time for RSA 1024-bit: ")
	print(avg_dec)

def rsa_2048():
	keyPair = RSA.generate(2048)

	pubKey = keyPair.publickey()
	pubKeyPEM = pubKey.exportKey()

	privKeyPEM = keyPair.exportKey()

	data = input("User-input message for RSA 2048-bit encryption/decryption: ")
	data_byte = bytes(data, 'utf-8')

	encryptor = PKCS1_OAEP.new(pubKey)
	enc_rep = timeit.timeit('encrypted = encryptor.encrypt(data_byte)',
		globals={'encryptor':encryptor,'data_byte':data_byte},number = 100)

	encrypted = encryptor.encrypt(data_byte)
	decryptor = PKCS1_OAEP.new(keyPair)
	dec_rep = timeit.timeit('decrypted = decryptor.decrypt(encrypted)', 
		globals={'decryptor':decryptor,'encrypted':encrypted},number = 100)

	avg_enc = np.mean(enc_rep)
	avg_dec = np.mean(dec_rep)

	print("Average encryption time for RSA 2048-bit: ")
	print(avg_enc)
	print("Average decryption time for RSA 2048-bit: ")
	print(avg_dec)

def rsa_4096():
	keyPair = RSA.generate(4096)

	pubKey = keyPair.publickey()
	pubKeyPEM = pubKey.exportKey()

	privKeyPEM = keyPair.exportKey()

	data = input("User-input message for RSA 4096-bit encryption/decryption: ")
	data_byte = bytes(data, 'utf-8')

	encryptor = PKCS1_OAEP.new(pubKey)
	enc_rep = timeit.timeit('encrypted = encryptor.encrypt(data_byte)',
		globals={'encryptor':encryptor,'data_byte':data_byte},number = 100)

	encrypted = encryptor.encrypt(data_byte)
	decryptor = PKCS1_OAEP.new(keyPair)
	dec_rep = timeit.timeit('decrypted = decryptor.decrypt(encrypted)', 
		globals={'decryptor':decryptor,'encrypted':encrypted},number = 100)

	avg_enc = np.mean(enc_rep)
	avg_dec = np.mean(dec_rep)

	print("Average encryption time for RSA 4096-bit: ")
	print(avg_enc)
	print("Average decryption time for RSA 4096-bit: ")
	print(avg_dec)


aes_128()
aes_192()
aes_256()

rsa_1024()
rsa_2048()
rsa_4096()