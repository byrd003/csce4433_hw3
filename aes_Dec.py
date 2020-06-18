from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# get key
key_data = open("key_aes.txt", "rb")
key = key_data.readline()

# get ciphertext
ct_data = open("ctext.txt", "rb")
ct_read = ct_data.readline()

# get iv
iv_data = open("iv_aes.txt", 'rb')
iv = iv_data.read(16)

# create new AES object and decrypt
cipher = AES.new(key, AES.MODE_CBC, iv=iv)
original_data = cipher.decrypt(ct_read) 

# outputs
print("Ciphertext: ")
print(ct_read)
print("Original message: ")
print(original_data)