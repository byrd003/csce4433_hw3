from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# get message from user
data = input("User-input message: ")

# handling for 18 bytes only
# while len(data) ==18:
# 	try:
# 	    print("Your message is: ", data)
# 	except ValueError:
# 	    print("This is not an 18-byte message")
# 	    exit()

data_byte = bytes(data, 'utf-8')

# generate 24 byte/192 bit key
key = get_random_bytes(24)

# write key to text file
ex= open("key_aes.txt","wb")
ex.write(key)

# creating cipher obj and then encrypting
cipher1 = AES.new(key, AES.MODE_CBC)
ct_bytes = cipher1.encrypt(pad(data_byte, AES.block_size))

# writing ciphertext to text file
ex= open("ctext.txt","wb")
ex.write(ct_bytes)

# write IV to text file
file_out = open("iv_aes.txt", "wb")
file_out.write(cipher1.iv)

# output
print("Message: ")
print(data)
print("Ciphertext: ")
print(ct_bytes)