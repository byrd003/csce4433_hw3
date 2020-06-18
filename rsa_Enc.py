from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


# In order to use this correctly, you need to first run KeyGen with "python rsa_KeyGen.py"
# From there, keys will be generated and can be used
# You may need to clear ctext.txt then run rsa_Enc.py then rsa_Dec.py to decrypt

# user input
data = input("User-input message: ")
data_byte = bytes(data, 'utf-8')

# write file with data
f_out = open("ctext.txt","wb")

# read key 
receiver_key = RSA.import_key(open("publicKey.txt").read())
# make new session key
current_key = get_random_bytes(24)

# Encrypt session key with public RSA key
rsaCipher = PKCS1_OAEP.new(receiver_key)
enc_current_key = rsaCipher.encrypt(current_key)

# Encrypt data with session key
aesCipher = AES.new(current_key, AES.MODE_EAX)
ctext, tag = aesCipher.encrypt_and_digest(data_byte)
[f_out.write(x) for x in (enc_current_key, aesCipher.nonce, tag, ctext)]

#output 
print("Current key: ")
print(current_key)
print("Public key: ")
print(receiver_key)