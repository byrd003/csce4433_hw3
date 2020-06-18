from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

# open ecnrypted data
f_in = open("ctext.txt", "rb")

# read key from private
private_key = RSA.import_key(open("privateKey.txt").read())

# read private key values from private_key.pem, s
enc_current_key, nonce, tag, ctext = \
   [f_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

# Decrypt  session key with the private key
rsaCipher = PKCS1_OAEP.new(private_key)
current_key = rsaCipher.decrypt(enc_current_key)

# Decrypt the data with session key
aesCipher = AES.new(current_key, AES.MODE_EAX, nonce)
data = aesCipher.decrypt_and_verify(ctext, tag)

#output
print("Current Key: ")
print(current_key)
print("Private key: ")
print(private_key)
print("Decrypted message: ")
print(data.decode("utf-8"))