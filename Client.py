import socket
from TextEncryption import TextEncryption
import hashlib
from RSA import *
s = socket.socket()
port = 4084
s.connect(('localhost', port))

# reciecing public key parameters from server
data=(s.recv(1024).decode())
strData = data.split(",")
server_public = int(strData[0]) #e
server_n = int(strData[1]) #n

# input secret key and plain text in the form of 010011 (without 0b)
message = int(input("Message text (binary value): "), 2)
key= int(input("Input secret key(binary value): "), 2)

# input public and private key of client
client_public,client_length=map(int, input("Public Key parameters: ").split())
client_private,client_length=map(int, input("Private key parameters: ").split())


print("\nClient output by:- Vedant golhani \n2018275\n")

'''
here we encrypt secret key with RSA algorithm
'''
encrypted_key= rsa_encrypt(server_public,server_n,str(key))
print("Encrypted Secret Key: ",encrypted_key)


''' 
AES Variant:- 
giving message and secret key to aes encrypt
'''
ciphertext = TextEncryption(key).encrypt(message)
textCode = str(ciphertext) + ',' + str(key)
print("Cipher text:",ciphertext)


'''
implement hash algorithm on message to create digest
'''
mess=str(message)
mDigest = hashlib.md5((mess).encode())
message_digest=mDigest.hexdigest()
print("Digest: ",message_digest)

''' 
Giving digest to RSA algo to create signature
'''
int_mes_dig=int(message_digest, 16)

signature=rsa_encrypt(client_private,client_length,str(int_mes_dig))
print("Digital Signature: ",signature)


# sending data to server
textCode = str(ciphertext) + ',' + str(encrypted_key)+ ',' + str(signature)+ ',' + str(client_public)+ ',' + str(client_length)
# print("text code= " ,textCode)
s.send(bytes(textCode, 'utf-8'))
print(s.recv(1024).decode())
s.close()