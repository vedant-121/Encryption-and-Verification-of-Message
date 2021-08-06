import socket
from TextDecryption import TextDecryption
import hashlib

from RSA import *

def decimalToBinary(n):
    return bin(n)



s = socket.socket()
print("Socket successfully created")
port = 4084
s.bind(('localhost', port))
s.listen(3)
print("socket is listening")


while True:
    c, addr = s.accept()

    # sending public key to client
    server_public_param,sn=map(int, input("Public Key parameters: ").split())
    serverprivate_param,sn=map(int, input("Private key parameters: ").split())


    public_k = str(server_public_param) + ',' + str(sn)
    c.send(bytes(public_k, 'utf-8'))    

    print("\nServer Output by:- Vedant golhani \n2018275\n")



    data = c.recv(1024).decode("utf-8")
    strData = data.split(",")
    
    '''
    getting data from client and storing in variable
    '''
    ciphertext = int(strData[0])
    enc_key = (strData[1])
    signature = (strData[2])
    client_public = int(strData[3])
    cn = int(strData[4])

    ''' 
    Decrypting key we took from client 
    using RSA Algorithm
    (server private key,encrypted secret key)

    dec_key :- is decrypted key after using RSA
    '''
    server_private = (serverprivate_param,sn)
    decrypt_key=rsa_decrypt(serverprivate_param,sn,enc_key)
    dec_key=int(decrypt_key)
    # print("dec key ",dec_key)

    '''
    using AES decrypting cipher text
    taking cipher text, secret key

    plain text:- message after decrypting
    ''' 

    plaintext = TextDecryption(dec_key).decrypt(ciphertext)
    # print("plain text= ",plaintext," binary ",bin(plaintext)[2:])


    '''
    implementing hash algorithm
    hashing message to get Digest
    '''
    mess=str(plaintext)
    mDigest = hashlib.md5((mess).encode())
    message_digest=mDigest.hexdigest()

    '''
    Using RSA Algorithm
    taking signature and decrypting with client public key
    -to verify signature
    '''
    decrypt_signature=hex(int(rsa_decrypt(client_public,cn,signature)))[2:]
    # print("Intermediate value = ",decrypt_signature)

   
    print("Decrypted Secret key: ",bin(dec_key)[2:])
    print("Decrypt Message: ",bin(plaintext)[2:])
    print("Message Digest: ",message_digest)
    print("Intermediate verification code:",decrypt_signature)
    '''
    verifying and printing
    '''
    if message_digest==decrypt_signature :
        print("Signature verified")
    else:
        print("Signature Not Verified")


    c.close()