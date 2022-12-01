'''
Created 12 Dec 2021
@author: Paola Gomez Reyna - pgomezr0

Computer Security Assignment 2:
Real Time Chat using Diffie Helmman
Key Exchange and AES encryption algorithm
'''

from base64 import b64encode, b64decode
import hashlib
from Cryptodome import Random
from Cryptodome.Cipher import AES

class AEStandard():

    def __init__(self, key, key_size):
        self.key = hashlib.sha256(key.encode()).digest()
        self.bytes_size = self.set_key_size(key_size)
        # Block_size is fixed to 128 bits 

    def set_key_size(self, key_size):
        if key_size == 24: # 192 bits
            self.key = self.key[:24]
            return self.key
        
        elif key_size == 16: # 128 bits
            self.key = self.key[:16]
            return self.key
        
        else: # maintain self.key as 32 bytes or 256 bits
            return self.key


    # Used for ECB and CBC
    def padding(self, s):
        return s + (AES.block_size - len(s) % AES.block_size)*chr(AES.block_size - len(s) % AES.block_size)

    def unpadding(self, s):
        return s[:-ord(s[len(s)-1:])]

    '''
    CBC (Cipher Block Chaining) encryption and decryption functions 
    
    '''
 
    def encrypt_CBC(self, message):

        message = self.padding(message)
        iv = Random.new().read(AES.block_size) # Init random vector
        cipher = AES.new(self.key, AES.MODE_CBC, iv) # Customizable mode of operation

        encrypted_msg = b64encode(iv + cipher.encrypt(message.encode()))

        return encrypted_msg


    def decrypt_CBC(self, ciphertext):
        
        ciphertext = b64decode(ciphertext)
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        decrypted_msg = self.unpadding(cipher.decrypt(ciphertext[AES.block_size:])).decode('utf-8')

        return decrypted_msg


    '''
    ECB (Electronic Codebook) encryption and decryption functions
    
    '''
    def encrypt_ECB(self, message):

        message = self.padding(message)
        cipher = AES.new(self.key, AES.MODE_ECB) # Customizable mode of operation

        encrypted_msg = b64decode(cipher.encrypt(message.encode('utf-8')))

        return encrypted_msg


    def decrypt_ECB(self, ciphertext):
        
        ciphertext = b64decode(ciphertext)
        cipher = AES.new(self.key, AES.MODE_ECB)

        decrypted_msg = self.unpadding(cipher.decrypt(ciphertext)).decode('utf-8')

        return decrypted_msg

    '''
    CFB (Cipher Feedback) encryption and decryption functions
    
    '''
    def encrypt_CFB(self, message):

        iv = Random.new().read(AES.block_size) # Init random vector
        cipher = AES.new(self.key, AES.MODE_CFB, iv) # Customizable mode of operation

        encrypted_msg = b64encode(iv + cipher.encrypt(message).decode('utf-8'))

        return encrypted_msg


    def decrypt_CFB(self, ciphertext):

        ciphertext = b64decode(ciphertext)
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CFB, iv)

        decrypted_msg = cipher.decrypt(ciphertext[AES.block_size:].decode('utf-8'))

        return decrypted_msg