
'''
Created 12 Dec 2021
@author: Paola Gomez Reyna - pgomezr0

Computer Security Assignment 2:
Real Time Chat using Diffie Helmman
Key Exchange and AES encryption algorithm
'''

import os, binascii, hashlib

# Global public elements

# Recommended DH group should be at least 2048 bits (14) according to https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf 
prime_group_14 = {
    'prime number':  0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
    'primitive root': 2
}


class DiffieHellman:

    def __init__(self, key_size):
        self.q = prime_group_14['prime number']
        self.alpha = prime_group_14['primitive root']
        self.bytes_size = key_size

        # Create a random Private key which must be less than prime number
        self.init_private_key = int(binascii.hexlify(os.urandom(self.bytes_size)), base=16)
    
    def create_public_key(self):
        # (alpha ^ private_key) mod q
        public_key = pow(self.alpha, self.init_private_key, self.q)
        return public_key

    def check_public_key(self, other_key):
        # Validate the other party's public key
        if (other_key > 2) and (other_key < self.q - 1):
            if pow(other_key, (self.q - 1) // 2, self.q) == 1:
                return True
        return False

    def create_secretshared_key(self, other_key):

        if self.check_public_key(other_key):
            secretshared_key = pow(other_key, self.init_private_key, self.q)

            secretshared_key = hashlib.sha256(str(secretshared_key).encode()).hexdigest()

            return secretshared_key
        
        raise Exception('Invalid Public Key.')
