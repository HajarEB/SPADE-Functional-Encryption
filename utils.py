import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
import numpy as np


#AES encryption
def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, tag, nonce

# AES decryption
def aes_decrypt(key, ciphertext, tag, nonce):
    cipher = AES.new(key, AES.MODE_EAX, nonce = nonce)
    plaintext = cipher.decrypt(ciphertext)
    
    try:
        cipher.verify(tag)
        return plaintext
    
    except ValueError:
        return None
        
# generate a timestamp
def generate_timestamp():
    t = (int(time.time())) 
    return t
    
# check timestamp validity
def is_ts_valid(ts):
    try:
        ts = int(ts)
    except ValueError:
        return False

    now = int(time.time())

    if ts > now or now - ts > 120: # timestamp is in future or older than 120s (2 minutes)
        return False  # invalid timestamp
    return True


# PKE scheme key generation
def PKE_gen():
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 3072, 
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# PKE scheme encryption
def PKE_enc(public_key, message):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext
   
# PKE scheme decryption     
def PKE_dec(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


# signing algorithm
def euf_cma_sign(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# signature verification algorithm
def euf_cma_verify(public_key, signature, message): 
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return True
    
    except InvalidSignature:
        return False


# used by all parties to verify validity of a received message
def verify(m, pk):

    if m == None:
        return False

    t, value, signature = m

    message = np.append(t, value)

    if euf_cma_verify(pk, signature, message) and is_ts_valid(t):
        return True

    return False

# to build / generate a message
def generate_message(sk, value):
    t = generate_timestamp()

    message = np.append(t, value)

    signature = euf_cma_sign(sk, message)

    return t, value, signature