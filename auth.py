"""
Helper functions to Handle password hash generation and verification.
"""
from passlib.hash import pbkdf2_sha256
import string
import random

def generate_hash(passwd):
    return pbkdf2_sha256.encrypt(passwd, rounds=200000, salt_size=16)

def verify_hash(passwd, hash):
    return pbkdf2_sha256.verify(passwd, hash)

#def generate_otp_secret(size=24, chars=string.ascii_uppercase+string.digits):
#    ##turns out the otp secret needs to be base32 encoded
#    return ''.join(random.choice(chars) for _ in range(size))
