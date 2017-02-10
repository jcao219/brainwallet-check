#!/usr/bin/python3

# Brainwallet Check
# Takes in string as an argument, generates private key and address, then checks blockchain.info to see if it is in use
# Most code taken from https://bitcointalk.org/index.php?topic=84238.0 - thank you JeromeS! 
# You need libpcre3-dev for the GET request to work to blockchain.info (apt get libpcre3-dev)
# - Josh Gilmour

import os
import sys, getopt
import ecdsa
import binascii, hashlib
import itertools
import base58

secp256k1curve=ecdsa.ellipticcurve.CurveFp(115792089237316195423570985008687907853269984665640564039457584007908834671663,0,7)
secp256k1point=ecdsa.ellipticcurve.Point(secp256k1curve,0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
secp256k1=ecdsa.curves.Curve('secp256k1',secp256k1curve,secp256k1point,(1,3,132,0,10))

GOAL = "17iUnGoZbFrGS7uU9z2d2yRT9BKgVqnKnn"

def addy(pk):
    pko = ecdsa.SigningKey.from_secret_exponent(pk,secp256k1)
    pubkey = binascii.hexlify(pko.get_verifying_key().to_string())
    pubkey2 = hashlib.sha256(binascii.unhexlify(b'04'+pubkey)).hexdigest()
    pubkey3 = hashlib.new('ripemd160',binascii.unhexlify(pubkey2)).hexdigest().encode('utf8')
    pubkey4 = hashlib.sha256(binascii.unhexlify(b'00'+pubkey3)).hexdigest()
    pubkey5 = hashlib.sha256(binascii.unhexlify(pubkey4)).hexdigest().encode('utf8')
    pubkey6 = pubkey3+pubkey5[:8]
    pubnum = int(pubkey6,16)
    pubnumlist = []
    while pubnum != 0: 
        pubnumlist.append(pubnum % 58)
        pubnum //= 58
    address = ''
    ALPH = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    for x in pubnumlist:
        address=ALPH[x]+address
    return '1'+address

POSSIBLE_LETTERS = set("ucoitsgr")

if len(sys.argv) != 2:
    for poss in itertools.permutations(POSSIBLE_LETTERS):
        passphrase = "8ln" + "".join(poss) + "nl8"
        privatekey = int(hashlib.sha256(passphrase.encode('utf8')).hexdigest(),16)
        #privatekeysha = (hashlib.sha256(sys.argv[1].encode('utf8'))).hexdigest()
        bcaddy = addy(privatekey)
        if bcaddy == GOAL:
            print("Success.")
            print("Passphrase: ", passphrase)
            print("Private Key: ", privatekey)
            break
        else:
            print(passphrase,":",bcaddy)
else:
    passphrase = sys.argv[1]
    privatekey = hashlib.sha256(passphrase.encode('utf8')).digest()
    privatekeyx = bytes([0x80]) + privatekey
    privatekeyxchk = hashlib.sha256(privatekeyx).digest()
    privatekeyxchk = hashlib.sha256(privatekeyxchk).digest()
    privatekeyxchk = privatekeyxchk[:4]
    privatekeyx += privatekeyxchk
    privatekeyimportable = base58.b58encode(privatekeyx)
    print("Passphrase: ", passphrase)
    print("Import Private Key:", privatekeyimportable)
