import requests
import nacl
import pyreadr
import json
import nacl.utils
import nacl.secret
import nacl.hash
from nacl.public import PrivateKey
import urllib.parse
import re
import sys
from io import StringIO
import pandas as pd


# for testing purposes
CLIENT_DISABLE_SECURITY = False


# R equivalent of stop
def stop(msg):
    print(msg)
    assert False

# URL encode and decode
def ENC(str):
    return urllib.parse.quote(str)

def DEC(str):
    return urllib.parse.unquote(str)


# hex-string to raw
def hexstring_to_bytes(hexstring, url_decode = False):
    if url_decode:
        hexstring = DEC(hexstring)

    # remove all non-hex chars (note that the caret `^` here designates negation)
    hexstring = re.sub('[^0-9a-fA-F]', '', hexstring)

    # hexstring must be even length
    assert(len(hexstring) % 2 == 0)

    byt = bytes.fromhex(hexstring)
    return byt

# raw to hex-string
def bytes_to_hexstring(bytes, url_encode = False):
    hex = bytes.hex()
    if url_encode:
        hex = ENC(hex)
    return hex

# verify
byt = b"Hello%20World!"
assert(hexstring_to_bytes(bytes_to_hexstring(byt)) == byt)
assert(hexstring_to_bytes(bytes_to_hexstring(byt, url_encode = True), url_decode = True) == byt)



# Useful functions
def data_encrypt(raw, passkey):
    box = nacl.secret.SecretBox(passkey)
    encrypted = box.encrypt(raw)
    return encrypted

def data_decrypt(encrypted, passkey):
    box = nacl.secret.SecretBox(passkey)
    raw = box.decrypt(encrypted)
    return (raw)

# Usage
raw = b"Hello"
encrypted = data_encrypt(raw, passkey = b'a5ac92b25c9fbef8c6504f120bcbb2b1')
assert (data_decrypt(encrypted, passkey = b'a5ac92b25c9fbef8c6504f120bcbb2b1') == raw)




CLIENT_ID = "client_py_001" # for authorization

# key management
CLIENT_PUB_KEY = None
CLIENT_PVT_KEY = None
SERVER_PUB_KEY = None
CLIENT_PVT_KEY_PASSKEY = None

# private key storage. Use any passphrase to encrypt client's private key.
client_pvt_key_passphrase = "user_client"
CLIENT_PVT_KEY_PASSKEY = nacl.hash.sha256(bytes(client_pvt_key_passphrase, "utf-8"))[0:32]

# Generate client keypair:
CLIENT_PVT_KEY = PrivateKey.generate()
CLIENT_PUB_KEY = CLIENT_PVT_KEY.public_key.__bytes__()
CLIENT_PVT_KEY = data_encrypt(CLIENT_PVT_KEY.__bytes__(), CLIENT_PVT_KEY_PASSKEY)
# original CLIENT_PVT_KEY can be fetched using nacl.public.PrivateKey(data_decrypt(CLIENT_PVT_KEY, CLIENT_PVT_KEY_PASSKEY))


# Public Key Functions
def pki_encrypt(txt, pvt_key, pub_key, passkey):
    pvt_key_decrypt = nacl.public.PrivateKey(data_decrypt(pvt_key, passkey))
    box = nacl.public.Box(pvt_key_decrypt, nacl.public.PublicKey(pub_key))
    raw = bytes(txt, "utf-8")
    encrypted = box.encrypt(raw)
    return encrypted

def pki_decrypt(encrypted, pvt_key, pub_key, passkey):
    pvt_key_decrypt = nacl.public.PrivateKey(data_decrypt(pvt_key, passkey))
    box = nacl.public.Box(pvt_key_decrypt, nacl.public.PublicKey(pub_key))
    raw = box.decrypt(encrypted)
    txt = raw.decode()
    return txt


# client-only function
def encrypt(txt, disable_security = CLIENT_DISABLE_SECURITY):
    if disable_security:
        return txt
    encrypted = pki_encrypt(txt, CLIENT_PVT_KEY, SERVER_PUB_KEY, CLIENT_PVT_KEY_PASSKEY)
    encrypted = bytes_to_hexstring(encrypted)
    return encrypted

def decrypt(encrypted, disable_security = CLIENT_DISABLE_SECURITY):
    if disable_security:
        return encrypted
    encrypted = hexstring_to_bytes(encrypted)
    txt = pki_decrypt(encrypted, CLIENT_PVT_KEY, SERVER_PUB_KEY, CLIENT_PVT_KEY_PASSKEY)
    return txt


def EXEC_API(api, type, argName = None, argVal = None, display = True, display_res = False):
    if type not in ['GET', 'POST']:
        stop("Only GET and POST are supported!")

    query = "http://127.0.0.1:8000/" + api

    # convert strings into single valued lists
    if isinstance(argName, str):
        argName = [argName]
    if isinstance(argVal, str):
        argVal = [argVal]

    # add client id in all requests
    if argName is None:
        argName = ["id"]
        argVal = [CLIENT_ID]
    else:
        argName.append("id")
        argVal.append(CLIENT_ID)

    params = []
    if (argName is not None) and (argVal is not None) and (len(argName) == len(argVal)):
        query = query + "?"
        argValEnc = [None for i in range(0, len(argVal))]
        for i in range(0, len(argName)):
            # encrypt argVal
            argValEnc[i] = encrypt(argVal[i])
            params.append(ENC(argName[i]) + "=" + ENC(argValEnc[i]))

    # out all args together
    params = "&".join(params)
    query = query + params

    if display:
        print("Executing:", type, "on URL:", query, "\n")

    res = None
    if type == "GET":
        try:
            res = requests.get(query)
        except requests.exceptions.ConnectionError:
            if display:
                print("Connection Failed")

    if type == "POST":
        try:
            res = requests.post(query)
        except requests.exceptions.ConnectionError:
            if display:
                print("Connection Failed")

    if res is None:
        print("Request Failed!")
        return None

    res_val = res.content.decode()
    if display_res:
        print("plain-text:", res_val, sep = "\n")

    dec_val = decrypt(res_val)
    if display_res:
        print("decrypted:", dec_val, sep = "\n")

    return dec_val










# get server's public key
SERVER_PUB_KEY = requests.get("http://127.0.0.1:8000/get-server-pub-key").content
SERVER_PUB_KEY = hexstring_to_bytes(SERVER_PUB_KEY.decode())





# Un-authorized request
requests.get("http://127.0.0.1:8000/app-name").content.decode()
requests.post("http://127.0.0.1:8000/set-param?paramName=CSV_FILE&paramVal=C%3A%2FUsers%2Fnikhi%2FDocuments%2Ftmp.csv").content.decode()
# EXEC_API("app-name", "GET", display_res = True)

# set client's public key on server
query = "http://127.0.0.1:8000/" + "set-client-pub-key" + "?" + "key=" + \
        bytes_to_hexstring(CLIENT_PUB_KEY, url_encode = True) + "&" + "id=" + \
        ENC(encrypt(CLIENT_ID))
res = requests.post(query)
print(res.content.decode())






# requests without client id
res = requests.get("http://127.0.0.1:8000/app-name").content.decode()
print(res)

# requests with incorrect client id
res = requests.get("http://127.0.0.1:8000/app-name?id=abcd").content.decode()
print(res)

# requests with correct client id but no encryption
res = requests.get("http://127.0.0.1:8000/app-name?id=" + ENC(CLIENT_ID)).content.decode()
print(res)

# requests with incorrect client id but encryption done
res = requests.get("http://127.0.0.1:8000/app-name?id=" + ENC(encrypt("abcd"))).content.decode()
print(res)

# correct client-id and encryption but no decryption of o/p!
res = requests.get("http://127.0.0.1:8000/app-name?id=" + ENC(encrypt(CLIENT_ID))).content.decode()
print(res)

# properly decrypted requests!
res = requests.get("http://127.0.0.1:8000/app-name?id=" + ENC(encrypt(CLIENT_ID))).content.decode()
print(decrypt(res))










EXEC_API("app-name", "GET")
ret = EXEC_API("get-param", "GET", "paramName", "CSV_FILE")
print(ret)




EXEC_API("set-param", "POST",
         ["paramName", "paramVal"],
         ["CSV_FILE", "C:/Users/nikhi/Documents/tmp.csv"])
ret = EXEC_API("get-param", "GET", "paramName", "CSV_FILE")
print(ret)


