#"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""


#libraries that i need
import base64
import hashlib
import time

# > Current time in milliseconds 
#-----------------------------------------------------------------------
def now_ms(): #raise NotImplementedError
    return int(time.time() * 1000) # return current time in milliseconds


# > Base64 encoding bytes to UTF-8 string ( URL-safe, no padding )
#-----------------------------------------------------------------------
def b64e(b: bytes): #raise NotImplementedError
    return base64.b64encode(b).decode("utf-8")


# > Base64 decoding UTF-8 string to bytes ( URL-safe, no padding )
#-----------------------------------------------------------------------
def b64d(s: str): #raise NotImplementedError
    return base64.b64decode(s.encode("utf-8"))


# > SHA-256 hash of data as hex string - helper for signatures
#-----------------------------------------------------------------------
def sha256_hex(data: bytes): #raise NotImplementedError
    return hashlib.sha256() # create sha256 hash object


#-----------------------------------------------------------------------
#-----------------------------------------------------------------------
# > test code for utils.py
if __name__ == "__main__":
    msg = b"hello world"
    print("Timestamp (ms):", now_ms())
    print("b64e:", b64e(msg))
    print("b64d:", b64d(b64e(msg)))
    print("sha256:", sha256_hex(msg))
#-----------------------------------------------------------------------
# to run on command line:
# python app/common/utils.py