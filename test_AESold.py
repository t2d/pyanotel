from Crypto.Cipher import AES
from Crypto.Util import Counter
import signal
import sys


def handler(signum, frame):
    print iterations
    sys.exit()

text = b'0123456789012345'
secret = b'0123456789012345'
counter = Counter.new(128)
iv = b'0123456789012345'
iterations = 0
cipher = AES.new(secret, AES.MODE_CTR, counter=counter, use_aesni=True)
signal.signal(signal.SIGALRM, handler)
signal.alarm(100)

while (True):
    ciphertext = cipher.encrypt(text)
    iterations += 1
