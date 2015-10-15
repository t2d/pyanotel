from Crypto.Cipher import AES
from Crypto.Util import Counter
import multiprocessing
from datetime import datetime
import sys


def worker(i, gpp):
    text = b'0123456789012345'
    secret = b'0123456789012345'
    counter = Counter.new(128)
    cipher = AES.new(secret, AES.MODE_CTR, counter=counter)

    #print "start %d" % i
    start = datetime.now()
    me = gpp

    while me != 0:
        ciphertext = cipher.encrypt(text)
        me -= 1

    diff = datetime.now() - start
    print "p%s: %s" % (i, diff)


if __name__ == '__main__':
    goal = int(sys.argv[1])
    processes = int(sys.argv[2])
    gpp = goal / processes
    print "Iterations per Process: %d" % gpp

    for i in range(processes):
        p = multiprocessing.Process(target=worker, args=(i, gpp))
        p.start()

