import constants
from helpers import serialize, deserialize
from socket import *


def bytes_from_file(filename, chunksize=8192):
    with open(filename, "rb") as f:
        while True:
            chunk = f.read(chunksize)
            if chunk:
                for b in chunk:
                    yield b
            else:
                break

s = socket(AF_INET, SOCK_STREAM)
#s.bind(('192.168.50.4', 0))
pseudonym_provider = (constants.P.ip, constants.P.port)
s.connect(pseudonym_provider)

data = [constants.Header.INITCALL, constants.user1_id, 1111111111111111]  # callee , caller
s.send(serialize(data) + "\r\n")
print "sending %s" % serialize(data)

answer = s.recv(1024)
packet = deserialize(answer)
print packet

if packet[0] == constants.Header.ANSWERCALL:
    cid = packet[1]
    # connect to network operator with CID and send raw data
    network = socket(AF_INET, SOCK_STREAM)
    network.connect((constants.N.ip, constants.N.port))
    announcement = [constants.Header.INITCALL, cid]
    network.send(serialize(announcement) + "\r\n")

    answer = network.recv(1024)
    packet = deserialize(answer)
    if packet[0] == constants.Header.RAWNOW:
        print "Sending"
        for b in bytes_from_file('hints.txt'):
            network.send(b)
    else:
        print packet
