# -*- test-case-name: pyanotel.test.test_user -*-

import sys
import subprocess
import os
from twisted.protocols.basic import LineReceiver
from twisted.internet.protocol import DatagramProtocol, ClientCreator
from twisted.internet import reactor, stdio, defer, error
from Crypto.PublicKey import RSA
from random import randint
from base64 import b64decode, b64encode
from time import sleep

from helpers import pick_random, deserialize, serialize, decrypt, create_paging_names, asym_encrypt, make_msg, get_msg
import constants


class PagingListener(DatagramProtocol):
    ''' Listens for UDP paging packets and location announcements '''
    def __init__(self, user):
        self.user = user
        print "id: %s" % self.user.identifier
        self.used_cids = []

    def datagramReceived(self, datagram, (ip, port)):
        # print "received %r from %s:%d" % (datagram, ip, port)
        try:
            packet = deserialize(datagram)
        except SyntaxError:
            print "No ANOTEL packet"
        else:
            # handle packet
            if packet[0] == constants.Header.PAGING:
                self.handle_paging(packet[1:])
            elif packet[0] == constants.Header.LOCATIONANNOUNCEMENT:
                self.update_location(packet[1:])
            else:
                print "Unrecognized Header %d" % packet[0]

    def handle_paging(self, payload):
        ''' Handle paging packet '''
        # find amount of paging signals
        amount = len(payload)/2
        pseudos = payload[:amount]
        call = False
        used_name = None

        # check for pseudonym and paging names
        if self.user.pseudonym in pseudos:
            print "Found my pseudonym!"
            index = pseudos.index(self.user.pseudonym)
            # L did broadcast, send location update
            used_name = self.user.pseudonym
        elif self.user.paging_names is not None:
            for name in self.user.paging_names:
                if name in pseudos:
                    print "Found a paging name: %s" % name
                    index = pseudos.index(name)
                    used_name = name
                    break
            if used_name is None:
                # packet not for me
                return
            elif used_name == self.user.pseudonym:
                    # was broadcast -> full location update
                    self.user.update_providers()
            else:
                # update paging names
                self.user.paging_names = create_paging_names(self.user.seed, used_name, amount=100)
        else:
            # packet not for me
            return

        # try to decrypt the paging packet
        try:
            cid, caller = decrypt(payload[amount+index], self.user.secret)
        except ValueError:
            print "Was no well-formed ciphertext"
        else:
            # check if cid is msg
            if cid.startswith("M:"):  # suboptimal, will eat calls
                msg = get_msg(cid)
                print "MSG: %s from %s" % (msg, caller)
            # check if we have seen this packet before
            elif cid not in self.used_cids:
                # really incoming call
                self.used_cids.append(cid)
                # Ask if user wants to take call
                self.user.io.transport.write("Do you want to take the call of %s? (y/n)\n" % caller)
                self.user.incoming_call = (cid, caller)

    def update_location(self, payload):
        assert isinstance(payload, list)
        assert len(payload) == 1
        location = payload[0]
        if self.user.location != location:
            self.user.update_providers(location)


class BankClient(LineReceiver):
    def __init__(self):
        self.bank_key = RSA.importKey(constants.B.public_key)

    def lineReceived(self, line):
        data = deserialize(line)
        if data[0] == constants.Header.SIGN:
            print "Receiving blind signatures"
            answers = data[1:]
            for i in range(len(answers)):
                blindsig = long(answers[i])
                blinding_factor, msg = self.blinding_factors[i]
                sig = self.bank_key.unblind(blindsig, blinding_factor)
                if self.bank_key.verify(msg, (sig,)):
                    self.user.coins.append((msg, (sig,)))
                else:
                    print "Couldn't verify signature for %s" % msg
            print "You now have %d coins." % len(self.user.coins)


class UserClientProtocol(LineReceiver):
    ''' Connects to the network '''
    def __init__(self, user=None):
        self.n_deferred = None
        self.p_deferred = None
        self.file = None
        self.user = user

    def sendLine(self, line):
        # print "sending " + line
        LineReceiver.sendLine(self, line)

    def lineReceived(self, line):
        ''' will only receive lines, when connected to P or N for outgoing call '''
        data = deserialize(line)
        if data[0] == constants.Header.ANSWERCALL:
            cid = data[1]
            self.p_deferred.callback(cid)
        elif data[0] == constants.Header.RAWNOW:
            self.n_deferred.callback("_")
        elif data[0] == constants.Header.ERROR:
            self.n_deferred.errback("Couldn't verify coin.")

    def rawDataReceived(self, data):
        self.file.write(data)

    def connectionLost(self, reason):
        ''' show received image'''
        if self.file is not None:
            self.file.close()
            p = subprocess.Popen(["display", "output"])

    def location_update(self, pseudonym, location, seed):
        ''' Update location at Location Provider with asymmetric encryption (ECIES) '''
        plaintext = [pseudonym, location, seed]
        ciphertext = asym_encrypt(plaintext, constants.L.public_key)
        packet = [constants.Header.LOCATIONUPDATE, ciphertext]
        self.sendLine(serialize(packet))

    def pseudonym_update(self, pseudonym, identifier, secret):
        ''' Update pseudonym at Pseudonym Provider with asymmetric encryption (ECIES) '''
        plaintext = [pseudonym, identifier, secret]
        ciphertext = asym_encrypt(plaintext, constants.P.public_key)
        packet = [constants.Header.PSEUDONYMUPDATE, ciphertext]
        self.sendLine(serialize(packet))

    def answer_call(self, cid):
        # knowledge of cid proofs our identity
        # XXX: possible race condition. when someone is able to answer the cid faster than me, he can take the call
        packet = [constants.Header.ANSWERCALL, cid]
        self.sendLine(serialize(packet))
        self.setRawMode()
        self.file = open("output", "wb")

    def send_msg(self, callee, caller, msg):
        msg = make_msg(msg)
        plaintext = [callee, caller, msg]
        ciphertext = asym_encrypt(plaintext, constants.P.public_key)
        packet = [constants.Header.MSG, ciphertext]
        self.sendLine(serialize(packet))

    def make_call(self, callee, caller, pseudonym, filename):
        plaintext = [callee, caller, pseudonym, filename]
        ciphertext = asym_encrypt(plaintext, constants.P.public_key)
        packet = [constants.Header.INITCALL, ciphertext]
        self.sendLine(serialize(packet))
        self.p_deferred = defer.Deferred()
        self.p_deferred.addCallback(self.connect_to_n, filename)

    def connect_to_n(self, cid, filename):
        ''' connect with cid to N '''
        # XXX hier wieder racecondition mit cid
        d = ClientCreator(reactor, UserClientProtocol, self.user).connectTCP(constants.N.external_ip, constants.N.port)
        d.addCallback(self._start_transfer, cid, filename)
        # d.addErrback(self._error("network operator"))

    def _start_transfer(self, protocol, cid, filename):
        ''' starts new instance of protocol to N and disconnects from P'''
        protocol.start_transfer(cid, filename)
        self.transport.loseConnection()

    def start_transfer(self, cid, filename):
        ''' start filetransfer with coin '''
        if self.user.coins:
            coin = self.user.coins.pop()
            data = [constants.Header.INITCALL, cid, coin[0], coin[1][0]]
            line = serialize(data)
            self.sendLine(line)
            self.n_deferred = defer.Deferred()
            self.n_deferred.addCallback(self.send_raw_data, filename)
            self.n_deferred.addErrback(self.print_error)
        else:
            self.user.io.sendLine("You don't have coins!")

    def send_raw_data(self, _, filename):
        self.setRawMode()
        f = open(filename, 'rb')
        content = f.read()
        f.close()
        self.sendLine(content)
        self.transport.loseConnection()

    def print_error(self, error):
        print "Error: " + str(error)


class IO(LineReceiver):
    from os import linesep as delimiter

    def __init__(self, user):
        self.user = user
        self.user.io = self

    def connectionMade(self):
        self.transport.write('>>> ')

    def lineReceived(self, line):
        help = "help, ping, msg user_id message, file user_id filename, coins, quit\n>>> "
        arguments = line.split()
        if len(arguments) == 0:
            self.transport.write(help)
            return

        command = arguments[0]
        if command == "ping" or command == "p":
            # send ping to myself
            d = ClientCreator(reactor, UserClientProtocol, self.user).connectTCP(constants.P.external_ip, constants.P.port)
            d.addCallback(self.user.send_msg, self.user.identifier, "PING")
            d.addErrback(self.no_conn)
        elif command == "quit" or command == "q":
            reactor.stop()
        elif command == "msg" or command == "m":
            # send message in paging
            if len(arguments) > 2:
                callee = arguments[1]
                msg = arguments[2]
                d = ClientCreator(reactor, UserClientProtocol, self.user).connectTCP(constants.P.external_ip, constants.P.port)
                d.addCallback(self.user.send_msg, callee, msg)
                d.addErrback(self.no_conn)
            else:
                self.transport.write(help)
        elif command == "n":
            # dismiss call
            self.user.incoming_call = None
        elif command == "y" and self.user.incoming_call is not None:
            # take incoming call
            cid, caller = self.user.incoming_call
            d = ClientCreator(reactor, UserClientProtocol, self.user).connectTCP(constants.N.external_ip, constants.N.port)
            d.addCallback(self.user._answer_call, cid)
            d.addErrback(self.no_conn)
        elif command == "file" or command == "f":
            # send file
            extensions = ['bmp', 'gif', 'jpg', 'jpeg', 'png', 'tiff']
            if len(arguments) > 2:
                callee = arguments[1]
                filename = arguments[2]
                # check if file exists
                if os.path.isfile(filename) and any([filename.endswith(ext) for ext in extensions]):
                    d = ClientCreator(reactor, UserClientProtocol, self.user).connectTCP(constants.P.external_ip, constants.P.port)
                    d.addCallback(self.user.make_call, callee, filename)
                    d.addErrback(self.no_conn)
                else:
                    self.sendLine("File not available. Available files:")
                    files = [fn for fn in os.listdir('.') if any([fn.endswith(ext) for ext in extensions])];
                    for f in files:
                        self.sendLine(f)
                    self.transport.write('>>> ')
            else:
                self.transport.write(help)
        elif command == "coins" or command == "c":
            if len(arguments) > 1:
                self.user.get_coins(arguments[1])
            else:
                self.user.get_coins()
        else:
            self.transport.write(help)

    def no_conn(self, failure):
        self.transport.write('Not connected to network operator\n>>> ')


class User(object):
    ''' Main class representing a User '''
    def __init__(self, identifier, secret, location=None, reactor=reactor):
        self.identifier = identifier
        self.secret = secret  # preshared secret with P
        self.pseudonym = None
        self.paging_listener = PagingListener(self)
        self.io = None
        self.location = None
        self.seed = None
        self.paging_names = None
        self.next_update = None
        self.incoming_call = None
        self.coins = list()

        if location is not None:
            loc_ip, loc_port = location
            reactor.listenMulticast(loc_port, self.paging_listener)
        else:
            reactor.listenMulticast(60001, self.paging_listener)

    def update_providers(self, location='', retry=False):
        ''' Update location of user and tell providers '''
        if retry:
            sleep(2)

        if location != '':
            self.location = location
            self.io.sendLine("Your location: %s" % self.location)

        # create new pseudonym for location
        self.pseudonym = pick_random()
        self.seed = pick_random()
        self.paging_names = create_paging_names(self.seed, amount=100)
        d = ClientCreator(reactor, UserClientProtocol, self).connectTCP(constants.N.external_ip, constants.N.port)
        d.addCallback(self._update_location)
        if retry:
            d.addErrback(self._error, "network operator")
        else:
            d.addErrback(self.retry)

    def retry(self, error):
        self.update_providers(retry=True)

    def _update_location(self, protocol):
        ''' Used for callback '''
        # send location update first to avoid race condition
        protocol.location_update(self.pseudonym, self.location, self.seed)
        # send pseudonym update
        protocol.pseudonym_update(self.pseudonym, self.identifier, self.secret)
        protocol.transport.loseConnection()

        # cancel next scheduled soft-state update and start new one
        try:
            self.next_update.cancel()
        except (AttributeError, error.AlreadyCancelled, error.AlreadyCalled):
            pass
        some_time = randint(constants.LIFETIME/2, constants.LIFETIME)
        # have to give location explicitly
        self.next_update = reactor.callLater(some_time, self.update_providers, self.location)

    def send_msg(self, protocol, callee, msg):
        caller = self.identifier
        protocol.send_msg(callee, caller, msg)
        protocol.transport.loseConnection()

    def make_call(self, protocol, callee, filename):
        ''' Get file by filename and send to callee '''
        caller = self.identifier
        protocol.make_call(callee, caller, self.pseudonym, filename)

    @staticmethod
    def _answer_call(protocol, cid):
        ''' wrapper for function in UserClientProtocol '''
        protocol.answer_call(cid)

    def get_coins(self, amount=5):
        packet = [constants.Header.SIGN]
        blinding_factors = list()

        for _ in range(int(amount)):
            msg = pick_random()
            blinding_factor = pick_random()
            key = RSA.importKey(constants.B.public_key)
            blind = b64encode(key.blind(msg, blinding_factor))
            packet.append(blind)
            blinding_factors.append((blinding_factor, msg))

        d = ClientCreator(reactor, BankClient).connectTCP(constants.B.external_ip, constants.B.port)
        d.addCallback(self._send_blinds, blinding_factors, packet)
        d.addErrback(self._error, "Bank")

    def _send_blinds(self, protocol, blinding_factors, packet):
        protocol.blinding_factors = blinding_factors
        protocol.user = self
        protocol.sendLine(serialize(packet))

    def _error(self, error, endpoint):
        self.io.sendLine("Error connecting to %s" % endpoint)
        self.io.sendLine(str(error))


if __name__ == "__main__":
    user = User(constants.user1_id, constants.user1_secret)
    stdio.StandardIO(IO(user))

    reactor.run()
