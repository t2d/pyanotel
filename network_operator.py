# -*- test-case-name: pyanotel.test.test_network_operator -*-

from twisted.internet.protocol import Factory, DatagramProtocol
from twisted.protocols.basic import LineReceiver
from twisted.internet import reactor, task, error
from Crypto.PublicKey import RSA
from base64 import b64decode, b64encode

import constants
from helpers import serialize, deserialize

# receive packet from locationProvider
# send them to the designated areas


class Pager(DatagramProtocol):
    ''' Sends UDP paging packets and location announcement '''
    def __init__(self):
        self.paging_packets = dict()

    def location_announcement(self):
        ''' send location announcements '''
        for key, value in constants.locations.iteritems():
            packet = [constants.Header.LOCATIONANNOUNCEMENT, key]
            self.transport.write(serialize(packet), value)

    def send_paging(self):
        ''' Forward paging packets from L '''
        for key, value in self.paging_packets.iteritems():
            self.transport.write(serialize(value), constants.locations[key])


class NetworkOperatorProtocol(LineReceiver):
    ''' Basic socket all users connect to '''
    def build_paging(self, data):
        if isinstance(data, list):
            # paging signal
            # split and send paging packets
            location = data.pop(1)
            self.factory.pager.paging_packets[location] = data

    def connectionMade(self):
        addr = self.transport.getPeer()
        print "Client connected from %s:%d" % (addr.host, addr.port)

    def connectionLost(self, reason):
        print "Connection lost"

        # change state
        if self == self.factory.pseudonym_provider or self == self.factory.location_provider:
            self.factory.fully_connected = False
            print "Not fully connected anymore"
            return

        to_delete = None
        for key, value in self.factory.waiting_connections.iteritems():
            if value == self:
                to_delete = key

        if hasattr(self, 'goal'):
            self.goal.transport.loseConnection()
            print "- Corresponding connection canceled"

        if to_delete is not None:
            del self.factory.waiting_connections[to_delete]
            print "- Waiting entry deleted"

    def lineReceived(self, line):
        # addr = self.transport.getPeer()
        # print "received: " + line + " from %s:%d" % (addr.host, addr.port)
        inputs = deserialize(line)

        if inputs[0] == constants.Header.REGISTER:
            self.register(inputs[1], self)
            return
        elif inputs[0] == constants.Header.PAGING:
            self.build_paging(inputs)
            return

        if self.factory.fully_connected:
            if inputs[0] == constants.Header.STORE_CID:
                self.factory.store_cid(inputs[1])
                return
            elif inputs[0] == constants.Header.LOCATIONUPDATE:
                # XXX check location validity?
                # forward to L
                self.factory.location_provider.sendLine(line)
                return
            elif inputs[0] == constants.Header.ANSWERCALL:
                cid = inputs[1]
                self.factory.connect_call(cid, self)
                return
            elif inputs[0] == constants.Header.INITCALL:
                cid = inputs[1]
                coin = (inputs[2], (long(inputs[3]),))
                self.forward(cid, coin)
                return
            elif inputs[0] == constants.Header.PSEUDONYMUPDATE:
                # forward to P
                self.factory.pseudonym_provider.sendLine(line)
                return
            else:
                print "Received unrecognized header %d" % inputs[0]

    def register(self, name, instance):
        if name == "L":
            self.factory.location_provider = instance
            print "Location Provider registered"
        elif name == "P":
            self.factory.pseudonym_provider = instance
            print "Pseudonym Provider registered"

        # change state
        if self.factory.location_provider is not None:
            if self.factory.pseudonym_provider is not None:
                self.factory.fully_connected = True
                print "Now fully connected"

    def forward(self, cid, coin):
        ''' Connect two user connections and set sockets to raw mode '''
        if cid in self.factory.waiting_connections:
            # verify coin
            msg, sig = coin
            key = RSA.importKey(constants.B.public_key)
            if coin not in self.factory.bank.used_coins and key.verify(msg, sig):
                # connect
                self.goal = self.factory.waiting_connections.pop(cid)
                answer = [constants.Header.RAWNOW]
                self.sendLine(serialize(answer))
                self.setRawMode()
                self.factory.bank.used_coins.append(coin)
            else:
                answer = [constants.Header.ERROR]
                self.sendLine(serialize(answer))
                self.transport.loseConnection()



    def rawDataReceived(self, data):
        ''' Forward raw data between users '''
        self.goal.transport.write(data)


class NetworkOperator(Factory):
    protocol = NetworkOperatorProtocol

    def __init__(self, pager_factory, bank_factory=None):
        self.pager = pager_factory
        self.bank = bank_factory
        self.location_provider = None
        self.pseudonym_provider = None
        self.cids = list() # cid
        self.waiting_connections = {}  # waiting for other endpoint
        self.fully_connected = False
        self.tasks = list()

    def store_cid(self, cid):
        ''' Store cid and start task to delete it '''
        self.cids.append(cid)
        task = reactor.callLater(60, self.delete_cid, cid)
        self.tasks.append(task)
        print "Store new cid %r" % cid

    def delete_cid(self, cid):
        ''' Delete cids and corresponding soft-state cleanup tasks'''
        try:
            self.cids.remove(cid)
            # FIXME this should also end task, but task is list. Sadly cid is not iterable
        except ValueError:
            pass

    def connect_call(self, cid, connection):
        if cid in self.cids:
            print "Connecting %r" % cid
            self.delete_cid(cid)
            # spawn proxy to User
            self.waiting_connections[cid] = connection
            connection.setRawMode()
            # tell P
            packet = [constants.Header.ANSWERCALL, cid]
            self.pseudonym_provider.sendLine(serialize(packet))
        else:
            print "No corresponding connection found"

    def cleanup(self):
        ''' Cancel future tasks '''
        for task in self.tasks:
            try:
                task.cancel()
            except (error.AlreadyCancelled, error.AlreadyCalled):
                pass


class Bank(LineReceiver):
    def __init__(self):
        self.key = RSA.importKey(constants.B.private_key)

    def lineReceived(self, line):
        data = deserialize(line)

        if data[0] == constants.Header.SIGN:
            # sign my blinds
            blinds = data[1:]
            print("Signing %d blinds" % len(blinds))
            answer = [constants.Header.SIGN]
            for blind in blinds:
                blindsig = self.key.sign(b64decode(blind), "bla")[0]
                answer.append(blindsig)
            self.sendLine(serialize(answer))


class BankFactory(Factory):
    def __init__(self):
        self.used_coins = list()
        # XXX das handeling fuer viele coins ist nicht ausgereift

    def buildProtocol(self, addr):
        return Bank()


if __name__ == "__main__":
    pager = Pager()
    reactor.listenUDP(0, pager)
    bank = BankFactory()
    reactor.listenTCP(constants.B.port, bank)
    network_operator = NetworkOperator(pager, bank)
    port = reactor.listenTCP(constants.N.port, network_operator)
    print "Network Operator started on port %d" % port.getHost().port

    # start periodic tasks
    location_announcement = task.LoopingCall(pager.location_announcement)
    location_announcement.start(2)  # from now every two seconds
    paging = task.LoopingCall(pager.send_paging)
    paging.start(1)

    reactor.addSystemEventTrigger('before', 'shutdown', network_operator.cleanup)

    reactor.run()
