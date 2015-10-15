# -*- test-case-name: pyanotel.test.test_pseudonym_provider -*-
from helpers import deserialize, serialize, pick_random, encrypt, asym_decrypt
from twisted.internet import reactor, ssl
from twisted.internet.protocol import Factory, ReconnectingClientFactory
from twisted.protocols.basic import LineReceiver
import constants


class PseudonymProtocol(LineReceiver):
    def lineReceived(self, line):
        print "received " + str(line)
        data = deserialize(line)
        op = data[0]
        if op == constants.Header.INITCALL:
            # if len(data) == 3:
            #     callee = data[1]
            #     caller = data[2]
            # el
            if len(data) == 2:
                callee, caller, pseudonym, msg = asym_decrypt(data[1], constants.P.private_key)
            else:
                print "Wrong amount of arguments"
                print data
            self.factory.P.init_call(callee, caller, pseudonym, self)
        elif op == constants.Header.MSG:
            callee, caller, msg = asym_decrypt(data[1], constants.P.private_key)
            self.factory.P.send_msg(callee, caller, msg)
        else:
            print "Type %d unknown" % op

    def connectionMade(self):
        print "Caller connected"

    def connectionLost(self, reason):
        print "Caller disconnected"


class PseudonymFactory(Factory):
    protocol = PseudonymProtocol

    def __init__(self, pseudonym_provider):
        self.P = pseudonym_provider


class LocationConnectorProtocol(LineReceiver):
    def connectionMade(self):
        print "Connected to Location Provider"
        self.factory.clientConnectionMade(self)
        # send register message
        self.sendLine(serialize([constants.Header.REGISTER, "P"]))

    def init_call(self, pseudo, blob):
        ''' Send pseudonym and a binary blob to L who will build paging packet from it '''
        packet = [constants.Header.INITCALL, pseudo, blob]
        self.sendLine(serialize(packet))
        print "Announcing call to L " + serialize(packet)


class LocationConnector(ReconnectingClientFactory):
    protocol = LocationConnectorProtocol

    def __init__(self, pseudonym_provider):
        self.P = pseudonym_provider

    def clientConnectionMade(self, server):
        self.P.L = server


class NetworkConnectorProtocol(LineReceiver):
    def connectionMade(self):
        print "Connected to Network Operator"
        self.factory.clientConnectionMade(self)
        # send register message
        self.sendLine(serialize([constants.Header.REGISTER, "P"]))

    def init_call(self, cid):
        packet = [constants.Header.STORE_CID, cid]
        self.sendLine(serialize(packet))

    def connectionLost(self, reason):
        print "Network connection lost"
        LineReceiver.connectionLost(self, reason)

    def lineReceived(self, line):
        print "received " + line
        packet = deserialize(line)
        if packet[0] == constants.Header.ANSWERCALL:
            cid = packet[1]
            self.factory.P.spawn_proxy(cid)
        elif packet[0] == constants.Header.PSEUDONYMUPDATE:
            plaintext = asym_decrypt(packet[1], constants.P.private_key)
            self.factory.P.pseudonym_update(plaintext[0], plaintext[1], plaintext[2])  # pseudonym, identifier, secret
        else:
            print "Type %d unknown" % packet[0]


class NetworkConnector(ReconnectingClientFactory):
    protocol = NetworkConnectorProtocol

    def __init__(self, pseudonym_provider):
        self.P = pseudonym_provider

    def clientConnectionMade(self, server):
        self.P.N = server


class PseudonymProvider():
    def __init__(self, reactor=reactor):
        self.reactor = reactor
        self.pseudonyms = {}  # id, pseudo
        self.calls = {}  # cid -> [callee, caller]
        self.secrets = constants.preshared_secrets  # {pseudo: symmetric_key}

        # process incoming calls, outgoing calls, pseudonym updates
        self.N = None
        self.L = None
        self.listener = PseudonymFactory(self)
        self.reactor.connectTCP(constants.N.ip, constants.N.port, NetworkConnector(self))
        # setup SSL
        self.reactor.connectSSL(constants.L.ip, constants.L.port, LocationConnector(self), ssl.ClientContextFactory())

        self.reactor.listenTCP(constants.P.port, self.listener)
        self.reactor.run()

    def init_call(self, callee, caller, pseudonym, connection):
        # check validity of caller
        if self.pseudonyms[caller] == pseudonym:
            cid = pick_random()
            try:
                assert len(callee) == constants.word_len
                assert len(caller) == constants.word_len
                pseudonym = self.pseudonyms[callee]
            except KeyError:
                print "Call for unknown user"
            except AssertionError:
                print "IDs have wrong length."
            else:
                self.calls[cid] = [callee, caller, connection]
                blob = encrypt([cid, caller], self.secrets[callee])
                self.L.init_call(pseudonym, blob)
                self.N.init_call(cid)

    def spawn_proxy(self, cid):
        if cid in self.calls:
            [callee, caller, connection] = self.calls[cid]
            # TODO muessen diese daten ueberhaupt vorher gespeichert werden?
            packet = [constants.Header.ANSWERCALL, cid]
            connection.sendLine(serialize(packet))

    def pseudonym_update(self, pseudonym, identifier, secret):
        # check preshared secret
        if self.secrets[identifier] == secret:
            # update pseudonym
            self.pseudonyms[identifier] = pseudonym
        else:
            print "Wrong secret supplied."

    def send_msg(self, callee, caller, msg):
        try:
            assert len(msg) <= constants.word_len
            pseudonym = self.pseudonyms[callee]
        except KeyError:
            print "Unknown recipient %s" % callee
        else:
            blob = encrypt([msg, caller], self.secrets[callee])
            self.L.init_call(pseudonym, blob)

if __name__ == "__main__":
    PseudonymProvider()
