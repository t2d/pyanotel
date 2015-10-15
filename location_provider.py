# -*- test-case-name: pyanotel.test.test_location_provider -*-

from twisted.internet.protocol import ServerFactory, ReconnectingClientFactory
from twisted.internet.ssl import PrivateCertificate
from twisted.internet import reactor, task
from twisted.protocols.basic import LineReceiver
from base64 import b64encode
from datetime import datetime

import constants
from helpers import pick_random, serialize, deserialize, asym_decrypt, create_paging_names


class LocationProviderClient(LineReceiver):
    ''' Connector to network '''
    def connectionMade(self):
        print "Connected to Network Operator"
        self.factory.clientConnectionMade(self)
        # send register message
        self.sendLine(serialize([constants.Header.REGISTER, "L"]))

    def lineReceived(self, line):
        print "Received %s from Network Operator" % line
        packet = deserialize(line)
        if packet[0] == constants.Header.LOCATIONUPDATE:
            plaintext = asym_decrypt(packet[1], constants.L.private_key)
            self.factory.server.store(plaintext[0], plaintext[1], plaintext[2])  # pseudo, loc, seed
        else:
            print "Unknown operator %d" % packet[0]


class NetworkConnector(ReconnectingClientFactory):
    ''' Factory to connect to network '''
    protocol = LocationProviderClient

    def __init__(self, server):
        self.loop = task.LoopingCall(self.paging)
        self.network_operator = None
        self.server = server
        self.server.client = self

    def clientConnectionMade(self, server):
        self.network_operator = server
        self.loop.start(2)

    def clientConnectionLost(self, connector, unused_reason):
        self.loop.stop()
        print "Connection lost"
        ReconnectingClientFactory.clientConnectionLost(self, connector, unused_reason)

    @staticmethod
    def create_dummy():
        ''' Create a dummy that looks like an actual paging message '''
        cid = pick_random()
        callee = pick_random()
        caller = pick_random()
        return [callee, b64encode(cid+caller)]  # + simulates encryption

    def paging(self):
        ''' Collect all calls and pages them, use dummy when no call '''
        temp = dict(self.server.calls)
        self.server.calls = dict().fromkeys(constants.locations.keys())

        # for each location send packet to network provider
        for location in temp:
            packet = list()
            packet.append(constants.Header.PAGING)
            packet.append(location)
            calls = temp[location]
            if calls is None:
                # no calls, include dummies
                dummy = self.create_dummy()
                packet.extend(dummy)
            else:
                # add calls
                for call in calls:  # list of calls
                    packet.extend(call)
            print "sending " + serialize(packet)
            self.network_operator.sendLine(serialize(packet))


class LocationProvider(LineReceiver):
    ''' Socket for pseudonym provider '''

    def handle_call(self, callee, blob):
        ''' Send paging for this call, no dummy '''
        try:
            (location, seed, time) = self.factory.database[callee]
        except KeyError:
            print "Location for %s not found -> Broadcast" % callee
            for location in constants.locations:
                self.add_call_to_location(location, callee, blob)
        else:
            # create paging names if not already done
            if not callee in self.factory.paging_names:
                self.factory.paging_names[callee] = create_paging_names(seed)

            paging_name = self.factory.paging_names[callee].pop(0)

            # refill paging_names if necesarry
            if len(self.factory.paging_names[callee]) == 0:
                self.factory.paging_names[callee] = create_paging_names(seed, paging_name)

            self.add_call_to_location(location, paging_name, blob)

    def add_call_to_location(self, location, callee, blob):
        ''' Append call that shall be paged in that location in the future '''
        if self.factory.calls[location] is None:
            self.factory.calls[location] = [[callee, blob]]
        else:
            self.factory.calls[location].append([callee, blob])  # callee, encrypted(cid, caller)

    def lineReceived(self, line):
        print "Received %s from Pseudonym Provider" % line
        packet = deserialize(line)

        if packet[0] == constants.Header.REGISTER:
            if packet[1] == "P":
                # register pseudonym provider
                self.factory.pseudonym_provider = self
                print "Registered Pseudonym Provider"
        elif packet[0] == constants.Header.INITCALL:
            self.handle_call(packet[1], packet[2])
        else:
            print "Wrong request_type %d" % packet[0]


class LocationProviderFactory(ServerFactory):
    ''' Main class for location provider '''
    protocol = LocationProvider

    def __init__(self):
        self.database = dict() # stores locations to pseudonyms
        self.calls = dict()  # store to be paged calls
        self.locations = constants.locations
        self.paging_names = dict() # stores paging names to pseudonyms
        self.client = None
        self.pseudonym_provider = None

    def store(self, pseudonym, location, seed):
        ''' Store a location update'''
        # don't allow override
        if pseudonym not in self.database:
            self.database[pseudonym] = [location, seed, datetime.now()]
            print "Storing location %s for pseudonym %r" % (location, pseudonym)

    def sanitize(self):
        ''' Delete old pseudonyms from database '''
        now = datetime.now()
        for pseudonym, value in self.database.items():
            date = value[2]
            diff = now - date
            if diff.seconds > constants.LIFETIME:
                del self.database[pseudonym]
                try:
                    del self.paging_names[pseudonym]
                except KeyError:
                    pass

if __name__ == "__main__":
    # setup SSL
    with open('ssl/localhost.pem') as keyandcert:
        certificate = PrivateCertificate.loadPEM(keyandcert.read())

    factory = LocationProviderFactory()
    reactor.listenSSL(constants.L.port, factory, certificate.options())

    reactor.connectTCP(constants.N.ip, constants.N.port, NetworkConnector(factory))

    sanitizing = task.LoopingCall(factory.sanitize)
    sanitizing.start(3, False)  # once a minute

    reactor.run()

    # XXX: Broadcast fuehrt zu erkennbarer Information