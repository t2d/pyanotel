from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.test.test_loopback import SimpleProtocol

from network_operator import NetworkOperator, NetworkOperatorProtocol, Pager
from helpers import deserialize, pick_random
import constants


class TestNetworkOperator(unittest.TestCase):
    def setUp(self):
        self.pager = Pager()
        self.transport = proto_helpers.FakeDatagramTransport()
        self.pager.transport = self.transport

    def test_location_announcement(self):
        self.pager.startProtocol()
        self.pager.location_announcement()
        self.assertEqual(len(self.transport.written), 2)
        packet_serialized, addr = self.transport.written[0]
        packet = deserialize(packet_serialized)
        self.assertEqual(packet[0], constants.Header.LOCATIONANNOUNCEMENT)


class TestCidsHandling(unittest.TestCase):
    def setUp(self):
        self.factory = NetworkOperator(Pager())
        self.protocol = NetworkOperatorProtocol()
        self.factory.protocol = self.protocol
        self.pseudonym_provider = SimpleProtocol()
        self.pseudonym_provider.transport = proto_helpers.StringTransport()
        self.factory.pseudonym_provider = self.pseudonym_provider

    def tearDown(self):
        self.factory.cleanup()

    def test_store_cid(self):
        cid = pick_random()
        self.factory.store_cid(cid)
        self.assertEqual(self.factory.cids, [cid])
        self.factory.connect_call(cid, self.protocol)
        self.assertEqual(self.factory.cids, [])
