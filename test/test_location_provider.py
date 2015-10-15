__author__ = 'Tim Dittler'

from twisted.trial import unittest
from twisted.test import proto_helpers
from datetime import datetime

from location_provider import LocationProvider, LocationProviderFactory


class LocationProviderTestCase(unittest.TestCase):
    def setUp(self):
        self.protocol = LocationProvider()
        self.transport = proto_helpers.FakeDatagramTransport()
        self.protocol.transport = self.transport

    # def test_incoming_call(self):
    #     cid = 8
    #     incoming_call = Packet(Packet.CALL, [constants.user1_pseudo, cid, constants.caller_id])
    #     self.transport.datagramReceived(incoming_call.serialize(), ("127.0.0.1", 80))
    #     # save call under cid


class DatabaseTestCase(unittest.TestCase):
    def setUp(self):
        self.L = LocationProviderFactory()

    def test_store(self):
        self.L.store("test", "test_location", "seed")
        value = self.L.database["test"]
        self.assertEqual("test_location", value[0])
        self.assertEqual("seed", value[1])
        diff = datetime.now() - value[2]
        self.assertLess(diff.seconds, 1)
        self.L.store("test", "false_location", "seed")
        self.assertEqual("test_location", value[0], "False override")


    def test_sanitize(self):
        time = datetime(2014, 8, 30, 9, 46, 59)
        self.L.database["test2"] = ["test_location", "seed", time]
        self.L.store("test", "test_location", "seed")
        self.assertEqual(len(self.L.database), 2)
        self.L.sanitize()
        self.assertEqual(len(self.L.database), 1)