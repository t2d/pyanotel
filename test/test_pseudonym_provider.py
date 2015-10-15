from twisted.trial import unittest
from twisted.internet import reactor
from twisted.test import proto_helpers
from pseudonym_provider import PseudonymProvider, PseudonymFactory
from helpers import serialize, deserialize
import constants


class CallTestCase(unittest.TestCase):
    def setUp(self):
        self.prov = PseudonymProvider()
        self.prov.listener = PseudonymFactory(self.prov)

    # def test_incoming_call(self):
    #     self.prov.listener.protocol.lineReceived("test\r\n")
