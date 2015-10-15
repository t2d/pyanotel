from twisted.trial import unittest
from hashlib import md5

import helpers
import constants


class LineTestCase(unittest.TestCase):
    def test_serialization(self):
        packet = [constants.Header.INITCALL, helpers.pick_random(), helpers.pick_random()]
        line = helpers.serialize(packet)
        self.assertEqual(type(line), str)
        self.assertEqual(packet, helpers.deserialize(line))


class EncryptionTestCase(unittest.TestCase):
    def test_encryption(self):
        test_string = helpers.pick_random()
        ciphertext = helpers.encrypt(test_string, constants.user1_secret)
        plaintext = helpers.decrypt(ciphertext, constants.user1_secret)
        self.assertEqual(test_string, plaintext)

    def test_asym_encryption(self):
        identifier = helpers.pick_random()
        ciphertext = helpers.asym_encrypt(identifier, constants.P.public_key)
        s = helpers.serialize([0, ciphertext])
        [op, d] = helpers.deserialize(s)
        plaintext = helpers.asym_decrypt(d, constants.P.private_key)
        self.assertEqual(identifier, plaintext)

    def test_pick_random(self):
        for _ in range(10000):
            identifier = helpers.pick_random()
            self.assertEqual(len(identifier), 16, "Must be 16byte block")
            self.assertNotIn(" ", identifier)
            self.assertNotIn("\t", identifier)
            self.assertNotIn(constants.variable_delimiter, identifier)

    def test_paging_names(self):
        seed = "abcdefgh"
        amount = 10
        names = helpers.create_paging_names(seed, amount=amount)
        self.assertEqual(len(names), amount)
        for i in range(amount-2):
            self.assertNotEqual(names[i], names[i+1])
            self.assertNotEqual(md5(names[i]).digest(), names[i+1])