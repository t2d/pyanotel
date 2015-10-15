# -*- test-case-name: pyanotel.test.test_helpers -*-

from Crypto.Cipher import AES
from Crypto.Util import Counter
from base64 import b64decode, b64encode
from hashlib import md5
from os import urandom
from string import whitespace

import seccure

import constants


def pick_random():
    ''' returns random 128 bit without any whitespaces '''
    has_space = True
    while has_space:
        random = urandom(constants.word_len)
        has_space = False
        # check for any whitespace
        if any(w in random for w in whitespace):
            has_space = True
    return random


def serialize(packet_list):
    # convert any int to str
    return ' '.join(map(str, packet_list))


def deserialize(packet_string):
    packet = packet_string.split()
    packet[0] = int(packet[0])  # XXX should this really be int
    return packet


def split_words(seq):
    """ divide a sequence into chunks of 16 units."""
    liste = list()
    nr = constants.word_len
    while seq:
        liste.append(seq[:nr])
        seq = seq[nr:]
    return liste


def asym_encrypt(plaintext, public_key):
    ''' encryption with ECIES '''
    if isinstance(plaintext, list):
        plaintext = ''.join(map(str, plaintext))
    ciphertext = seccure.encrypt(plaintext, public_key)
    encoded_ciphertext = b64encode(ciphertext)
    return encoded_ciphertext


def asym_decrypt(encoded_ciphertext, private_key):
    ''' decryption with ECIES '''
    ciphertext = b64decode(encoded_ciphertext)
    plaintext = seccure.decrypt(ciphertext, private_key)
    liste = split_words(plaintext)
    if len(liste) > 1:
        return liste
    else:
        return plaintext


def encrypt(plaintext, secret):
    ''' encryption with AES '''
    if isinstance(plaintext, list):
        new_plaintext = []
        for text in plaintext:
            word = make_word(text)
            new_plaintext.append(word)
        plaintext = ''.join(map(str, new_plaintext))
    if len(plaintext) % 16 != 0:
        print plaintext
        print len(plaintext)
    assert len(plaintext) % 16 == 0
    counter = Counter.new(128)  # bits
    cipher = AES.new(secret, AES.MODE_CTR, counter=counter)
    ciphertext = cipher.encrypt(plaintext)
    encoded_ciphertext =b64encode(ciphertext)
    return encoded_ciphertext


def decrypt(encoded_ciphertext, secret):
    ''' decryption with AES '''
    ciphertext = b64decode(encoded_ciphertext)
    assert len(ciphertext) % 16 == 0
    counter = Counter.new(128)
    cipher = AES.new(secret, AES.MODE_CTR, counter=counter)
    plaintext = cipher.decrypt(ciphertext)
    liste = split_words(plaintext)
    if len(liste) > 1:
        return liste
    else:
        return plaintext


def make_word(text):
    while len(text) < constants.word_len:
        text = text + "#"
    return text

def make_msg(text):
    msg = "M:" + text
    return make_word(msg)

def get_msg(word):
    while word[-1] == "#":
        word = word[:-1]
    return word[2:]


def create_paging_names(seed, name='', amount=5):
    ''' create paging pseudonyms for a user from a supplied seed '''
    paging_names = []
    while len(paging_names) < amount:
        name = md5(name + seed).digest()
        if not any(w in name for w in whitespace):
            # surpress whitespaces in names
            paging_names.append(name)
    return paging_names
