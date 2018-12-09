"""
Name:       enigma.py
Purpose:    This module is the main module of the project, exports class
            Enigma and useful functions to use with it
Author:     Dor Genosar (dor.genosar@outlook.com)
Change log:
   2018/11/23 16:04 Created
"""

import random
import binascii
from functools import reduce


def hexlify(itr):
    return binascii.hexlify(bytes(itr)).decode('ascii')


def unhexlify(string):
    return list(binascii.unhexlify(string.encode('ascii')))


ROTOR_SIZE = 256


def split_by_count(obj, count):
    splits = []
    for start, stop in zip(range(0, len(obj), count),
                           list(range(count, len(obj) + count, count))):
        if stop < len(obj):
            splits.append(obj[start:stop])
        else:
            splits.append(obj[start:])
    return splits


def create_random_rotor():
    rotor = list(range(ROTOR_SIZE))
    random.shuffle(rotor)
    return rotor


def create_random_rotors(rotor_count):
    rotors = []
    for _ in range(rotor_count):
        rotors.append(create_random_rotor())
    return rotors


def create_random_rotor_configuration(rotor_count):
    return list(random.randrange(ROTOR_SIZE) for _ in range(rotor_count))


class Enigma(object):
    def __init__(self, rotors, rotor_conf):
        self._rotors = rotors
        self._rotor_conf = rotor_conf[:]

    @staticmethod
    def randomize_new_machine(rotor_count=32):
        return Enigma(
            create_random_rotors(rotor_count),
            create_random_rotor_configuration(rotor_count)
        )

    @staticmethod
    def from_key(key_bytes):
        *rotors, rotor_conf = split_by_count(key_bytes, ROTOR_SIZE)
        return Enigma(
            [list(rotor) for rotor in rotors],
            list(rotor_conf)
        )

    def increment(self):
        for i, position in enumerate(self._rotor_conf):
            new_position = (position + 1) % ROTOR_SIZE
            self._rotor_conf[i] = new_position
            if new_position:
                break

    def encrypt_byte(self, byte):
        cipher_byte = byte
        for position, rotor in zip(self._rotor_conf, self._rotors):
            cipher_byte = rotor[(cipher_byte + position) % ROTOR_SIZE]
        self.increment()
        return cipher_byte

    def decrypt_byte(self, cipher_byte):
        byte = cipher_byte
        for position, rotor in zip(reversed(self._rotor_conf),
                                   reversed(self._rotors)):
            byte = (rotor.index(byte) - position) % ROTOR_SIZE
        self.increment()
        return byte

    def encrypt_bytes(self, org_bytes):
        return bytes(
            self.encrypt_byte(byte)
            for byte in org_bytes
        )

    def decrypt_bytes(self, cipher_bytes):
        return bytes(
            self.decrypt_byte(cipher_byte)
            for cipher_byte in cipher_bytes
        )

    def export_key(self):
        return reduce(lambda a, b: a + b, (bytes(rotor) for rotor in self._rotors))\
               + bytes(self._rotor_conf)

    def __str__(self):
        return f"<Enigma:{len(self._rotors)} rotors;" \
            f"at {hexlify(self._rotor_conf)}>"

    def __repr__(self):
        return self.__str__()
