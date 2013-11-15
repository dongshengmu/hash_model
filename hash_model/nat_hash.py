#!/usr/bin/env python
"""
    " nat_hash - get a set of NAT addresses that makes the 2 wing hash to same index.
    "
    " Created by Dongsheng Mu on 3/12/13.
    " Copyright 2013 Dongsheng Mu. All rights reserved.
    """

import random

class tuple_class:
    def __init__(self, value=None, note='tuple'):
        self.value = self.random() if value == None else value
        self.note = note
        self.bytes = [self.value[0] >> 24,
                      (self.value[0] >> 16) & 0xFF,
                      (self.value[0] >> 8) & 0xFF,
                      self.value[0] & 0xFF,
                      self.value[1] >> 24,
                      (self.value[1] >> 16) & 0xFF,
                      (self.value[1] >> 8) & 0xFF,
                      self.value[1] & 0xFF,
                      self.value[2] & 0xFF,
                      (self.value[3] >> 8) & 0xFF,
                      self.value[3] & 0xFF,
                      (self.value[4] >> 8) & 0xFF,
                      self.value[4] & 0xFF]
        self.hash = byte_hash(self.bytes)

    def random(self):
        S = random_bytes(4)
        D = random_bytes(4)
        p = random_bytes(1)
        s = random_bytes(2)
        d = random_bytes(2)
        return (S, D, p, s, d)
    
    def __repr__(self):
        (S, D, p, s, d) = self.value
        disp = ('%s: (S:%03d.%03d.%03d.%03d D:%03d.%03d.%03d.%03d p:%03d s:%05d d:%05d)'
              % (self.note, S >> 24, (S >> 16) & 0xFF, (S >> 8) & 0xFF, S & 0xFF,
                 D >> 24, (D >> 16) & 0xFF, (D >> 8) & 0xFF, D & 0xFF,
                 p, s, d))
        # disp += '\nhex: %s' % hex_rep(self.value)
        disp += ' hash result %s (%s)' % (self.hash, hex(self.hash))
        return disp

def byte_hash(bytes):
    h = 0
    for b in bytes:
        h ^= b
    return h

def hex_rep(l):
    disp = ''
    for i in l:
        disp += '%s ' % hex(i)
    return disp

def random_bytes(num):
    v = 0
    for i in xrange(num):
        v = (v << 8) + random.randint(0x01, 0xFF)
    return v

if __name__ == '__main__':
    t = tuple_class(note='random ipv4 tuple')
    print('Sample: %s' % t)
    
    # assume src_ip is translated
    for (index, name, size) in [(0, 'src_ip', 4), (1, 'dst_ip', 4), (3, 'src_port', 2), (4, 'dst_port', 2)]:
        nat = list(t.value)
        nat[index] = 0
        n = tuple_class(value= tuple(nat), note='%s nat tuple' % name)
        exp = n.hash ^ t.hash
        print('\nFor %s NAT, given [%s],' % (name, ', '.join([hex(x) for x in nat])))
        print('any %s with byte-hash value %s (%s) would make the NAT address having same hash as original tuple.' % (name, exp, hex(exp)))
        for sample in xrange(10):
            pool = []
            for i in xrange(size - 1):
                pool.append(random_bytes(1))
            pool.append(byte_hash(pool) ^ exp)
            value = 0
            for i in xrange(len(pool)):
                value = (value << 8) + pool[i]
            preferred_nat = list(t.value)
            preferred_nat[index] = value
            preferred_tuple = tuple_class(value=tuple(preferred_nat))
            print('\tin pool %s.**, %s' % ('.'.join([('%03d' % x) for x in pool[0:-1]]), preferred_tuple))


