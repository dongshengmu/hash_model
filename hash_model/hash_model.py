#!/usr/bin/env python
"""
" hash_model - model flow hash distribution
"
" Created by Dongsheng Mu on 10/5/12.
" Copyright 2012 Dongsheng Mu. All rights reserved.
"""

import random

def tuple_generator(sip, dip, protocols, sport, dport, note):
    idx = 0
    if sip:
        print('Generatng tuple samples, %s:\n    %d src_ip: %s\n    %d dst_ip: %s\n    %d protocols: %s\n    src_port: %s\n    dst_port: %s'
              % (note, len(sip), sip[:10], len(dip), dip[:10], len(protocols), protocols[:10], sport, dport))
        for S in sip:
            for D in dip:
                for p in protocols:
                    for s in sport(S, D):
                        for d in dport(S, D):
                            if idx < 10 or idx % 100000 == 0:
                                print('%8d: (S:%d.%d.%d.%d D:%d.%d.%d.%d p:%d s:%d d:%d)'
                                      % (idx, S >> 24, (S >> 16) & 0xFF, (S >> 8) & 0xFF, S & 0xFF,
                                         D >> 24, (D >> 16) & 0xFF, (D >> 8) & 0xFF, D & 0xFF,
                                         p, s, d))
                            idx += 1
                            if idx > 1000000:
                                raise StopIteration()
                            else:
                                yield (S, D, p, s, d)
    else:
        print('Generatng tuple samples, %s:' % note)
        for idx in xrange(1000000):
            S = random.randint(0x01000001, 0xFFFFFFFF)
            D = random.randint(0x01000001, 0xFFFFFFFF)
            p = random.randint(1, 0xFF)
            s = random.randint(1, 0xFFFF)
            d = random.randint(1, 0xFFFF)
            if idx < 10 or idx % 100000 == 0:
                print('%8d: (S:%d.%d.%d.%d D:%d.%d.%d.%d p:%d s:%d d:%d)'
                      % (idx, S >> 24, (S >> 16) & 0xFF, (S >> 8) & 0xFF, S & 0xFF,
                         D >> 24, (D >> 16) & 0xFF, (D >> 8) & 0xFF, D & 0xFF,
                         p, s, d))
            yield (S, D, p, s, d)
    print('')


ip_start = random.randint(0x10000001, 0xffffff00)
favored_ip = [x for x in xrange(ip_start, ip_start + 0x1F)]
port_start = random.randint(1, 0xFF00)
favored_port = range(port_start, port_start + 0x0005)
nat_port = range(1, 0x0FFF)
dst_ip = [0x4a7d816a, 0x481e268c]   # google, yahoo
dst_port = [80]         # http
ip_protocol_type = [6]  # tcp, udp
    #favored_tuples = [(S, D, p, s, d)
    #              for S in favored_ip
    #              for D in dst_ip
    #              for p in ip_protocol_type
    #              for s in (nat_port if (S == favored_ip[0]) else favored_port)
    #              for d in dst_port]
favored_tuples = lambda : tuple_generator(favored_ip, dst_ip, ip_protocol_type,
                                          lambda S, D: (nat_port if (S == favored_ip[0]) else favored_port),
                                          lambda S, D: dst_port,
                                          'favored tuples with 2 fat NAT')
str_favored = ("Fake 2 fat NAT (31 src-ip, 4 src_port, 1 PNAT-4K, 2 dst-ip, 1 dst-port, 1 protocols)")
#print(favored_tuples)

ip_start2 = random.randint(0x10000001, 0xffffff00)
favored_ip2 = [x for x in xrange(ip_start2, ip_start2 + 0xFF)]
port_start2 = random.randint(1, 0xFF00)
favored_port2 = range(port_start2, port_start2 + 0x0008)
nat_port2 = range(1, 0xFFFF)
#dst_ip2 = [0x4a7d816a, 0x481e268c, 0x45abf715]   # google, yahoo, facebook
dst_ip2 = random.sample(xrange(0x40000000, 0x4FFFFFFF), 3)
dst_port2 = [80, 8080, 8081, 22, 23]       # http
ip_protocol_type2 = [6, 17]  # tcp, udp
    #favored_tuples_1M = [(S, D, p, s, d)
    #                 for S in favored_ip2
    #                 for D in dst_ip2
    #                 for p in ip_protocol_type2
    #                 for s in (nat_port2 if (S == favored_ip2[0]) else favored_port2)
    #                 for d in dst_port2]
favored_tuples_1M = lambda : tuple_generator(favored_ip2, dst_ip2, ip_protocol_type2,
                                             lambda S, D: (nat_port2 if (S == favored_ip2[0]) else favored_port2),
                                             lambda S, D: dst_port2,
                                             'favored tuples with 6 fat NAT')
str_favored_1M = ("Fake 6 fat NAT, 1 of 255 SrcIP has 64K SrcPort, all connected to 3 DstIP 2 Proto (255 src-ip, 8 src_port, 1 PNAT-64K, 3 dst-ip, 5 dst-port, 2 protocols)")
#print(favored_tuples_1M)

dst_ip3 = random.sample(xrange(0x40000000, 0x4FFFFFFF), 100)
nat_port3 = [random.sample(xrange(0xFFFF), random.randint(1, (0xFFFF * 2 / 100))) for x in xrange(100)]
favored_nat = lambda : tuple_generator(favored_ip2, dst_ip3, ip_protocol_type2,
                                       lambda S, D: (nat_port3[D % 100] if (S == favored_ip2[0]) else favored_port2),
                                       lambda S, D: dst_port2,
                                       'favored tuples with 6 fat NAT')
str_favored_nat = ("PNAT, 1 of 255 SrcIP has 64K SrcPort, randomly connected to 100 DstIP 2 Proto (255 src-ip, 8 src_port, 1 PNAT-64K, 100 dst-ip, 5 dst-port, 2 protocols)")


rS = random.sample(xrange(0xFFFFFFFF), 100)
rD = random.sample(xrange(0xFFFFFFFF), 100)
rp = random.sample(xrange(0xFF), 1)
rs = [random.sample(xrange(0xFFFF), random.randint(1, 100)) for x in xrange(100)]
rd = [random.sample(xrange(0xFFFF), random.randint(1, 5)) for x in xrange(5)]
    #random_tuples = [(S, D, p, s, d)
    #             for S in rS
    #             for D in rD
    #             for p in rp
    #             for s in rs[S % 100]
    #             for d in rd[D % 5]]
random_tuples = lambda : tuple_generator(rS, rD, rp,
                                         lambda S, D: rs[S % 100],
                                         lambda S, D: rd[D % 5],
                                         'random tuples, upto 100 random num of ports per SrcIP, upto 5 per DstIP')
str_random_1M = ("random tuples, (100 src-ip, 10 dst-ip, 1 protocol, ip pair with 0-100 random num of random src-ip, 0-5 dst-ip)")
#print(random_tuples)

pure_random_tuples = lambda : tuple_generator(None, None, None, None, None,
                                              'completely random tuples')
str_pure_random_1M = ("completely random tuples")


ip_start = random.randint(0x10000001, 0xfff00000)
favored_ip = [x for x in xrange(ip_start, ip_start + 0xFFFF)]  # 64K sequential
port_start = random.randint(1, 0xFF00)
favored_port = [x & 0xFFFF for x in range(port_start, port_start + 0xFFFF)]
dst_ip = [0x4a7d816a]   # google, yahoo
dst_port = [80]         # http
ip_protocol_type = [6]  # tcp, udp
lab_incremental_tuples = lambda : tuple_generator(favored_ip, dst_ip, ip_protocol_type,
                                          lambda S, D: [(S & 0xFFFF) + 0],
                                          lambda S, D: dst_port,
                                          'lab increasing src-ip and src-port together')
str_lab_incremental_tuples = ("Lab increasing src-ip/src-port (64K src-ip, 64K src_port, 1 dst-ip, 1 dst-port, 1 protocols)")
#print(lab_incremental_tuples)


class tuple_class:
    def __init__(self, num_sip=0, num_dip=0, num_sport=0, num_dport=0, num_p=0):
        pass

crc32_tab = [
    0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
    0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
    0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
    0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
    0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
    0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
    0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
    0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
    0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
    0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
    0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
    0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
    0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
    0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
    0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
    0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
    0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
    0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
    0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
    0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
    0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
    0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
    0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
    0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
    0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
    0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
    0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
    0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
    0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
    0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
    0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
    0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
    0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
    0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
    0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
    0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
    0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
    0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
    0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
    0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
    0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
    0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
    0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
    0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
    0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
    0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
    0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
    0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
    0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
    0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
    0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
    0x2d02ef8dL]

def crc32(val, byte_len, crc32val=0):
    """
    Return a 32-bit CRC of the contents of a buffer.
    Support incremental CRC calculations.
    Generated using the AUTODIN II polynomial
    x^32 + x^26 + x^23 + x^22 + x^16 +
    x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x^1 + 1
    """
    global crc32_tab
    for i in xrange(byte_len):
        crc32val = crc32_tab[(crc32val ^ (val >> (i * 8))) & 0xff] ^ (crc32val >> 8);
    return crc32val;


def hash_algorithm(tuple=None, prime=False, all_keys=True, num_bits=8,
                   dst_only=False, src_only=False, port_only=False, crc=False):
    if tuple == None:
        name = ('%d-tuple hash: hash-bucket-size %d'
                % (2 if port_only else (5 if all_keys else 3), 2 ** num_bits))
        if src_only or dst_only:
            alias = ('%sIP-Only'
                     % ('Dst' if dst_only else 'Src'))
        elif crc:
            alias = ('%dT%dB-CRC'
                     % (5 if all_keys else 3, num_bits))
        elif port_only:
            alias = ('%dB-Port-Only'
                     % (num_bits))
        else:
            alias = ('%dT%dB'
                     % (5 if all_keys else 3, num_bits))
        #print('hash_algorithm: multiply-prime-num %s, num-of-tuple-used %d, hash-result-bits %d, hash-bucket-size %d'
        #  % (prime, 5 if all_keys else 3, num_bits, 2 ** num_bits))
        return (name, alias, 2 ** num_bits)
    
    (S, D, p, s, d) = tuple
    if (prime):
        S *= 263
        D *= 263
        p *= 13
        s *= 37
        d *= 37
    
    mask = (2 ** num_bits) - 1
    if dst_only:
        h = ((D & mask)
             ^ ((D >> (num_bits * 1)) & mask)
             ^ ((D >> (num_bits * 2)) & mask)
             ^ ((D >> (num_bits * 3)) & mask))
    elif src_only:
        h = ((S & mask)
             ^ ((S >> (num_bits * 1)) & mask)
             ^ ((S >> (num_bits * 2)) & mask)
             ^ ((S >> (num_bits * 3)) & mask))
    elif crc:
        c = crc32(S ^ D, 4, 0)
        if all_keys:
            c = crc32(s ^ d, 2, c)
            c = crc32(p, 1, c)
        h = ((c & mask)
             ^ ((c >> (num_bits * 1)) & mask)
             ^ ((c >> (num_bits * 2)) & mask)
             ^ ((c >> (num_bits * 3)) & mask)
             )
    else:
        h = 0
        if not port_only:
            h = ((S & mask)
                 ^ ((S >> (num_bits * 1)) & mask)
                 ^ ((S >> (num_bits * 2)) & mask)
                 ^ ((S >> (num_bits * 3)) & mask)
                 ^ (D & mask)
                 ^ ((D >> (num_bits * 1)) & mask)
                 ^ ((D >> (num_bits * 2)) & mask)
                 ^ ((D >> (num_bits * 3)) & mask)
                 ^ (p & mask)
                 )
        if all_keys:
            h = (h
                 ^ (s & mask)
                 ^ ((s >> (num_bits * 1)) & mask)
                 ^ (d & mask)
                 ^ ((d >> (num_bits * 1)) & mask)
                 )
    return h

h3 = lambda x: hash_algorithm(x, prime=False, all_keys=False, num_bits=8)
h3p = lambda x: hash_algorithm(x, prime=True, all_keys=False, num_bits=8)
h3_10 = lambda x: hash_algorithm(x, prime=False, all_keys=False, num_bits=10)
h3p_10 = lambda x: hash_algorithm(x, prime=True, all_keys=False, num_bits=10)
h5 = lambda x: hash_algorithm(x, prime=False, all_keys=True, num_bits=8)
h5p = lambda x: hash_algorithm(x, prime=True, all_keys=True, num_bits=8)
h5_10 = lambda x: hash_algorithm(x, prime=False, all_keys=True, num_bits=10)
h5p_10 = lambda x: hash_algorithm(x, prime=True, all_keys=True, num_bits=10)
h3_16 = lambda x: hash_algorithm(x, prime=False, all_keys=False, num_bits=16)
h5_16 = lambda x: hash_algorithm(x, prime=False, all_keys=True, num_bits=16)
h_dip = lambda x: hash_algorithm(x, prime=False, num_bits=8, dst_only=True)
h_sip = lambda x: hash_algorithm(x, prime=False, num_bits=8, src_only=True)
h2_crc = lambda x: hash_algorithm(x, prime=False, all_keys=False, num_bits=8, crc=True)
h5_crc = lambda x: hash_algorithm(x, prime=False, all_keys=True, num_bits=8, crc=True)
h_port_only = lambda x: hash_algorithm(x, prime=False, all_keys=True, num_bits=8, port_only=True)

accumulated_buckets = {}
def calc_bucket_dist(tuples, hash, hash_alias, bucket_size):
    global accumulated_buckets
    bucket_dist = [0] * bucket_size
    if type(tuples) == list:
        tuples = tuples.__iter__
    for i in tuples():
        h = hash(i)
        bucket_dist[h] += 1
    
    # accumulate the bucket_dist
    if hash_alias in accumulated_buckets:
        a = accumulated_buckets[hash_alias]
        for i in xrange(bucket_size):
            a[i] += bucket_dist[i]
    else:
        accumulated_buckets[hash_alias] = [x for x in bucket_dist]
    return bucket_dist

def hash_buckets(tuples, hash, num_spu=None, note=None):
    hash_name, hash_alias, bucket_size = hash(None)
    
    print('%s (%s)\n%s' % (hash_name, hash_alias, '=' * (7 + len(hash_name))))
    
    if tuples:
        bucket_dist = calc_bucket_dist(tuples, hash, hash_alias, bucket_size)
        total_tuples = sum(bucket_dist)
        if note:
            print('\n=== %s hash result for %d flows, %s' % (hash_alias, total_tuples, note))
    else:
        bucket_dist = accumulated_buckets[hash_alias]
        total_tuples = sum(bucket_dist)
        print('\n=== %s Accumulated hash result for %d tuples:' % (hash_alias, total_tuples))
    
    #print('total num of tuples %d, hashed %d\n' % (num, t))
    average_bucket = total_tuples / float(bucket_size)
    print('%d bucket distribution: max %d (%s), min %d (%s), average %d, bucket_size %d, empty_buckets: %d'
          % (bucket_size,
             max(bucket_dist), round((max(bucket_dist) * 100.0)/average_bucket, 2),
             min(bucket_dist), round((min(bucket_dist) * 100.0)/average_bucket, 2),
             int(average_bucket), bucket_size, len([x for x in bucket_dist if x == 0])))
    #print('%s\n' % bucket_dist)
    heavy_loaded = [(x, bucket_dist[x]) for x in xrange(bucket_size) if bucket_dist[x] > max(3 * average_bucket, 1)]
    cold_buckets = [(x, bucket_dist[x]) for x in xrange(bucket_size) if bucket_dist[x] < average_bucket / 3]
    print('    %d hot buckets: %s' % (len(heavy_loaded), heavy_loaded[:20]))
    print('    %d cold buckets: %s' % (len(cold_buckets), cold_buckets[:20]))
    
    
    # SPU distribution
    typical_install = [num_spu] if num_spu else [3, 7, 8, 11, 31, 39]
    for num_spu in typical_install:
        spu_dist = []
        for i in xrange(num_spu):
            spu_dist.append(sum([bucket_dist[x] for x in xrange(bucket_size) if x % num_spu == i]))
        
        average = total_tuples / float(num_spu)
        print('%d spu distribution: max %d (%s), min %d (%s), average %d, num_spu %d, idle_spu %d\n    session: %s\n    percent: %s'
              % (num_spu,
                 max(spu_dist), round((max(spu_dist) * 100.0)/average, 2),
                 min(spu_dist), round((min(spu_dist) * 100.0)/average, 2),
                 int(average), num_spu, len([x for x in spu_dist if x == 0]),
                 spu_dist, [round((x * 100.0)/average, 2) for x in spu_dist]))
        loaded_spu = [(x, spu_dist[x]) for x in xrange(num_spu) if spu_dist[x] >= 3 * average]
        cold_spu = [(x, spu_dist[x]) for x in xrange(num_spu) if spu_dist[x] <= average / 3]
        print('    %d hot SPUs: %s' % (len(loaded_spu), loaded_spu))
        print('    %d cold SPUs: %s' % (len(cold_spu), cold_spu))
    print('\n\n')


def hash_test_patterns(hash=h3, num_spu=None):
    hash_buckets(lab_incremental_tuples, hash, num_spu=num_spu, note=str_lab_incremental_tuples)
    hash_buckets(favored_tuples, hash, num_spu=num_spu, note=str_favored)
    hash_buckets(favored_tuples_1M, hash, num_spu=num_spu, note=str_favored_1M)
    hash_buckets(favored_nat, hash, num_spu=num_spu, note=str_favored_nat)
    hash_buckets(random_tuples, hash, num_spu=num_spu, note=str_random_1M)
    hash_buckets(pure_random_tuples, hash, num_spu=num_spu, note=str_pure_random_1M)
    hash_buckets(None, hash, num_spu=num_spu)


def hash_test_algorithms(tuple_gen=favored_tuples, num_spu=None):
    tuples = [x for x in tuple_gen()]
    # hash_buckets(tuples, h_port_only, num_spu=num_spu, note='byte_XOR(SrcPort ^ DstPort)')
    # hash_buckets(tuples, h2_crc, num_spu=num_spu, note='byte_XOR(crc32(SrcIP ^ DstIP))')
    hash_buckets(tuples, h3, num_spu=num_spu, note='byte_XOR(SrcIP ^ DstIP, proto)')
    # hash_buckets(tuples, h5, num_spu=num_spu, note='byte_XOR(5-tuple)')

t = hash_test_patterns
T = hash_test_algorithms


if __name__ == '__main__':
    T(lab_incremental_tuples, num_spu=8)
    T(favored_tuples, num_spu=8)
    T(favored_tuples_1M, num_spu=8)
    T(favored_nat, num_spu=8)
    T(random_tuples, num_spu=8)
    T(pure_random_tuples, num_spu=8)

    #t(h2_crc)
    #t(h5_crc)
    #t(h5)
    #t(h3)
    #t(h5_16)
    #t(h3_16)
    #t(h_dip)
    #t(h_sip)
    



