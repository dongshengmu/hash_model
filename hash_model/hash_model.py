#!/usr/bin/env python
"""
" hash_model - model flow hash distribution
"
" Created by Dongsheng Mu on 10/5/12.
" Copyright 2012 Dongsheng Mu. All rights reserved.
"""

import random

ip_start = random.randint(0x10000001, 0xffffff00)
favored_ip = [x for x in xrange(ip_start, ip_start + 0x1F)]
port_start = random.randint(1, 0xFF00)
favored_port = range(port_start, port_start + 0x0005)
nat_port = range(1, 0x0FFF)
dst_ip = [0x4a7d816a, 0x481e268c]   # google, yahoo
dst_port = [0x80]       # http
ip_protocol_type = [6]  # tcp, udp
favored_tuples = [(S, D, p, s, d)
                  for S in favored_ip
                  for D in dst_ip
                  for p in ip_protocol_type
                  for s in (nat_port if (S == favored_ip[0]) else favored_port)
                  for d in dst_port]
str_favored = ("%s favored tuples, 2 fat NAT (31 src-ip, 4 src_port, 1 PNAT-4K, 1 dst-ip, 1 dst-port, 1 protocols)"
               % len(favored_tuples))
#print(favored_tuples[:10])

ip_start2 = random.randint(0x10000001, 0xffffff00)
favored_ip2 = [x for x in xrange(ip_start2, ip_start2 + 0xFF)]
port_start2 = random.randint(1, 0xFF00)
favored_port2 = range(port_start2, port_start + 0x0008)
nat_port2 = range(1, 0xFFFF)
#dst_ip2 = [0x4a7d816a, 0x481e268c, 0x45abf715]   # google, yahoo, facebook
dst_ip2 = random.sample(xrange(0x40000000, 0x4FFFFFFF), 3)
dst_port2 = [0x80, 0x8080, 0x8081, 22, 23]       # http
ip_protocol_type2 = [6, 17]  # tcp, udp
favored_tuples_1M = [(S, D, p, s, d)
                     for S in favored_ip2
                     for D in dst_ip2
                     for p in ip_protocol_type2
                     for s in (nat_port2 if (S == favored_ip2[0]) else favored_port2)
                     for d in dst_port2]

str_favored_1M = ("%s favored tuples, 6 fat NAT (255 src-ip, 8 src_port, 1 PNAT-64K, 3 dst-ip, 5 dst-port, 2 protocols)"
                  % len(favored_tuples_1M))
#print(favored_tuples_1M[:10])


rS = random.sample(xrange(0xFFFFFFFF), 100)
rD = random.sample(xrange(0xFFFFFFFF), 100)
rp = random.sample(xrange(0xFF), 1)
rs = [random.sample(xrange(0xFFFF), num_ports) for num_ports in random.sample(xrange(100), 100)]
rd = [random.sample(xrange(0xFFFF), num_ports) for num_ports in random.sample(xrange(5), 5)]
random_tuples = [(S, D, p, s, d)
                 for S in rS
                 for D in rD
                 for p in rp
                 for s in rs[S % 100]
                 for d in rd[D % 5]]
str_random_1M = ("%s random tuples, (100 src-ip, 10 dst-ip, 1 protocol, ip pair with 0-100 random num of random src-ip, 0-5 dst-ip)" % len(random_tuples))
#print(random_tuples[:10])


def hash_algorithm(tuple=None, prime=False, all_keys=True, num_bits=8):
    if tuple == None:
        name = ('%d-tuple hash: hash-bucket-size %d, multiply-prime-num %s'
                % (5 if all_keys else 3, 2 ** num_bits, prime))
        #print('hash_algorithm: multiply-prime-num %s, num-of-tuple-used %d, hash-result-bits %d, hash-bucket-size %d'
        #  % (prime, 5 if all_keys else 3, num_bits, 2 ** num_bits))
        return (name, 2 ** num_bits)
    
    (S, D, p, s, d) = tuple
    if (prime):
        S *= 263
        D *= 263
        p *= 13
        s *= 37
        d *= 37
    
    mask = (2 ** num_bits) - 1
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

accumulated_buckets = {}
def calc_bucket_dist(tuples, hash, hash_name, bucket_size):
    global accumulated_buckets
    bucket_dist = [0] * bucket_size
    num = len(tuples)
    for i in xrange(num):
        h = hash(tuples[i])
        bucket_dist[h] += 1
    
    # accumulate the bucket_dist
    if hash_name in accumulated_buckets:
        a = accumulated_buckets[hash_name]
        for i in xrange(bucket_size):
            a[i] += bucket_dist[i]
    else:
        accumulated_buckets[hash_name] = [x for x in bucket_dist]
    return bucket_dist

def hash_buckets(tuples, hash, num_spu=None, note=None):
    hash_name, bucket_size = hash(None)
    
    print('%s\n%s' % (hash_name, '=' * len(hash_name)))
    if note:
        print('*** hash result for %s' % note)
    
    if tuples:
        bucket_dist = calc_bucket_dist(tuples, hash, hash_name, bucket_size)
        total_tuples = len(tuples)
    else:
        bucket_dist = accumulated_buckets[hash_name]
        total_tuples = sum(bucket_dist)
        print('*** Accumulated hash result for %d tuples:' % total_tuples)
    
    #print('total num of tuples %d, hashed %d\n' % (num, t))
    average_bucket = total_tuples / float(bucket_size)
    print('%d bucket distribution: max %d (%s), min %d (%s), average %d, bucket_size %d, empty_buckets: %d'
          % (bucket_size,
             max(bucket_dist), round((max(bucket_dist) * 100.0)/average_bucket, 2),
             min(bucket_dist), round((min(bucket_dist) * 100.0)/average_bucket, 2),
             int(average_bucket), bucket_size, len([x for x in bucket_dist if x == 0])))
    #print('%s\n' % bucket_dist)
    heavy_loaded = [(x, bucket_dist[x]) for x in xrange(bucket_size) if bucket_dist[x] >= 3 * average_bucket]
    cold_buckets = [(x, bucket_dist[x]) for x in xrange(bucket_size) if bucket_dist[x] <= average_bucket / 3]
    print('  %d hot buckets: %s' % (len(heavy_loaded), heavy_loaded[:20]))
    print('  %d cold buckets: %s' % (len(cold_buckets), cold_buckets[:20]))
    
    
    # SPU distribution
    typical_install = [num_spu] if num_spu else [3, 7, 11, 31, 39]
    for num_spu in typical_install:
        spu_dist = []
        for i in xrange(num_spu):
            spu_dist.append(sum([bucket_dist[x] for x in xrange(bucket_size) if x % num_spu == i]))
        
        average = total_tuples / float(num_spu)
        print('%d spu distribution: max %d (%s), min %d (%s), average %d, num_spu %d, idle_spu %d\n  %s\n  %s'
              % (num_spu,
                 max(spu_dist), round((max(spu_dist) * 100.0)/average, 2),
                 min(spu_dist), round((min(spu_dist) * 100.0)/average, 2),
                 int(average), num_spu, len([x for x in spu_dist if x == 0]),
                 spu_dist, [round((x * 100.0)/average, 2) for x in spu_dist]))
        loaded_spu = [(x, spu_dist[x]) for x in xrange(num_spu) if spu_dist[x] >= 3 * average]
        cold_spu = [(x, spu_dist[x]) for x in xrange(num_spu) if spu_dist[x] <= average / 3]
        print('  %d hot SPUs: %s' % (len(loaded_spu), loaded_spu))
        print('  %d cold SPUs: %s' % (len(cold_spu), cold_spu))
    print('\n\n')


def hash_test(hash=h3, num_spu=None):
    hash_buckets(favored_tuples, hash, num_spu=num_spu, note=str_favored)
    hash_buckets(favored_tuples_1M, hash, num_spu=num_spu, note=str_favored_1M)
    hash_buckets(random_tuples, hash, num_spu=num_spu, note=str_random_1M)
    hash_buckets(None, hash, num_spu=num_spu)


t = hash_test


if __name__ == '__main__':
    t(h3)
    t(h3_16)
    t(h5)
    t(h5_16)



