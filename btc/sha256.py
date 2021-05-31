#inspired by the karpathy/cryptos code

"""
n = Number of bits to be rotated or shifted when a word is operated upon.
w = word size"""

import math
from itertools import count, islice

def ch(x, y, z):
    return (x & y)^ (~x & z)

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def rotr(x, n, size=32):
    return (x >> n) | (x << size - n) & (2**size - 1)

def shr(x, n):
    return x >> n

def sig0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)

def sig1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)

def omega0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def omega1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def b2i(b):
    return int.from_bytes(b, 'big')

def i2b(i):
    return i.to_bytes(4, 'big')


def is_prime(n):
    return not any(f for f in range(2,int(math.sqrt(n))+1) if n%f == 0)

def first_n_primes(n):
    return islice(filter(is_prime, count(start=2)), n)

def frac_bin(f, n=32):
    """ return the first n bits of fractional part of float f """
    f -= math.floor(f) # get only the fractional part
    f *= 2**n # shift left
    f = int(f) # truncate the rest of the fractional content
    return f

def generateK():

    return [frac_bin(p ** (1/3.0)) for p in first_n_primes(64)]

def generateHash():

    return [frac_bin(p ** (1/2.0)) for p in first_n_primes(8)]

def padding(b):

    b = bytearray(b) # convert to a mutable equivalent
    l = len(b) * 8 # note: len returns number of bytes not bits

    # append but "1" to the end of the message
    b.append(0x80)

    # follow by k zero bits, where k is the smallest non-negative solution to
    # l + 1 + k = 448 mod 512
    # i.e. pad with zeros until we reach 448 (mod 512)
    while (len(b)*8) % 512 != 448:
        b.append(0x00)

    # the last 64-bit block is the length l of the original message
    # expressed in binary (big endian)
    b.extend(l.to_bytes(8, 'big'))

    return b

def sha256(b: bytes) -> bytes:

    # Section 4.2
    K = generateK()
    b = padding(b)
    # Section 5.2: Separate the message into blocks of 512 bits (64 bytes)
    blocks = [b[i:i+64] for i in range(0, len(b), 64)]
    H = generateHash() # Section 5.3

    # Section 6
    for M in blocks: # each block is a 64-entry array of 8-bit bytes
        # 1. Prepare the message schedule, a 64-entry array of 32-bit words
        W = []
        for t in range(64):
            if t <= 15:
                # the first 16 words are just a copy of the block
                W.append(bytes(M[t*4:t*4+4]))
            else:
                term1 = sig1(b2i(W[t-2]))
                term2 = b2i(W[t-7])
                term3 = sig0(b2i(W[t-15]))
                term4 = b2i(W[t-16])
                total = (term1 + term2 + term3 + term4) % 2**32
                W.append(i2b(total))

        # 2. Initialize the 8 working variables a,b,c,d,e,f,g,h with prev hash value
        a, b, c, d, e, f, g, h = H

        # 3.
        for t in range(64):
            T1 = (h + omega1(e) + ch(e, f, g) + K[t] + b2i(W[t])) % 2**32
            T2 = (omega0(a) + maj(a, b, c)) % 2**32
            h = g
            g = f
            f = e
            e = (d + T1) % 2**32
            d = c
            c = b
            b = a
            a = (T1 + T2) % 2**32

        # 4. Compute the i-th intermediate hash value H^i
        delta = [a, b, c, d, e, f, g, h]
        H = [(i1 + i2) % 2**32 for i1, i2 in zip(H, delta)]

    return b''.join(i2b(i) for i in H)

if __name__ == '__main__':
    import sys
    assert len(sys.argv) == 2, "Pass in exactly one filename to return checksum of"
    with open(sys.argv[1], 'rb') as f:
        print(sha256(f.read()).hex())
