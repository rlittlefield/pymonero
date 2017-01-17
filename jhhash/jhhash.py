import math
import functools

def bigend_toint(r):
    return sum(b<<(len(r)-1-i) for i, b in enumerate(r))

def bigend_tobin(d, r):
    assert r < (1<<d)
    return [(r>>(d-1-i))&1 for i in range(d)]

######################################################################

sbox = [
    [9, 0, 4, 11, 13, 12, 3, 15, 1, 10, 2, 6, 7, 5, 8, 14],
    [3, 12, 6, 13, 5, 7, 1, 9, 15, 2, 0, 4, 11, 10, 14, 8]
]

def sbox_layer(c, x):
    assert len(c) == len(x)
    return [sbox[ce][xe] for ce, xe in zip(c, x)]

def gfdouble(a):
    a0, a1, a2, a3 = bigend_tobin(4, a)
    return bigend_toint([a1, a2, a0^a3, a0])

def JH_L(a, b):
    b ^= gfdouble(a)
    a ^= gfdouble(b)
    return (a, b)

JH_L_pre = [[JH_L(a, b) for b in range(16)] for a in range(16)]

def l_layer(x):
    assert len(x) % 2 == 0
    return [e for i in range(0, len(x), 2) for e in JH_L_pre[x[i]][x[i+1]]]

def pi_d(d, i):
    assert i < (1<<d)
    return i ^ ((i>>1) &1)

def p_prime_d(d, i):
    assert i < (1<<d)
    return (i << 1) ^ (i>>(d-1))*(1 | (1<<d))

def phi_d(d, i):
    assert i < (1<<d)
    return i ^ (i >> (d-1))

def p_d(d, i):
    assert i < (1<<d)
    return pi_d(d, p_prime_d(d, phi_d(d, i)))

@functools.lru_cache(maxsize=2048)
def perms_d(d):
    return [p_d(d, i) for i in range(1<<d)]

def permutation(d, x):
    assert len(x) == (1<<d)
    return [x[p] for p in perms_d(d)]

def JH_R(d, c, x):
    assert len(x) == (1<<d)
    assert len(c) == (1<<d)
    return permutation(d, l_layer(sbox_layer(c, x)))

def intsqrt(n):
    r = int(math.sqrt(n))
    while True:
        d = n - r*r
        if d >= 0 and d < 2*r+1:
            return r
        r = (r + n//r)//2

def czero(d):
    return bigend_tobin(1<<d,intsqrt(2**(1 + (2<<d))) - 2**(1<<d))

@functools.lru_cache(maxsize=2048)
def JH_c(d, i):
    assert d >= 4
    if i == 0:
        return czero(d)
    else:
        pr = JH_c(d, i-1)
        prq = [bigend_toint(pr[i:i+4]) for i in range(0, 1<<d, 4)]
        zeroc = [0 for i in range(1<<(d-2))]
        resq = JH_R(d-2, zeroc, prq)
        return [b for rn in resq for b in bigend_tobin(4,rn)]

def eunpack(d, a):
    assert len(a) == (4<<d)
    return [bigend_toint([a[(i>>1)|((i&1)<<(d-1))+(j<<d)]
        for j in range(4)]) for i in range(1<<d)]

def epack(d, q):
    assert len(q) == (1<<d)
    return [bigend_tobin(4,q[(((1<<d)-1)&(i<<1))|(1&(i>>(d-1)))])[i>>d]
        for i in range(4<<d)]

def JH_E(d, a):
    assert len(a) == (4<<d)
    q = eunpack(d, a)
    nrounds = (d-1)*5+1
    for i in range(nrounds):
        if i == nrounds -1:
            q = sbox_layer(JH_c(d, i), q)
        else:
            q = JH_R(d, JH_c(d, i), q)
    return epack(d, q)

def bxor(a, b):
    assert len(a) == len(b)
    return [aa ^ bb for aa, bb in zip(a, b)]

def JH_F(d, h, m):
    assert len(h) == (4<<d)
    assert len(m) == (2<<d)
    p = [0]*(2<<d)
    return bxor(p + m, JH_E(d, bxor(m + p, h)))

def JH_H0(d, l):
    lbits = 16
    assert lbits <= (4<<d)
    return JH_F(d, bigend_tobin(lbits,l) + [0] * ((4<<d)-lbits), [0]*(2<<d))

def JHbits(d, digestlen, m):
    lbits = 128
    assert lbits < (2<<d)
    l = len(m)
    zerobits = (2<<d) + (-l % (2<<d)) - lbits -1
    m = m + [1] + [0] * zerobits + bigend_tobin(lbits, l)
    h = JH_H0(d, digestlen)
    for i in range(0, len(m), (2<<d)):
        h = JH_F(d, h, m[i:i+(2<<d)])
    return h[-digestlen:]

def hashbits(digestlen, m):
    return JHbits(8, digestlen, m)

'''
I modified this function from the original author to return a bytearray
so it can be python3 friendly
'''
def hashbytes(digestlen, m):
    res = JHbits(8, digestlen, [bit for byte in m for bit in bigend_tobin(8,byte)])
    return bytearray(bigend_toint(res[i:i+8]) for i in range(0, len(res), 8))

