"""ML-KEM-768 (FIPS 203), written from the standard for the tests: the
reference src/crypto/mlkem.inc is checked against, byte for byte. Slow
and plain on purpose; only encapsulation and what it needs, plus key
generation and decapsulation to close the loop."""
import hashlib

Q, N, K, ETA1, ETA2, DU, DV = 3329, 256, 3, 2, 2, 10, 4


def bitrev7(x):
    return int(f"{x:07b}"[::-1], 2)


ZETAS = [pow(17, bitrev7(i), Q) for i in range(128)]
GAMMAS = [pow(17, 2 * bitrev7(i) + 1, Q) for i in range(128)]


def H(b):
    return hashlib.sha3_256(b).digest()


def G(b):
    d = hashlib.sha3_512(b).digest()
    return d[:32], d[32:]


def J(b):
    return hashlib.shake_256(b).digest(32)


def PRF(eta, s, b):
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def byte_encode(f, d):
    bits = []
    for a in f:
        bits += [(a >> i) & 1 for i in range(d)]
    return bytes(sum(bits[8 * i + j] << j for j in range(8)) for i in range(len(bits) // 8))


def byte_decode(b, d):
    bits = [(b[i // 8] >> (i % 8)) & 1 for i in range(8 * len(b))]
    m = Q if d == 12 else 1 << d
    return [sum(bits[i * d + j] << j for j in range(d)) % m for i in range(N)]


def compress(x, d):
    return ((x << (d + 1)) + Q) // (2 * Q) % (1 << d)


def decompress(y, d):
    return ((y * Q << 1) + (1 << d)) >> (d + 1)


def sample_ntt(b):
    stream = hashlib.shake_128(b).digest(168 * 6)
    a, i = [], 0
    while len(a) < N:
        c0, c1, c2 = stream[i], stream[i + 1], stream[i + 2]
        i += 3
        d1 = c0 + 256 * (c1 % 16)
        d2 = c1 // 16 + 16 * c2
        if d1 < Q:
            a.append(d1)
        if d2 < Q and len(a) < N:
            a.append(d2)
    return a


def cbd(b, eta):
    bits = [(b[i // 8] >> (i % 8)) & 1 for i in range(8 * len(b))]
    return [(sum(bits[2 * i * eta + j] for j in range(eta))
             - sum(bits[2 * i * eta + eta + j] for j in range(eta))) % Q for i in range(N)]


def ntt(f):
    f = list(f)
    i, ln = 1, 128
    while ln >= 2:
        for start in range(0, N, 2 * ln):
            z = ZETAS[i]
            i += 1
            for j in range(start, start + ln):
                t = z * f[j + ln] % Q
                f[j + ln] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        ln //= 2
    return f


def intt(f):
    f = list(f)
    i, ln = 127, 2
    while ln <= 128:
        for start in range(0, N, 2 * ln):
            z = ZETAS[i]
            i -= 1
            for j in range(start, start + ln):
                t = f[j]
                f[j] = (t + f[j + ln]) % Q
                f[j + ln] = z * (f[j + ln] - t) % Q
        ln *= 2
    return [x * 3303 % Q for x in f]


def mul_ntt(a, b):
    c = [0] * N
    for i in range(128):
        a0, a1, b0, b1 = a[2 * i], a[2 * i + 1], b[2 * i], b[2 * i + 1]
        c[2 * i] = (a0 * b0 + a1 * b1 * GAMMAS[i]) % Q
        c[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return c


def add(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


def matrix(rho):
    """A[i][j] = SampleNTT(rho | j | i)."""
    return [[sample_ntt(rho + bytes([j, i])) for j in range(K)] for i in range(K)]


def pke_keygen(d):
    rho, sigma = G(d + bytes([K]))
    a = matrix(rho)
    s = [ntt(cbd(PRF(ETA1, sigma, i), ETA1)) for i in range(K)]
    e = [ntt(cbd(PRF(ETA1, sigma, K + i), ETA1)) for i in range(K)]
    t = [e[i] for i in range(K)]
    for i in range(K):
        for j in range(K):
            t[i] = add(t[i], mul_ntt(a[i][j], s[j]))
    ek = b"".join(byte_encode(t[i], 12) for i in range(K)) + rho
    dk = b"".join(byte_encode(s[i], 12) for i in range(K))
    return ek, dk


def pke_encrypt(ek, m, r):
    t = [byte_decode(ek[384 * i:384 * (i + 1)], 12) for i in range(K)]
    rho = ek[384 * K:]
    a = matrix(rho)
    y = [ntt(cbd(PRF(ETA1, r, i), ETA1)) for i in range(K)]
    e1 = [cbd(PRF(ETA2, r, K + i), ETA2) for i in range(K)]
    e2 = cbd(PRF(ETA2, r, 2 * K), ETA2)
    u = []
    for i in range(K):
        acc = [0] * N
        for j in range(K):
            acc = add(acc, mul_ntt(a[j][i], y[j]))
        u.append(add(intt(acc), e1[i]))
    mu = [decompress(x, 1) for x in byte_decode(m, 1)]
    acc = [0] * N
    for j in range(K):
        acc = add(acc, mul_ntt(t[j], y[j]))
    v = add(add(intt(acc), e2), mu)
    c1 = b"".join(byte_encode([compress(x, DU) for x in u[i]], DU) for i in range(K))
    c2 = byte_encode([compress(x, DV) for x in v], DV)
    return c1 + c2


def pke_decrypt(dk, c):
    u = [[decompress(x, DU) for x in byte_decode(c[320 * i:320 * (i + 1)], DU)] for i in range(K)]
    v = [decompress(x, DV) for x in byte_decode(c[320 * K:], DV)]
    s = [byte_decode(dk[384 * i:384 * (i + 1)], 12) for i in range(K)]
    acc = [0] * N
    for i in range(K):
        acc = add(acc, mul_ntt(s[i], ntt(u[i])))
    w = [(x - y) % Q for x, y in zip(v, intt(acc))]
    return byte_encode([compress(x, 1) for x in w], 1)


def ek_valid(ek):
    """The encapsulation key checks (FIPS 203 7.2): its length, and every
    coefficient below q."""
    if len(ek) != 384 * K + 32:
        return False
    return all(byte_encode(byte_decode(ek[384 * i:384 * (i + 1)], 12), 12) == ek[384 * i:384 * (i + 1)]
               for i in range(K))


def keygen(d, z):
    ek, dkp = pke_keygen(d)
    return ek, dkp + ek + H(ek) + z


def encaps(ek, m):
    """(shared secret, ciphertext), the randomness m given."""
    k, r = G(m + H(ek))
    return k, pke_encrypt(ek, m, r)


def decaps(dk, c):
    dkp, ek, h, z = dk[:384 * K], dk[384 * K:768 * K + 32], dk[768 * K + 32:768 * K + 64], dk[768 * K + 64:]
    m = pke_decrypt(dkp, c)
    k, r = G(m + h)
    kbar = J(z + c)
    return k if pke_encrypt(ek, m, r) == c else kbar
