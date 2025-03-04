"""

This code created by Dexizer

It will recover Ecdsa Secp256K1 private key up to 256 bits and with up to 250 bits k nonces.

"""

import random

p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
K = GF(p)
a = K(0x0000000000000000000000000000000000000000000000000000000000000000)
b = K(0x0000000000000000000000000000000000000000000000000000000000000007)
E = EllipticCurve(K, (a, b))
G = E(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
E.set_order(0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 * 0x1)

q = E.order()

def identityPlus2(u, elem=1):
	result = [[0] * (u + 2) for _ in range(u)]
	
	for i in range(u):
		result[i][i] = elem
	
	return result

def basis():
	matrix = identityPlus2(len(signatures), q)
	
	t = []
	
	for signature in signatures:
		t.append(signature[0] * pow(signature[1], -1, q))
	
	t.append(B / q)
	t.append(0)
	
	a = []
	
	for signature in signatures:
		a.append(signature[2] * pow(signature[1], -1, q))
	
	a.append(0)
	a.append(B)
	
	
	matrix.append(t)
	matrix.append(a)

	return Matrix(QQ, matrix)

def attack():
	M = basis()
	
	positiveKeys = []
	unPositiveKeys = []
	
	for r in M.LLL():
		for key in r:
			key = int(key)
		
			if key != 0 and key != q:
				if key > 0:
					positiveKeys.append(key)
				else:
					unPositiveKeys.append(key)

	recoveredPrivateKey = 0
	
	for key in positiveKeys:	
		for signature in signatures:
			if key != 0:
				d = (signature[1] * Mod(key, q) - signature[2]) * pow(signature[0], -1, q)

				if d == secret:
					recoveredPrivateKey = d
	
	if recoveredPrivateKey == 0:
		k = M.LLL()[1][0]
	
		if k != 0:
			recoveredPrivateKey = (signatures[0][1] * Mod(k, q) - signatures[0][2]) * pow(signatures[0][0], -1, q)

	return recoveredPrivateKey

num = 200

secret = random.randrange(1, q)

print('Private Key:', secret)

kbits = 250

B = 2 ** 249

z = [random.getrandbits(256) for i in range(num)]
nonces = [random.getrandbits(kbits) for i in range(num)]
sigsR = [int((G * int(nonces[i])).xy()[0]) for i in range(num)]
modInvNonces = [pow(nonces[i], -1, q) for i in range(num)]
sigsS = [(z[i] + secret * sigsR[i]) * modInvNonces[i] % q for i in range(num)]
sinv = [pow(s, -1, q) for s in sigsS]

signatures = []

for i in range(len(sigsR)):
	signatures.append([sigsR[i], sigsS[i], z[i]])

d = attack()

print()
print('Recovered Private Key:', d)

if d == secret:
	print()
	print('Private Key Found!!!')
	print('Private Key Successfully Recovered:', d)

