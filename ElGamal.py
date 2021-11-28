import random
import sys
from tkinter import constants
import miller_rabin.GenPrime as gp
import miller_rabin.IsPrime as ip

ATTEMPTS = 23

class PrivateKey(object):
	def __init__(self, p=None, g=None, x=None, iNumBits=0):
		self.p = p
		self.g = g
		self.x = x
		self.iNumBits = iNumBits

class PublicKey(object):
	def __init__(self, p=None, g=None, h=None, iNumBits=0):
		self.p = p
		self.g = g
		self.h = h
		self.iNumBits = iNumBits

def gcd( a, b ):
		while b != 0:
			c = a % b
			a = b
			b = c
		return a

# trả về base^exp mod modulus
def modexp( base, exp, modulus ):
		return pow(base, exp, modulus)

# tìm một số g là thành phần nguyên thủy của số nguyên tố p
def find_primitive_root(p):
	if p == 2:
		return 1
	# p-1 = 2 * (p-1)/2
	p1 = 2
	p2 = (p-1) // p1
	while( 1 ):
		g = random.randint( 2, p-1 )
		if not (pow( g, (p-1)//p1, p ) == 1):
			if not pow( g, (p-1)//p2, p ) == 1:
				return g

# mã hóa message bytes --> integers
def encode(sPlaintext, iNumBits):
		byte_array = bytearray(sPlaintext, 'utf-16')
		z = []
		k = iNumBits//8
		j = -1 * k
		num = 0

		for i in range( len(byte_array) ):
				if i % k == 0:
						j += k
						num = 0
						z.append(0)
				z[j//k] += byte_array[i]*(2**(8*(i%k)))

		# ví dụ
		# 		n = 24, k = n / 8 = 3
		# 		z[0] = (tổng từ i = 0 đến i = k)m[i]*(2^(8*i))
		# 		m[i] byte thứ i của tin nhắn is

		return z

# giải mã integers -->  message bytes
def decode(aiPlaintext, iNumBits):
	bytes_array = []

	k = iNumBits//8

	for num in aiPlaintext:
		for i in range(k):
			temp = num
			for j in range(i+1, k):
				temp = temp % (2**(8*j))
			letter = temp // (2**(8*i))
			bytes_array.append(letter)
			num = num - (letter*(2**(8*i)))

		# example
		# if "You" were encoded.
		# Letter        #ASCII
		# Y              89
		# o              111
		# u              117
		# if the encoded integer is 7696217 and k = 3
		# m[0] = 7696217 % 256 % 65536 / (2^(8*0)) = 89 = 'Y'
		# 7696217 - (89 * (2^(8*0))) = 7696128
		# m[1] = 7696128 % 65536 / (2^(8*1)) = 111 = 'o'
		# 7696128 - (111 * (2^(8*1))) = 7667712
		# m[2] = 7667712 / (2^(8*2)) = 117 = 'u'

	decodedText = bytearray(b for b in bytes_array).decode('utf-16')
	return decodedText

# tạo khóa công khai K1 (p, g, h) và khóa bí mật K2 (p, g, x)
def generate_keys(iNumBits=256):
		# p: số nguyên tố
		# g: thành phần nguyên tố của p
		# x: số ngẫu nhiên trên đoạn (0, p-1)
		# h = g ^ x mod p
		p = gp.generatePrime(iNumBits, ATTEMPTS)
		g = find_primitive_root(p)
		g = modexp( g, 2, p )
		x = random.randint( 1, (p - 1) // 2 )
		h = modexp( g, x, p )

		publicKey = PublicKey(p, g, h, iNumBits)
		privateKey = PrivateKey(p, g, x, iNumBits)

		return {'privateKey': privateKey, 'publicKey': publicKey}

# def is_iNumBits_primeNumber(p, iNumBits):
# 	return true if p is a prime number and number of bits of p == iNumBits

# def is_primitive_root(g, p):
# 	return true if g is primitive root of p



# mã hóa bản tin sPlaintext với khóa key
def encrypt(key, sPlaintext):
		z = encode(sPlaintext, key.iNumBits)

		# cipher_pairs sẽ gồm các cặp (c, d) ứng với mỗi số nguyên trong mảng z
		cipher_pairs = []
		
		for i in z:
				# y: số ngẫu nhiên trên đoạn (0, p-1)
				y = random.randint( 0, key.p )
				# c = g^y mod p
				c = modexp( key.g, y, key.p )
				# d = ih^y mod p
				d = (i*modexp( key.h, y, key.p)) % key.p
				# thêm cặp (c, d) vào list cipher_pairs
				cipher_pairs.append( [c, d] )

		encryptedStr = ""
		for pair in cipher_pairs:
				encryptedStr += str(pair[0]) + ' ' + str(pair[1]) + ' '
	
		return encryptedStr


# giải mã với cặp mã hóa cipher với khóa bí mật key
def decrypt(key, cipher):
		plaintext = []

		cipherArray = cipher.split()
		if (not len(cipherArray) % 2 == 0):
				return "Malformed Cipher Text"
		for i in range(0, len(cipherArray), 2):
				c = int(cipherArray[i])
				d = int(cipherArray[i+1])

				# s = c^x mod p
				s = modexp( c, key.x, key.p )
				# plaintext integer = ds^-1 mod p
				plain = (d*modexp( s, key.p-2, key.p)) % key.p
				
				plaintext.append( plain )

		decryptedText = decode(plaintext, key.iNumBits)

		# loại bỏ bytes null
		decryptedText = "".join([ch for ch in decryptedText if ch != '\x00'])

		return decryptedText

# hàm kiểm tra
def test(message):
		assert (sys.version_info >= (3,4))
		keys = generate_keys()
		priv = keys['privateKey']
		pub = keys['publicKey']
		cipher = encrypt(pub, message)
		plain = decrypt(priv, cipher)
		return message == plain