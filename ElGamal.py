import random
import sys
from tkinter.constants import X
import miller_rabin.GenPrime as gp
import miller_rabin.IsPrime as ip

ATTEMPTS = 23
ALPHABET = " abcdefjhijklmnopqrstuvwxyz0123456789"

class PrivateKey(object):
	def __init__(self, a):
		self.a = a
	
	def getvalue(self):
		return self.a

class PublicKey(object):
	def __init__(self, p, alpha, privateKey):
		self.p = p
		self.alpha = alpha
		self.beta = modexp(alpha, privateKey.getvalue(), p)

	def getp(self):
		return self.p
	
	def getalpha(self):
		return self.alpha

	def getbeta(self):
		return self.beta

class CypherNum(object):
	def __init__(self, y1, y2):
		self.y1 = y1
		self.y2 = y2

	def gety1(self):
		return self.y1 
	
	def gety2(self):
		return self.y2

def euclid( a, b ):
	tempB = b
	x1 = 0
	y1 = 1
	x2 = 1
	y2 = 0
	while b > 0:
		q = a // b
		r = a - b * q
		a = b
		b = r
		x = x2 - x1 * q
		x2 = x1
		x1 = x 
		y = y2 - y1 * q 
		y2 = y1 
		y1 = y 
	if x2 < 0:
		return x2 + tempB 
	else:
		return x2

	return a

# trả về base^exp mod modulus
def modexp( base, exp, modulus ):
		return pow(base, exp, modulus)

# tìm một số g là thành phần nguyên thủy của số nguyên tố p
def find_primitive_root(p):
	if p == 2:
		return 1

	while( 1 ):
		g = random.randint( 2, p-1 )
		if check_primitive_root(g, p):
			return g

# kiểm tra căn nguyên thủy g mô-đun p với p là "số nguyên tố an toàn"
def check_primitive_root(g, p):
	if p == 2:
		return g == 1

	p1 = 2
	p2 = (p - 1) // p1
	
	if not (pow( g, (p-1)//p1, p ) == 1):
		if not pow( g, (p-1)//p2, p ) == 1:
			return True

	return False


# tạo khóa công khai K1 (p, alpha, beta) và khóa bí mật K2 (a)
def generate_random_keys(numBits=256):
	# p: số nguyên tố
	# alpha: thành phần nguyên tố của p
	# privateKey(a): số ngẫu nhiên trên đoạn (0, p-1)
	p = gp.generatePrime(numBits, ATTEMPTS)
	alpha = find_primitive_root(p)
	privateKey = PrivateKey(random.randint(1, (p - 1)))
	publicKey = PublicKey(p, alpha, privateKey)

	return {'privateKey': privateKey, 'publicKey': publicKey}

# Tạo khóa với p có trước
def generate_key(p):
	alpha = find_primitive_root(p)
	privateKey = PrivateKey(random.randint(1, (p - 1)))
	publicKey = PublicKey(p, alpha, privateKey)

	return {'privateKey': privateKey, 'publicKey': publicKey}

#---------------------------------------STRING TO NUMBER--------------------------------------
def to_valid_text(text, alphabet):
	text = text.lower()
	validText = ""
	for c in text:
		if (alphabet.find(c) >= 0):
			validText += c
	return validText

def char_to_int(char, alphabet):
	return alphabet.find(char)

def int_to_char(n, alphabet):
	n = n % len(alphabet)
	return alphabet[n]

def text_to_num(text, alphabet):
	textLen = len(text)
	base = 1
	num = 0
	for i in range (0, textLen):
		num += char_to_int(text[i], alphabet) * base
		base *= len(alphabet)
	return num

def num_to_text(num, alphabet):
	text = ""
	length = len(alphabet)
	while(num > length):
		order = num % length
		text += int_to_char(order, alphabet)
		num = (num - order) // length
	text += int_to_char(num % length, alphabet)
	return text

def unitLength(alphabetLength, p):
	result = 0
	while (p > alphabetLength):
		result = result + 1
		p = p // alphabetLength
	return int(result)

def split_text(text, length):
	textLen = len(text)
	if (textLen < length):
		return {text}
	chunks = []
	chunks = [text[i: i + length] for i in range (0, textLen, length)]
	return chunks

#--------------------------------------------------------------------------------------------------
# chuẩn hóa và chia message thành các đoạn có giá trị < p rồi mã hóa
def encrypt_mess(message, publicKey, alphabet):
	plainText = to_valid_text(message, alphabet)
	cypherNum = []
	unitText = []
	unitText = split_text(plainText, unitLength(len(alphabet), publicKey.getp()))
	for unit in unitText:
		cypherNum.append(encrypt_unit(unit, publicKey, alphabet))
	return cypherNum

# mã hóa đoạn tin unitText
def encrypt_unit(unitText, publicKey, alphabet):
	x = text_to_num(unitText, alphabet)
	print(x)
	return encrypt_num(x, publicKey)
	
# mã hóa đoạn tin có giá trị int = x 
def encrypt_num(x, publicKey):
	p = publicKey.getp()
	alpha = publicKey.getalpha()
	beta = publicKey.getbeta()
	k = random.randrange(1, p - 2)

	y1 = modexp(alpha, k, p)
	y2 = (x * modexp(beta, k, p)) % p
	return CypherNum(y1, y2)

# giải mã với các cặp mã hóa cipherNums
def decrypt_mess(cypherNums, privateKey, publicKey, alphabet):
	decryptMess = ""
	for unit in cypherNums:
		decryptMess += decrypt_unit(unit, privateKey, publicKey, alphabet)
	return decryptMess

# giải mã 1 cặp mã hóa 
def decrypt_unit(unitCypher, privateKey, publicKey, alphabet):
	p = publicKey.getp()
	a = privateKey.getvalue()
	y1Reverse = euclid(unitCypher.gety1(), p)
	decryptValue = (unitCypher.gety2() * (modexp(y1Reverse, a, p))) % p
	print("d:", decryptValue)
	decryptText = num_to_text(decryptValue, alphabet)
	return decryptText


p = gp.generatePrime(80, 15)
alpha = find_primitive_root(p)
privateKey = PrivateKey(20)
publicKey = PublicKey(p, alpha, privateKey)
mess = "To prepare for a good night’s sleep we are better off putting the brakes on caffeine consumption as early as 3 p.m"
print("TEXT")
e = encrypt_mess(mess, publicKey, ALPHABET)
print("DECRYPT")
d = decrypt_mess(e, privateKey, publicKey, ALPHABET)
print("-----------------------------------------")
print("TIN BAN ĐẦU: \n", mess)
print("BÃN GIẢI MÃ: \n", d)