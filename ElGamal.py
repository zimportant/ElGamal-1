import random
import sys
import miller_rabin.GenPrime as gp
import miller_rabin.IsPrime as ip
import Euclid
import TextProcessing as Text

ATTEMPTS = 23
ALPHABET = ".,:;!?-'()[]&+=<>/*_$#@^abcdefghijklmnopqrstuvwxyzáàảãạăắằẳẵặâấầẩẫậéèẻẽẹêếềểễệóòỏõọôốồổỗộơớờởỡợíìỉĩịúùủũụưứừửữựýỳỷỹỵđ 0123456789"

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

# tính gcd(a, b) giả sử a > b
def gcd( a, b ):
		while b != 0:
			c = a % b
			a = b
			b = c
		return a

# trả về base^exp mod modulus
def modexp( base, exp, modulus ):
		return pow(base, exp, modulus)



#-----------------------------------------------SINH KHÓA-------------------------------------------------
# tìm một số g là thành phần nguyên thủy của số nguyên tố p
def find_primitive_root(p):
	if p == 2:
		return 1
	p1 = 2
	p2 = (p - 1) // p1
	while( 1 ):
		g = random.randint( 2, p-1 )
		if not (pow( g, (p-1)//p1, p ) == 1):
			if not pow( g, (p-1)//p2, p ) == 1:
				return g

# kiểm tra g có phải là thành phần nguyên thủy của p ko
def is_primitive_root(g, p):
	p1 = 2
	p2 = (p - 1) // p1
	if not (pow( g, (p-1)//p1, p ) == 1):
			if not pow( g, (p-1)//p2, p ) == 1:
				return True
	else:
		return False

# tạo khóa công khai K1 (p, alpha, beta) và khóa bí mật K2 (a)
def generate_keys(numBits=256):
	# p: số nguyên tố
	# alpha: thành phần nguyên tố của p
	# privateKey(a): số ngẫu nhiên trên đoạn (0, p-1)
	p = gp.generatePrime(numBits, ATTEMPTS)
	alpha = find_primitive_root(p)
	privateKey = PrivateKey(random.randint(1, (p - 1)))
	publicKey = PublicKey(p, alpha, privateKey)

	return {'privateKey': privateKey, 'publicKey': publicKey}

# Tạo khóa với p có trước
def generate_key_with_p(p):
	alpha = find_primitive_root(p)
	privateKey = PrivateKey(random.randint(1, (p - 1)))
	publicKey = PublicKey(p, alpha, privateKey)

	return {'privateKey': privateKey, 'publicKey': publicKey}


# kiểm tra một khóa có sẵn
def check_keys(p, g, x):
	if ip.isPrime(p, ATTEMPTS) and is_primitive_root(g, p) and x >=2 and x <= p-2:
		return True
	else:
		return False

#-----------------------------------------MÃ HÓA VÀ GIẢI MÃ------------------------------------------------
# trả về y1
def merge_y1(encryptNums):
	y1 = ""
	for encryptUnit in encryptNums:
		y1 += str(encryptUnit.gety1())
		y1 += "\n"
	return y1
# trả về y2
def merge_y2(encryptNums):
	y2 = ""
	for encryptUnit in encryptNums:
		y2 += str(encryptUnit.gety2())
		y2 += "\n"
	return y2

# chuẩn hóa và chia message thành các đoạn có giá trị < p rồi mã hóa
def encrypt_mess(message, publicKey, alphabet):
	# chuẩn hóa message -> plainText
	plainText = Text.toValidText(message, alphabet)
	cypherNum = []
	unitText = []
	# chia plainText thành các đoạn có giá trị < p
	unitText = Text.splitText(plainText, Text.unitLength(len(alphabet), publicKey.getp()))
	# mã hóa từng đoạn 
	for unit in unitText:
		cypherNum.append(encrypt_unit(unit, publicKey, alphabet))
	return cypherNum

# mã hóa đoạn tin unitText
def encrypt_unit(unitText, publicKey, alphabet):
	x = Text.textToNum(unitText, alphabet)
	# in ra giá trị đoạn unitText được chuyển từ text sang số (chưa mã hóa)
	print("x: ", x)
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
	y1Reverse = Euclid.inverseMod(unitCypher.gety1(), p)
	decryptValue = (unitCypher.gety2() * (modexp(y1Reverse, a, p))) % p
	# in ra giá trị đoạn unitCypher được giải mã (dạng số)
	print("d:", decryptValue)
	decryptText = Text.numToText(decryptValue, alphabet)
	return decryptText


#-----------------------------------------Ký và kiểm tra văn bản được ký------------------------------------------------
# ký văn bản m
def egGen(p, a, x, m):
	while 1:
		k = random.randint(1,p-2)
		if gcd(p-1, k)==1: break
	r = modexp(a,k,p)
	l = Euclid.inverseMod(k, p-1)
	s = l*(m-x*r)%(p-1)
	return r,s


# kiểm tra văn bản được ký
def egVer(p, a,	y, r, s, m):
	if r < 1 or r > p-1 : return False
	v1 = modexp(y,r,p)%p * modexp(r,s,p)%p
	v2 = modexp(a,m,p)
	return v1 == v2


# p = gp.generatePrime(80, 15)
# alpha = find_primitive_root(p)
# privateKey = PrivateKey(20)
# publicKey = PublicKey(p, alpha, privateKey)
# mess = "To prepare for a good night’s sleep we are better off putting the brakes on caffeine consumption as early as 3 p.m"
# print("TEXT")
# e = encrypt_mess(mess, publicKey, ALPHABET)
# print("DECRYPT")
# d = decrypt_mess(e, privateKey, publicKey, ALPHABET)
# print("-----------------------------------------")
# print("TIN BAN ĐẦU: \n", mess)
# print("BÃN GIẢI MÃ: \n", d)
