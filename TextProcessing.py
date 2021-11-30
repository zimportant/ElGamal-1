#------------------------------------Xử lý chuỗi tin đầu vào--------------------------------------
def toValidText(text, alphabet):
	text = text.lower()
	validText = ""
	for c in text:
		# nếu không tìm thấy ký tự c thì hàm find trả về -1
		if (alphabet.find(c) >= 0):
			validText += c
	return validText

def charToInt(char, alphabet):
	# chuyển từ ký tự sang giá trị số tương ứng
	# đếm ký tự đầu của alphabet từ 1
	# để tránh bị mất ký tự khi decrypt
	return alphabet.find(char) + 1

def intToChar(n, alphabet):
	# chuyển từ giá trị n sang ký tự tương ứng trong bảng chữ cái
	# lấy n - 1 vì hàm char_to_int đã trả về:
	# giá trị của mỗi ký tự = vị trí của nó trong alphabet + 1
	n = n % len(alphabet) - 1
	return alphabet[n]

# chuyển 1 đoạn ký tự về 1 số
def textToNum(text, alphabet):
	textLen = len(text)
	base = 1
	num = 0
	for i in range (0, textLen):
		num += charToInt(text[i], alphabet) * base
		base *= len(alphabet)
	return num

# chuyển đổi 1 số về 1 đoạn ký tự
def numToText(num, alphabet):

	text = ""
	length = len(alphabet)
	while(num > length):
		order = num % length
		text += intToChar(order, alphabet)
		num = (num - order) // length
	text += intToChar(num % length, alphabet)
	return text

# tìm độ dài tối đa (số ký tự) cho 1 đoạn tin để giá trị của nó < p
def unitLength(alphabetLength, p):
	result = 0
	while (p > alphabetLength):
		result = result + 1
		p = p // alphabetLength
	return int(result)

# chia text thành các đoạn tin có độ dài length
def splitText(text, length):
	textLen = len(text)
	if (textLen < length):
		return {text}
	chunks = []
	chunks = [text[i: i + length] for i in range (0, textLen, length)]
	print(chunks)
	return chunks