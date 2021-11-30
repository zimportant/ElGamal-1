# find a^-1 mod b
def inverseMod( a, b ):
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