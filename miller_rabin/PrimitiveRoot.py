import random
import IsPrime
import GenPrime

def primitiveRootSearch(p, attempts):
    if (not IsPrime.isPrime(p, attempts)):
        print("Invalid p for primitive root search")
        return -1
    n = p - 1
    factors = findPrimeFactors(n, attempts)
    # Try to find the primitive root by starting at random number
    g = random.randrange(2, n - 1)
    while (not checkPrimitiveRoot(g, p, n, factors)):
        g = g + 1
    return g

def checkPrimitiveRoot(g, p, n, factors):
    for i in factors:
        if (pow(g, n // i, p) == 1):
            return False
    return True

def findPrimeFactors(n, attempts):
    factor_set = set()
    for i in range (2, n):
        while (n % i == 0):
            factor_set.add(i)
            n = n // i
            if (IsPrime.isPrime(n, attempts)):
                return factor_set
    return factor_set
  

pr = GenPrime.generatePrime(12, 7)
print(pr)
print(find_primitive_root(pr))