# Source: https://www.geeksforgeeks.org/primality-test-set-3-miller-rabin/?ref=lbp 
# Python3 program Miller-Rabin primality test
import random
 
# Utility function to do modular exponentiation.
# It returns (x^y) % p
def power(x, y, p):
     
    # Initialize result
    res = 1;
     
    # Update x if it is more than or equal to p
    x = x % p;
    while (y > 0):
         
        # If y is odd, multiply x with result
        if (y & 1):
            res = (res * x) % p;
 
        # y must be even now
        y = y>>1; # y = y/2
        x = (x * x) % p;
     
    return res;
 
# This function is called for all k trials. It returns
# false if n is composite and
# returns false if n is
# probably prime. d is an odd
# number such that d*2<sup>r</sup> = n-1
# for some r >= 1
def millerTest(d, n):
     
    # Pick a random number in [2..n-2]
    # Corner cases make sure that n > 4
    a = 2 + random.randint(1, n - 4);
 
    # Compute a^d % n
    x = power(a, d, n);
 
    if (x == 1 or x == n - 1):
        return True;
 
    # Keep squaring x while one
    # of the following doesn't
    # happen
    # (i) d does not reach n-1
    # (ii) (x^2) % n is not 1
    # (iii) (x^2) % n is not n-1
    while (d != n - 1):
        x = (x * x) % n;
        d *= 2;
 
        if (x == 1):
            return False;
        if (x == n - 1):
            return True;
 
    # Return composite
    return False;
 
# It returns false if n is composite and returns true if n is probably prime
# k is an input parameter that determines accuracy level. 
# Higher value of k indicates more accuracy.
def isPrime( n, k):
     
    # Corner cases
    if (n <= 1 or n == 4):
        return False;
    if (n <= 3):
        return True;
 
    # Find r such that n =
    # 2^d * r + 1 for some r >= 1
    d = n - 1;
    while (d % 2 == 0):
        d //= 2;
 
    # Iterate given nber of 'k' times
    for i in range(k):
        if (millerTest(d, n) == False):
            return False;
 
    return True;

# Driver Code
# Number of iterations

prime = isPrime(777794613755110717309859924959968295263543997507727851073674222283048411552406632043735830364794908317894769511802431335009779604202073690338068283732465871454481497408176551130504847510575522101718311697582531674195544458368767944497824633930959985993428986067753565954424952196025531712919404073235, 5)
print(prime)

# This code is contributed by mits