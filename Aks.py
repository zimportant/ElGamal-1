# Author Zach Trong - UET VNU
from math import log2, gcd, floor
from sympy.ntheory.factor_ import totient
import Crypto.Util.number as number


class Aks(object):
    def __init__(self):
        self.c_coef = [0] * 1_000_000
        pass

    def is_perfect_power(self, n):
        for x in range(2, int(log2(n)) + 1):
            a = n ** (1 / x)
            if a.is_integer():
                return True
        return False

    # find r that ord_r(n) > log2(n)^2
    def find_r(self, n):
        max_k = log2(n) ** 2
        max_r = log2(n) ** 5
        next_r = True
        r = 1

        while next_r:
            r += 1
            next_r = False
            k = 0
            while k <= max_k and not next_r:
                k += 1
                if pow(n, k, r) == 1:
                    next_r = True

        return r

    # a_coef, b_coef = array of coff according to its degree
    # c_coef = a_coef * b_coff mod (n, x^r - 1)
    # will have no more than r elements
    def mul_poly(self, a_coef, b_coef, n, r):
        sz = min(len(a_coef) + len(b_coef) - 1, r)
        for i in range(sz):
            self.c_coef[i] = 0

        for i in range(len(a_coef)):
            for j in range(len(b_coef)):
                # c_coff[i + j] += a_coff[i] * b_coff[j]
                # mod (n, x^r - 1)
                self.c_coef[(i + j) % r] = (self.c_coef[(i + j) % r] + a_coef[i] * b_coef[j]) % n

        return self.c_coef[0:sz]

    # calculate (x + a)^n == x^n + a (mod n, x^r - 1)
    # lhs_coef = (x + a)^n (mod n, x^r - 1)
    # rhs_coef = x^n + a (mod n, x^r - 1)
    def fast_poly(self, a, n, r):
        rhs_coef = [0] * r
        rhs_coef[0] = a
        rhs_coef[n % r] = 1

        base = [a, 1]
        lhs_coef = [1, 0]
        power = n

        while power > 0:
            print("power, lhs_coef, base:", power, len(lhs_coef), len(base))
            if power % 2 == 1:
                lhs_coef = self.mul_poly(lhs_coef, base, n, r)
            base = self.mul_poly(base, base, n, r)
            power //= 2

        eq_coef = [lhs_coef[i] - rhs_coef[i] for i in range(r)]
        return eq_coef

    def is_prime(self, n):
        if self.is_perfect_power(n):
            return False

        r = self.find_r(n)
        for a in range(2, min(r, n)):
            if gcd(a, n) > 1:
                return False

        if n <= r:
            return True

        for a in range(1, floor((totient(r) ** (1 / 2)) * log2(n))):
            print("a, n, r:", a, n, r)
            x = self.fast_poly(a, n, r)
            if any(x):
                return False

        return True
