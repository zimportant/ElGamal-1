import unittest

import miller_rabin.GenPrime as gp
import miller_rabin.IsPrime as ip
import Crypto.Util.number as number

class TestElGamalMethods(unittest.TestCase):

    def test_generate_prime_length_100(self):
        prime = gp.generatePrime(100, 23)
        self.assertEqual(len(bin(prime)) - 2, 100)
        self.assertEqual(number.isPrime(prime), True)

    def test_generate_prime_length_500(self):
        prime = gp.generatePrime(500, 23)
        self.assertEqual(len(bin(prime)) - 2, 500)
        self.assertEqual(number.isPrime(prime), True)

    def test_generate_prime_length_1000(self):
        prime = gp.generatePrime(1000, 23)
        self.assertEqual(len(bin(prime)) - 2, 1000)
        self.assertEqual(number.isPrime(prime), True)
        

if __name__ == '__main__':
    unittest.main()