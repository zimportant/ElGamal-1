import unittest

import string
import miller_rabin.GenPrime as gp
import miller_rabin.IsPrime as ip
import Crypto.Util.number as number
import random
import sys
import ElGamal

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

    def test_sign_message(self):
        message = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10000))
        p = gp.generatePrime(100, ElGamal.ATTEMPTS)
        alpha = ElGamal.find_primitive_root(p)
        privateKey = ElGamal.PrivateKey(random.randint(2, (p - 1)))
        publicKey = ElGamal.PublicKey(p, alpha, privateKey)

        sig_num = ElGamal.SigNum \
                .of_key(message, privateKey, publicKey, ElGamal.ALPHABET)

        self.assertTrue(sig_num.verify(message, privateKey, publicKey, ElGamal.ALPHABET))


    def test_sign_message_1000(self):
        message = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10000))
        p = gp.generatePrime(1000, ElGamal.ATTEMPTS)
        alpha = ElGamal.find_primitive_root(p)
        privateKey = ElGamal.PrivateKey(random.randint(2, (p - 1)))
        publicKey = ElGamal.PublicKey(p, alpha, privateKey)

        sig_num = ElGamal.SigNum \
                .of_key(message, privateKey, publicKey, ElGamal.ALPHABET)

        self.assertTrue(sig_num.verify(message, privateKey, publicKey, ElGamal.ALPHABET))


if __name__ == '__main__':
    unittest.main()