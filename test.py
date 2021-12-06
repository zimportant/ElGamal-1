import unittest

import string
import miller_rabin.GenPrime as gp
import miller_rabin.IsPrime as ip
import Crypto.Util.number as number
import random
import sys
import ElGamal

class TestElGamalMethods(unittest.TestCase):

    def test_generate_prime_length_100_1(self):
        prime = gp.generatePrime(100, 23)
        self.assertEqual(len(bin(prime)) - 2, 100)
        self.assertEqual(number.isPrime(prime), True)

    def test_generate_prime_length_100_2(self):
        prime = gp.generatePrime(100, 23)
        self.assertEqual(len(bin(prime)) - 2, 100)
        self.assertEqual(number.isPrime(prime), True)

    def test_generate_prime_length_100_3(self):
        prime = gp.generatePrime(100, 23)
        self.assertEqual(len(bin(prime)) - 2, 100)
        self.assertEqual(number.isPrime(prime), True)

    def test_generate_prime_length_500_1(self):
        prime = gp.generatePrime(500, 23)
        self.assertEqual(len(bin(prime)) - 2, 500)
        self.assertEqual(number.isPrime(prime), True)

    def test_generate_prime_length_500_2(self):
        prime = gp.generatePrime(500, 23)
        self.assertEqual(len(bin(prime)) - 2, 500)
        self.assertEqual(number.isPrime(prime), True)

    def test_generate_prime_length_500_3(self):
        prime = gp.generatePrime(500, 23)
        self.assertEqual(len(bin(prime)) - 2, 500)
        self.assertEqual(number.isPrime(prime), True)

    def test_generate_prime_length_1000_1(self):
        prime = gp.generatePrime(1000, 23)
        self.assertEqual(len(bin(prime)) - 2, 1000)
        self.assertEqual(number.isPrime(prime), True)

    def test_generate_prime_length_1000_2(self):
        prime = gp.generatePrime(1000, 23)
        self.assertEqual(len(bin(prime)) - 2, 1000)
        self.assertEqual(number.isPrime(prime), True)

    def test_generate_prime_length_1000_3(self):
        prime = gp.generatePrime(1000, 23)
        self.assertEqual(len(bin(prime)) - 2, 1000)
        self.assertEqual(number.isPrime(prime), True)

    def test_sign_message_1(self):
        message = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10000))
        p = gp.generatePrime(100, ElGamal.ATTEMPTS)
        alpha = ElGamal.find_primitive_root(p)
        privateKey = ElGamal.PrivateKey(random.randint(2, (p - 1)))
        beta = ElGamal.modexp(alpha, privateKey.getvalue(), p)
        publicKey = ElGamal.PublicKey(p, alpha, beta)

        sig_num = ElGamal.SigNum \
                .of_key(message, privateKey, publicKey, ElGamal.ALPHABET)

        self.assertTrue(sig_num.verify(message, publicKey, ElGamal.ALPHABET))

    def test_sign_message_2(self):
        message = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10000))
        p = gp.generatePrime(100, ElGamal.ATTEMPTS)
        alpha = ElGamal.find_primitive_root(p)
        privateKey = ElGamal.PrivateKey(random.randint(2, (p - 1)))
        beta = ElGamal.modexp(alpha, privateKey.getvalue(), p)
        publicKey = ElGamal.PublicKey(p, alpha, beta)

        sig_num = ElGamal.SigNum \
                .of_key(message, privateKey, publicKey, ElGamal.ALPHABET)

        self.assertTrue(sig_num.verify(message, publicKey, ElGamal.ALPHABET))

    def test_sign_message_3(self):
        message = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10000))
        p = gp.generatePrime(100, ElGamal.ATTEMPTS)
        alpha = ElGamal.find_primitive_root(p)
        privateKey = ElGamal.PrivateKey(random.randint(2, (p - 1)))
        beta = ElGamal.modexp(alpha, privateKey.getvalue(), p)
        publicKey = ElGamal.PublicKey(p, alpha, beta)

        sig_num = ElGamal.SigNum \
                .of_key(message, privateKey, publicKey, ElGamal.ALPHABET)

        self.assertTrue(sig_num.verify(message, publicKey, ElGamal.ALPHABET))


    def test_sign_message_1000_1(self):
        message = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10000))
        p = gp.generatePrime(1000, ElGamal.ATTEMPTS)
        alpha = ElGamal.find_primitive_root(p)
        privateKey = ElGamal.PrivateKey(random.randint(2, (p - 1)))
        beta = ElGamal.modexp(alpha, privateKey.getvalue(), p)
        publicKey = ElGamal.PublicKey(p, alpha, beta)

        sig_num = ElGamal.SigNum \
                .of_key(message, privateKey, publicKey, ElGamal.ALPHABET)

        self.assertTrue(sig_num.verify(message, publicKey, ElGamal.ALPHABET))


    def test_sign_message_1000_2(self):
        message = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10000))
        p = gp.generatePrime(1000, ElGamal.ATTEMPTS)
        alpha = ElGamal.find_primitive_root(p)
        privateKey = ElGamal.PrivateKey(random.randint(2, (p - 1)))
        beta = ElGamal.modexp(alpha, privateKey.getvalue(), p)
        publicKey = ElGamal.PublicKey(p, alpha, beta)

        sig_num = ElGamal.SigNum \
                .of_key(message, privateKey, publicKey, ElGamal.ALPHABET)

        self.assertTrue(sig_num.verify(message, publicKey, ElGamal.ALPHABET))


    def test_sign_message_1000_3(self):
        message = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10000))
        p = gp.generatePrime(1000, ElGamal.ATTEMPTS)
        alpha = ElGamal.find_primitive_root(p)
        privateKey = ElGamal.PrivateKey(random.randint(2, (p - 1)))
        beta = ElGamal.modexp(alpha, privateKey.getvalue(), p)
        publicKey = ElGamal.PublicKey(p, alpha, beta)

        sig_num = ElGamal.SigNum \
                .of_key(message, privateKey, publicKey, ElGamal.ALPHABET)

        self.assertTrue(sig_num.verify(message, publicKey, ElGamal.ALPHABET))


if __name__ == '__main__':
    unittest.main()
