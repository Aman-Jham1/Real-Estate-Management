# Large Prime Generation for RSA
import random, math

class RSA:
    first_primes_list =   [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                                31, 37, 41, 43, 47, 53, 59, 61, 67, 
                                71, 73, 79, 83, 89, 97, 101, 103, 
                                107, 109, 113, 127, 131, 137, 139, 
                                149, 151, 157, 163, 167, 173, 179, 
                                181, 191, 193, 197, 199, 211, 223,
                                227, 229, 233, 239, 241, 251, 257,
                                263, 269, 271, 277, 281, 283, 293,
                                307, 311, 313, 317, 331, 337, 347, 349]

    def __init__(self):
        p  = self.getPrime()
        # print(p)
        q  = self.getPrime()
        # print(q)

        # p=7
        # q=13
        n = p*q
        # print('n is :', n)
        e = self.getE(p,q)
        # print("this is e : ", e)
        self.pub = (n,e)
        d = self.getD(e, p , q)
        # print("this is d : ", d)
        self.priv = (n,d)
        # text = 5
        # print(text)
        # C = RSA(text , p*q , e)
        # print(C)
        # D = RSA(C , p*q , d)
        # print(D)
        #return 

    def getEncryption(self, text, n, key):
        pswd = []
        for i in range(len(text)):
            pswd.append(self.RSA(ord(text[i]), n, key))
        return pswd

    def getDecryption(self, text, n, key):
        ct = ""
        for val in text:
            ct+=chr(self.RSA(val, n, key))
        return ct
        
        # Pre generated primes
    def RSA(self, text , num , key):
        return pow(text, key, num)
    
    def nBitRandom(self, n):
        return random.randrange(2**(n-1)+1, 2**n - 1)
    
    def getLowLevelPrime(self, n):
        '''Generate a prime candidate divisible 
        by first primes'''
        while True:
            # Obtain a random number
            pc = self.nBitRandom(n) 
    
            # Test divisibility by pre-generated 
            # primes
            for divisor in self.first_primes_list:
                if pc % divisor == 0 and divisor**2 <= pc:
                    break
            else: return pc
    
    def isMillerRabinPassed(self, mrc):
        '''Run 20 iterations of Rabin Miller Primality test'''
        maxDivisionsByTwo = 0
        ec = mrc-1
        while ec % 2 == 0:
            ec >>= 1
            maxDivisionsByTwo += 1
        assert(2**maxDivisionsByTwo * ec == mrc-1)
    
        def trialComposite(round_tester):
            if pow(round_tester, ec, mrc) == 1:
                return False
            for i in range(maxDivisionsByTwo):
                if pow(round_tester, 2**i * ec, mrc) == mrc-1:
                    return False
            return True
    
        # Set number of trials here
        numberOfRabinTrials = 20 
        for i in range(numberOfRabinTrials):
            round_tester = random.randrange(2, mrc)
            if trialComposite(round_tester):
                return False
        return True

    def getPrime(self, ):
        while True:
            n = 128
            prime_candidate = self.getLowLevelPrime(n)
            if not self.isMillerRabinPassed(prime_candidate):
                continue
            else:
                # print(n, "bit prime is: \n", prime_candidate)
                break
        return prime_candidate

    
    def getE(self, p,q):
        e = 2
        phi = (p-1)*(q-1) 
        while e < phi :
            if math.gcd(e,phi) == 1:
                break
            else :
                e += 1
        return e

    def getD(self, e, p ,q):
        return pow(e, -1, (p-1)*(q-1))
    
rsa = RSA()


    
    


