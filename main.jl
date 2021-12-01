"""
For this project, I build RSA encryption. While it isn't the most secure RSA encryption (it is missing padding and is probably not using as
large of numbers as possible), it has all the parts for RSA. It generates a public/private key pair through the steps: 

1) Compute two prime numbers, p and q 

2) Compute n = pq, the product of the two prime numbers 

3) Compute Carmichael's totient function of n, which because p and q are prime, can be computed through: lcm(p-1, q-1)

4) Choose an e value such that 1 < e < lambda(n) (that Carmichael function) and gcd(e, lambda(n)) = 1. Apparently 2^16 + 1
just works, so I used that. 

5) Compute d such that d is the modular multiplicative inverse of e mod lambda(n)

(n, e) is released as the public key while d is the private key. We can use these the encrypt and decrypt message strings. 

The function rsa_key_gen() returns a random public/private key pair for use with encryption/decrytion which the functions
encrypt() and decrypt() can use. 

"""

using Random

function is_prime(n)
    """
    Check whether n is prime. I used example code from wikipedia here: https://en.wikipedia.org/wiki/Primality_test

    Parameters
    ----------

    n : Int
        Number which you are checking for prime. Any positive integer. 
    

    Returns
    -------

    prime : bool 
        true is prime, false if not

    """

    if n <= 3 #if n is 1, 2, or 3
        return n > 1 #as 1 isn't prime, only return true if n isn't 1... This also accounts for when user inputs 0 or negative integer. 
    end

    if (n % 2 == 0) || (n % 3 == 0) #if the number is divisable by 2 or 3, it obviously isn't prime. I am assuming we take this step as checking mod 2 or 3 is much easier then all mods 
        return false 
    end
    
    #I don't entirely understand what this is doing, but it appears to be checking for mod 5, 7 then 11 13, then 19 21, etc... I assume we do this because of some efficiency thing, but I can't say I understand it
    i = 5
    while i^2 <= n #while loop while the square of i is less than n
        if (n % i == 0) || (n % (i + 2) == 0) #check for divisability 
            return false
        end
        
        i += 6 #add 6 to i
    end
    return true 
end

function rsa_key_gen()
    """
    Generates private/public key pair for RSA.
    Used this wikipedia page as reference: https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation
    Also used this page: https://www.comparitech.com/blog/information-security/rsa-encryption/

    Returns
    -------

    (n, e): tuple
        Public key for RSA key. n is the product of p, q (two secret prime numbers). e is used for d, 
        where d is the modular multiplicative inverse of e modulo lambda(n).

    d: int
        Private key for RSA key. d is the modular multiplicative inverse of e modulo lambda(n)

    """

    randomNumberPair = rand(Int32, 2) #generate two random integers. use Int32 to limit integer size
    while randomNumberPair[1] < 2^(16) || randomNumberPair[2] < 2^(16) #make sure the two random numbers are over 2^16
        randomNumberPair = rand(Int32, 2) 
    end

    randomNumberPair = BigInt.(randomNumberPair) #convert integers to big integers
    randomNumberPair = abs.(randomNumberPair) #take absolute value of random numbers to remove any negatives

    #split vector into seperate variables 
    p = randomNumberPair[1]
    q = randomNumberPair[2]

    #iterate p until it is prime 
    while is_prime(p) == false
        p+=1 
    end

    #iterate through q until it is prime
    while is_prime(q) == false
        q+=1
    end

    #compute n, released as part of public key
    n = p*q

    #compute Carmichael's totient function. Here we know lambda(n) = lcm(lambda(p), lambda(q)) where lambda(p) = p - 1, lambda(q) = q - 1 according to the wiki page I am using to implement this
    lambda = lcm(p-1, q-1)

    #choose value for e... Aparently this always works? 
    e = 2^(16) + 1

    #calculate d such that d is the modular multiplicative inverse of e modulo lambda(n)
    d = invmod(e, lambda)

    return ((n,e), d)

end

function encrypt(text, public_key)
    """
    Encrypts the inputed text using the RSA public key. Doesn't do padding (which is important to prevent
    relatively easy attacks from decrypting cipher text. I am not including it for the time being because
    it is currently too big of a headache for me.) Uses Julia's "parse" to turn text into number, removes
    spaces

    Parameters
    ----------

    text : Str
        String for text being encrypted 

    public_key : tuple
        Public key used in RSA encryption where you have (n, e)

    Returns
    -------

    cipherText : Str
        String representing encrypted, cipher text

    """

    #found parsing code here: https://stackoverflow.com/questions/49415718/representing-a-non-numeric-string-as-in-integer-in-julia
    encodedText = parse(BigInt, text, base=62)

    #calculate cipher text with c = m^e mod n
    cipherTextEncoded = (encodedText^public_key[2]) % public_key[1]

    string(cipherTextEncoded, base=62)

end

function modular_exponentiation(x, y, p)
    """
    At a few steps in RSA, I need to calculate x^y mod p. Here is an implementation of modular 
    exponentiation to make that work. 
    I used the source: https://www.geeksforgeeks.org/modular-exponentiation-power-in-modular-arithmetic/

    Parameters
    ----------

    x : Int
        The number x in x^y mod p

    y : Int
        The number y in x^y mod p

    p : Int
        The number p in x^y mod p

    Returns
    -------

    res : Int
        The value of x^y mod p

    """

    res = 1 #variable to store result

    x = x % p #reset x to be x mod p. This is to make sure x is less than p (in modular arithmatic, these should be equal if I am not mistaken)

    #if x mod p is 0, then x^y mod p will also be 0. Just return 0 in that case here 
    if x == 0 
        return 0
    end

    while y>0

        #if y is odd, multiply x by the result (idk what is happening here, this I am just copying)
        if y%2 == 1 
            res = (res * x) % p
        end

        #perform bitshift on y
        y = y >> 1
        x = (x * x) % p 
    end

    res
end

function decrypt(cipherText, public_key, private_key)
    """
    Decrypts encrypted cipher text using RSA

    Parameters
    ----------

    cipherText : Str
        String represented encrypted text using public key

    public_key : tuple
        Public key for this RSA key pair. In the form (n, e)

    private_key : Int
        Private key in public/private key pair for RSA encryption 

    Returns
    -------

    message : Str
        String for decrypted message

    """

    cipher = parse(BigInt, cipherText, base=62) #turn cipher string into int

    message = modular_exponentiation(cipher, private_key, public_key[1]) #perform modular exponentiation on string to find m = c^d mod n

    string(message, base=62) #convert message back to string and return

end

textToEncrypt = "David"

RSA_keys = rsa_key_gen()
encryptedText = encrypt("David",RSA_keys[1])
println("Encrypted text: $encryptedText")
decryptedText = decrypt(encryptedText, RSA_keys[1], RSA_keys[2])
println("Decrypted text: $decryptedText")