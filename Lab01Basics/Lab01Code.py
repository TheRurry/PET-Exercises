#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 01
#
# Basics of Petlib, encryption, signatures and
# an end-to-end encryption system.
#
# Run the tests through:
# $ py.test-2.7 -v Lab01Tests.py 

###########################
# Group Members: Ryan Collins and Javier Pascual Mesa
###########################


#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can 
#           be imported.

import petlib
# NOTE: Test coverage only supports tasks 1 - 5 hence why it is shows coverage at 80%

#####################################################
# TASK 2 -- Symmetric encryption using AES-GCM 
#           (Galois Counter Mode)
#
# Implement a encryption and decryption function
# that simply performs AES_GCM symmetric encryption
# and decryption using the functions in petlib.cipher.

from os import urandom
from petlib.cipher import Cipher
from binascii import hexlify
import time
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec

def encrypt_message(K, message):
    """ Encrypt a message under a key K """

    plaintext = message.encode("utf8")
    
    ## YOUR CODE HERE
    aes = Cipher.aes_128_gcm()
    iv = urandom(16)
    ciphertext, tag = aes.quick_gcm_enc(K, iv, plaintext)

    return (iv, ciphertext, tag)

def decrypt_message(K, iv, ciphertext, tag):
    """ Decrypt a cipher text under a key K 

        In case the decryption fails, throw an exception.
    """
    ## YOUR CODE HERE
    aes = Cipher.aes_128_gcm()
    plain = aes.quick_gcm_dec(K, iv, ciphertext, tag)

    return plain.encode("utf8")

#####################################################
# TASK 3 -- Understand Elliptic Curve Arithmetic
#           - Test if a point is on a curve.
#           - Implement Point addition.
#           - Implement Point doubling.
#           - Implement Scalar multiplication (double & add).
#           - Implement Scalar multiplication (Montgomery ladder).
#
# MUST NOT USE ANY OF THE petlib.ec FUNCIONS. Only petlib.bn!

from petlib.bn import Bn


def is_point_on_curve(a, b, p, x, y):
    """
    Check that a point (x, y) is on the curve defined by a,b and prime p.
    Reminder: an Elliptic Curve on a prime field p is defined as:

              y^2 = x^3 + ax + b (mod p)
                  (Weierstrass form)

    Return True if point (x,y) is on curve, otherwise False.
    By convention a (None, None) point represents "infinity".
    """
    assert isinstance(a, Bn)
    assert isinstance(b, Bn)
    assert isinstance(p, Bn) and p > 0
    assert (isinstance(x, Bn) and isinstance(y, Bn)) or (x == None and y == None)

    if (x is not None) and (y is not None):
        lhs = (y * y) % p
        rhs = (x*x*x + a*x + b) % p
        on_curve = (lhs == rhs)
        return on_curve
    return True

def point_add(a, b, p, x0, y0, x1, y1):
    """Define the "addition" operation for 2 EC Points.

    Reminder: (xr, yr) = (xq, yq) + (xp, yp)
    is defined as:
        lam = (yq - yp) * (xq - xp)^-1 (mod p)
        xr  = lam^2 - xp - xq (mod p)
        yr  = lam * (xp - xr) - yp (mod p)

    Return the point resulting from the addition. Raises an Exception if the points are equal.
    """

    # ADD YOUR CODE BELOW
    assert isinstance(a, Bn)
    assert isinstance(b, Bn)
    assert isinstance(p, Bn) and p > 0
    assert (isinstance(x0, Bn) and isinstance(y0, Bn)) or (x0 == None and y0 == None)
    assert (isinstance(x1, Bn) and isinstance(y1, Bn)) or (x1 == None and y1 == None)

    if (x0 is not None and y0 is not None) and (x1 is None and y1 is None):
        return (x0, y0)
    if (x0 is None and y0 is None) and (x1 is not None and y1 is not None):
        return (x1, y1)
    if (x0 is x1) and (y0 is not y1):
        return (None, None)
    if (x0 is not x1) and (y0 is not y1):
        lam = (y1.mod_sub(y0, p)).mod_mul(((x1.mod_sub(x0, p)).mod_inverse(p)), p)
        xr = ((lam.mod_pow(2, p)).mod_sub(x0, p)).mod_sub(x1, p)
        yr = (lam.mod_mul(x0.mod_sub(xr, p), p)).mod_sub(y0, p)
        return (xr, yr) 
    raise ArithmeticError("EC Points must not be equal")

def point_double(a, b, p, x, y):
    """Define "doubling" an EC point.
     A special case, when a point needs to be added to itself.

     Reminder:
        lam = (3 * xp ^ 2 + a) * (2 * yp) ^ -1 (mod p)
        xr  = lam ^ 2 - 2 * xp
        yr  = lam * (xp - xr) - yp (mod p)

    Returns the point representing the double of the input (x, y).
    """  

    # ADD YOUR CODE BELOW
    assert isinstance(a, Bn)
    assert isinstance(b, Bn)
    assert isinstance(p, Bn) and p > 0
    assert (isinstance(x, Bn) and isinstance(y, Bn)) or (x == None and y == None)

    if (x is not None) and (y is not None):
        lam = (((x.mod_pow(2, p)).mod_mul(3, p)).mod_add(a, p)).mod_mul((y.mod_mul(2, p)).mod_inverse(p), p)
        xr = (lam.mod_pow(2, p)).mod_sub(x.mod_mul(2, p), p)
        yr = ((x.mod_sub(xr, p)).mod_mul(lam, p)).mod_sub(y, p)
        return (xr, yr)
    return (None, None)

def point_scalar_multiplication_double_and_add(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        Q = infinity
        for i = 0 to num_bits(P)-1
            if bit i of r == 1 then
                Q = Q + P
            P = 2 * P
        return Q

    """
    assert isinstance(a, Bn)
    assert isinstance(b, Bn)
    assert isinstance(p, Bn) and p > 0
    assert (isinstance(x, Bn) and isinstance(y, Bn)) or (x == None and y == None)
    assert isinstance(scalar, Bn)

    Q = (None, None)
    P = (x, y)

    for i in range(scalar.num_bits()):
        if (scalar.is_bit_set(i)):
            Q = point_add(a, b, p, Q[0], Q[1], P[0], P[1])
        P = point_double(a, b, p, P[0], P[1])
    return Q

def fixed_point_scalar_multiplication_double_and_add(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        Q = infinity
        for i = 0 to num_bits(P)-1
            if bit i of r == 1 then
                Q = Q + P
            P = 2 * P
        return Q

    """
    assert isinstance(a, Bn)
    assert isinstance(b, Bn)
    assert isinstance(p, Bn) and p > 0
    assert (isinstance(x, Bn) and isinstance(y, Bn)) or (x == None and y == None)
    assert isinstance(scalar, Bn)

    Q = (None, None)
    R = (None, None)
    P = (x, y)

    for i in range(scalar.num_bits()):
        if (scalar.is_bit_set(i)):
            Q = point_add(a, b, p, Q[0], Q[1], P[0], P[1])
        else:
            R = point_add(a, b, p, R[0], R[1], P[0], P[1])
        P = point_double(a, b, p, P[0], P[1])
    return Q

def point_scalar_multiplication_montgomerry_ladder(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        R0 = infinity
        R1 = P
        for i in num_bits(P)-1 to zero:
            if di = 0:
                R1 = R0 + R1
                R0 = 2R0
            else
                R0 = R0 + R1
                R1 = 2 R1
        return R0

    """
    assert isinstance(a, Bn)
    assert isinstance(b, Bn)
    assert isinstance(p, Bn) and p > 0
    assert (isinstance(x, Bn) and isinstance(y, Bn)) or (x == None and y == None)
    assert isinstance(scalar, Bn)

    R0 = (None, None)
    R1 = (x, y)

    for i in reversed(range(0,scalar.num_bits())):
        if (scalar.is_bit_set(i)):
            R0 = point_add(a, b, p, R0[0], R0[1], R1[0], R1[1])
            R1 = point_double(a, b, p, R1[0], R1[1])
        else:
            R1 = point_add(a, b, p, R0[0], R0[1], R1[0], R1[1])
            R0 = point_double(a, b, p, R0[0], R0[1])
    return R0


#####################################################
# TASK 4 -- Standard ECDSA signatures
#
#          - Implement a key / param generation 
#          - Implement ECDSA signature using petlib.ecdsa
#          - Implement ECDSA signature verification 
#            using petlib.ecdsa

from hashlib import sha256
from petlib.ec import EcGroup
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify

def ecdsa_key_gen():
    """ Returns an EC group, a random private key for signing 
        and the corresponding public key for verification"""
    G = EcGroup()
    priv_sign = G.order().random()
    pub_verify = priv_sign * G.generator()
    return (G, priv_sign, pub_verify)

def ecdsa_sign(G, priv_sign, message):
    """ Sign the SHA256 digest of the message using ECDSA and return a signature """
    plaintext =  message.encode("utf8")

    ## YOUR CODE HERE
    digest = sha256(plaintext).digest()
    sig = do_ecdsa_sign(G, priv_sign, digest)
    return sig

def ecdsa_verify(G, pub_verify, message, sig):
    """ Verify the ECDSA signature on the message """
    plaintext =  message.encode("utf8")

    ## YOUR CODE HERE
    digest = sha256(plaintext).digest()
    res = do_ecdsa_verify(G, pub_verify, sig, digest)
    return res

#####################################################
# TASK 5 -- Diffie-Hellman Key Exchange and Derivation
#           - use Bob's public key to derive a shared key.
#           - Use Bob's public key to encrypt a message.
#           - Use Bob's private key to decrypt the message.
#
# NOTE: 

def dh_get_key():
    """ Generate a DH key pair """
    G = EcGroup()
    priv_dec = G.order().random()
    pub_enc = priv_dec * G.generator()
    return (G, priv_dec, pub_enc)

# Alice
def dh_encrypt(pub, message, aliceSig = None):
    """ Assume you know the public key of someone else (Bob), 
    and wish to Encrypt a message for them.
        - Generate a fresh DH key for this message.
        - Derive a fresh shared key.
        - Use the shared key to AES_GCM encrypt the message.
        - Optionally: sign the message with Alice's key.
    """
    
    ## YOUR CODE HERE
    bob_public_key = pub

    # Ciphertext encryption
    G, alice_private_key, alice_public_key = dh_get_key()
    shared_key = (alice_private_key * bob_public_key).export()[:16]
    iv, ciphertext, tag = encrypt_message(shared_key, message)

    # Public key signing
    sig = None
    if (aliceSig is not None):
        sig = ecdsa_sign(G, aliceSig, hexlify(alice_public_key.export()))
    return alice_public_key, sig, (iv, ciphertext, tag)

# Bob
def dh_decrypt(priv, ciphertext, aliceVer = None):
    """ Decrypt a received message encrypted using your public key, 
    of which the private key is provided. Optionally verify 
    the message came from Alice using her verification key."""
    
    ## YOUR CODE HERE
    G = EcGroup()
    bob_private_key = priv
    alice_public_key, aliceSig, aead = ciphertext
    
    # Signature verification
    if (aliceVer is not None):
        if (aliceSig is None):
            raise ValueError("There is no signed public key")
        if (not ecdsa_verify(G, aliceVer, hexlify(alice_public_key.export()), aliceSig)):
            raise ValueError("Signed public key can not be verified")

    # Ciphertext decryption
    shared_key = (bob_private_key * alice_public_key).export()[:16]
    iv, encrypted_message, tag = aead
    message = decrypt_message(shared_key, iv, encrypted_message, tag)
    return message

## NOTE: populate those (or more) tests
#  ensure they run using the "py.test filename" command.
#  What is your test coverage? Where is it missing cases?
#  $ py.test-2.7 --cov-report html --cov Lab01Code Lab01Code.py 

def encrypt_no_signatures():
    G, bob_private_key, bob_public_key = dh_get_key()
    message = u"Hello World!"

    # No signature assertions
    ciphertext = dh_encrypt(bob_public_key, message)
    # Check that return type is a tuple of length 3
    assert len(ciphertext) == 3
    # Check that a public key has been returned
    assert ciphertext[0]
    # Check that the public key has not been signed
    assert ciphertext[1] == None
    # Check that the cipher text is a tuple of length 3
    assert len(ciphertext[2]) == 3

    # AES_GCM encryption checks
    iv, encrypted_message, tag = ciphertext[2]
    assert len(iv) == 16
    assert len(encrypted_message) == len(message)
    assert len(tag) == 16

def encrypt_with_signatures():
    G, bob_private_key, bob_public_key = dh_get_key()
    message = u"Hello World!"

    # With signature assertions
    G, aliceSig, aliceVer = ecdsa_key_gen()
    ciphertext = dh_encrypt(bob_public_key, message, aliceSig)
    # Check that return type is a tuple of length 3
    assert len(ciphertext) == 3
    # Check that a public key has been returned
    assert ciphertext[0]
    # Check that the public key has been signed
    assert ciphertext[1]
    # Check that the cipher text is a tuple of length 3
    assert len(ciphertext[2]) == 3

    # AES_GCM encryption checks
    iv, encrypted_message, tag = ciphertext[2]
    assert len(iv) == 16
    assert len(encrypted_message) == len(message)
    assert len(tag) == 16

def test_encrypt():
    encrypt_no_signatures()
    encrypt_with_signatures()

def test_decrypt():
    G, bob_private_key, bob_public_key = dh_get_key()
    message = u"Hello World!"

    # No signature assertions
    ciphertext = dh_encrypt(bob_public_key, message)
    decrypted_message = dh_decrypt(bob_private_key, ciphertext)
    assert message == decrypted_message

    # With signature assertions
    G, aliceSig, aliceVer = ecdsa_key_gen()
    ciphertext = dh_encrypt(bob_public_key, message, aliceSig)
    decrypted_message = dh_decrypt(bob_private_key, ciphertext, aliceVer)
    assert message == decrypted_message

def test_fails():
    from pytest import raises
    G, bob_private_key, bob_public_key = dh_get_key()
    message = u"Hello World!"

    # Message not signed, but verification required
    G, aliceSig, aliceVer = ecdsa_key_gen()
    ciphertext = dh_encrypt(bob_public_key, message)
    with raises(Exception) as excinfo:
        decrypted_message = dh_decrypt(bob_private_key, ciphertext, aliceVer)
    assert "There is no signed public key" in str(excinfo.value)

    # Signature can not be verified
    ciphertext = dh_encrypt(bob_public_key, message, aliceSig)
    G, aliceSig, aliceVer = ecdsa_key_gen()
    with raises(Exception) as excinfo:
        decrypted_message = dh_decrypt(bob_private_key, ciphertext, aliceVer)
    assert "Signed public key can not be verified" in str(excinfo.value)

#####################################################
# TASK 6 -- Time EC scalar multiplication
#             Open Task.
#           
#           - Time your implementations of scalar multiplication
#             (use time.clock() for measurements)for different 
#              scalar sizes)
#           - Print reports on timing dependencies on secrets.
#           - Fix one implementation to not leak information.

# To test task 6 run "python Lab01Code.py", and after ~5 mins of run time graphs should be generated.
# From the graphs we can see that double and add is leaking information on the amount of bits set in
# the scalar used, whereas montgomerry ladder is not. In order to fix this we do similar to montgommery
# ladder and ensure the same amount of doubles and adds occur each step of the algorithm. 
# See "fixed_point_scalar_multiplication_double_and_add" for the implementation of this fix.

def get_time_dif(mul, args):
    before = time.clock()
    mul(*args)
    after = time.clock()
    return after - before

def time_scalar_mul():
    # Get EC Parameters
    G = EcGroup(713)
    d = G.parameters()
    a, b, p = d["a"], d["b"], d["p"]
    g = G.generator()
    x, y = g.get_affine()

    # Generate graph data
    double_add = list()
    fixed_double_add = list()
    montgomerry_ladder = list()
    n = 500
    bits_set = range(1, n)
    for i in bits_set:
        scalar = Bn.from_decimal(("1"*i) + ("0"*(n-i-1)))
        print i, scalar
        double_add.append(get_time_dif(point_scalar_multiplication_double_and_add, (a, b, p, x, y, scalar)))
        fixed_double_add.append(get_time_dif(fixed_point_scalar_multiplication_double_and_add, (a, b, p, x, y, scalar)))
        montgomerry_ladder.append(get_time_dif(point_scalar_multiplication_montgomerry_ladder, (a, b, p, x, y, scalar)))

    fig = plt.figure("Runtime graphs")

    gs = gridspec.GridSpec(4, 4)

    ax = plt.subplot(gs[0:2, 0:2])
    ax.set_title("Double and Add")
    ax.plot(bits_set, double_add)
    ax.set_xlabel("Number of bits set")
    ax.set_ylabel("Time taken to multiply")

    ax = plt.subplot(gs[0:2, 2:])
    ax.set_title("Montgomerry Ladder")
    ax.plot(bits_set, montgomerry_ladder)
    ax.set_xlabel("Number of bits set")
    ax.set_ylabel("Time taken to multiply")

    ax = plt.subplot(gs[2:4, 1:3])
    ax.set_title("Fixed Double and Add")
    ax.plot(bits_set, fixed_double_add)
    ax.set_xlabel("Number of bits set")
    ax.set_ylabel("Time taken to multiply")

    gs.tight_layout(fig)
    
    plt.show()
    
if __name__ == "__main__":
    time_scalar_mul()