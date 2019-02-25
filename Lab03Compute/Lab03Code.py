#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 03
#
# Basics of Privacy Friendly Computations through
#         Additive Homomorphic Encryption.
#
# Run the tests through:
# $ py.test -v test_file_name.py

#####################################################
# TASK 1 -- Setup, key derivation, log
#           Encryption and Decryption
#

###########################
# Group Members: Ryan Collins
###########################


from petlib.ec import EcGroup

def setup():
    """Generates the Cryptosystem Parameters."""
    G = EcGroup(nid=713)
    g = G.hash_to_point(b"g")
    h = G.hash_to_point(b"h")
    o = G.order()
    return (G, g, h, o)

def keyGen(params):
    """ Generate a private / public key pair """
    (G, g, h, o) = params
    
    # ADD CODE HERE
    priv = o.random()
    pub = priv * g
    return (priv, pub)

def encrypt(params, pub, m):
    """ Encrypt a message under the public key """
    if not -100 < m < 100:
        raise Exception("Message value to low or high.")

   # ADD CODE HERE
    (G, g, h, o) = params
    k = o.random()
    c = (k*g, k*pub + m*h)
    return c

def isCiphertext(params, ciphertext):
    """ Check a ciphertext """
    (G, g, h, o) = params
    ret = len(ciphertext) == 2
    a, b = ciphertext
    ret &= G.check_point(a)
    ret &= G.check_point(b)
    return ret

_logh = None
def logh(params, hm):
    """ Compute a discrete log, for small number only """
    global _logh
    (G, g, h, o) = params

    # Initialize the map of logh
    if _logh == None:
        _logh = {}
        for m in range (-1000, 1000):
            _logh[(m * h)] = m

    if hm not in _logh:
        raise Exception("No decryption found.")

    return _logh[hm]

def decrypt(params, priv, ciphertext):
    """ Decrypt a message using the private key """
    assert isCiphertext(params, ciphertext)
    a , b = ciphertext

   # ADD CODE HERE
    hm = b - (priv*a)
    return logh(params, hm)

#####################################################
# TASK 2 -- Define homomorphic addition and
#           multiplication with a public value
# 

def add(params, pub, c1, c2):
    """ Given two ciphertexts compute the ciphertext of the 
        sum of their plaintexts.
    """
    assert isCiphertext(params, c1)
    assert isCiphertext(params, c2)

   # ADD CODE HERE
    a0, b0 = c1
    a1, b1 = c2
    c3 = (a0 + a1, b0 + b1)
    return c3

def mul(params, pub, c1, alpha):
    """ Given a ciphertext compute the ciphertext of the 
        product of the plaintext time alpha """
    assert isCiphertext(params, c1)

   # ADD CODE HERE
    a, b = c1
    c3 = (alpha * a, alpha * b)
    return c3

#####################################################
# TASK 3 -- Define Group key derivation & Threshold
#           decryption. Assume an honest but curious 
#           set of authorities.

def groupKey(params, pubKeys=[]):
    """ Generate a group public key from a list of public keys """
    (G, g, h, o) = params

   # ADD CODE HERE
    pub = reduce(lambda x,y : x+y, pubKeys)
    return pub

def partialDecrypt(params, priv, ciphertext, final=False):
    """ Given a ciphertext and a private key, perform partial decryption. 
        If final is True, then return the plaintext. """
    assert isCiphertext(params, ciphertext)
    
    # ADD CODE HERE
    (a1, b1) = ciphertext
    b1 -= priv * a1

    if final:
        return logh(params, b1)
    else:
        return a1, b1

#####################################################
# TASK 4 -- Actively corrupt final authority, derives
#           a public key with a known private key.
#

def corruptPubKey(params, priv, OtherPubKeys=[]):
    """ Simulate the operation of a corrupt decryption authority. 
        Given a set of public keys from other authorities return a
        public key for the corrupt authority that leads to a group
        public key corresponding to a private key known to the
        corrupt authority. """
    (G, g, h, o) = params
    
   # ADD CODE HERE
    pub = priv*g - groupKey(params, OtherPubKeys)
    return pub

#####################################################
# TASK 5 -- Implement operations to support a simple
#           private poll.
#

def encode_vote(params, pub, vote):
    """ Given a vote 0 or 1 encode the vote as two
        ciphertexts representing the count of votes for
        zero and the votes for one."""
    assert vote in [0, 1]

    # ADD CODE HERE
    v0 = encrypt(params, pub, 1) # default return values for vote 0
    v1 = encrypt(params, pub, 0)
    if vote: v0, v1 = v1, v0     # swap values if vote 1
    return (v0, v1)

def process_votes(params, pub, encrypted_votes):
    """ Given a list of encrypted votes tally them
        to sum votes for zeros and votes for ones. """
    assert isinstance(encrypted_votes, list)
    
   # ADD CODE HERE
    v_add = lambda x,y : add(params, pub, x, y)                         # reducer for adding ciphertexts
    tv0, tv1 = map(lambda v : reduce(v_add, v), zip(*encrypted_votes))  # apply reducer to unzipped encrypted_votes
    return tv0, tv1

def simulate_poll(votes):
    """ Simulates the full process of encrypting votes,
        tallying them, and then decrypting the total. """

    # Generate parameters for the crypto-system
    params = setup()

    # Make keys for 3 authorities
    priv1, pub1 = keyGen(params)
    priv2, pub2 = keyGen(params)
    priv3, pub3 = keyGen(params)
    pub = groupKey(params, [pub1, pub2, pub3])

    # Simulate encrypting votes
    encrypted_votes = []
    for v in votes:
        encrypted_votes.append(encode_vote(params, pub, v))

    # Tally the votes
    total_v0, total_v1 = process_votes(params, pub, encrypted_votes)

    # Simulate threshold decryption
    privs = [priv1, priv2, priv3]
    for priv in privs[:-1]:
        total_v0 = partialDecrypt(params, priv, total_v0)
        total_v1 = partialDecrypt(params, priv, total_v1)

    total_v0 = partialDecrypt(params, privs[-1], total_v0, True)
    total_v1 = partialDecrypt(params, privs[-1], total_v1, True)

    # Return the plaintext values
    return total_v0, total_v1

###########################################################
# TASK Q1 -- Answer questions regarding your implementation
#
# Consider the following game between an adversary A and honest users H1 and H2: 
# 1) H1 picks 3 plaintext integers Pa, Pb, Pc arbitrarily, and encrypts them to the public
#    key of H2 using the scheme you defined in TASK 1.
# 2) H1 provides the ciphertexts Ca, Cb and Cc to H2 who flips a fair coin b.
#    In case b=0 then H2 homomorphically computes C as the encryption of Pa plus Pb.
#    In case b=1 then H2 homomorphically computes C as the encryption of Pb plus Pc.
# 3) H2 provides the adversary A, with Ca, Cb, Cc and C.
#
# What is the advantage of the adversary in guessing b given your implementation of 
# Homomorphic addition? What are the security implications of this?

"""
The implementation of homomorphic addition "add" is deterministic, which means if the attacker has access to
"add" or knowledge of its implementation, they can simply "add" Ca with Cb, and Cb with Cc. To guess the value
of b they can compare the two resultant values with C and choose b = 0 if C is equivalent to Ca "add" Cb, and 
b = 1 if C is equivalent to Cb "add" Cc.  

The fact that this implementation of homomorphic addtion is determinstic, there can be concerns of anonymity 
being violated. In a scenario where we have a selection of users each producing a ciphertext, and one of those 
users is malicious, if the attacker knows who has produced each ciphertext, they will be able to determine
which user's ciphertext has been added on to theirs. Since homorphic addition when decrypted provided the addtion 
of two plaintext values, if they see the decrypted value they will be able to subtract their plaintext value, 
and determine a plaintext value for an honest user's ciphertext.
"""


###########################################################
# TASK Q2 -- Answer questions regarding your implementation
#
# Given your implementation of the private poll in TASK 5, how
# would a malicious user implement encode_vote to (a) distrupt the
# poll so that it yields no result, or (b) manipulate the poll so 
# that it yields an arbitrary result. Can those malicious actions 
# be detected given your implementation?

"""
a) A malicious user can change the implementation of encode vote to return a 2-tuple where both values are 0 
encoded with the group public key. This would result in the total vote counts of both 1 and 0 being 0.

b) Assuming the malicious user knows the total number of votes which are going to be made, they can change encode
vote to return a 2-tuple where the first value is the desired total count of 0 votes / len(votes) encrypted
with the group public key, and the second value is the desired total count of 1 votes / len(votes) encrypted
with the group public key.

In most cases these malicious actions can be detected by checking to make sure if the total count of 0 votes
+ the total count of 1 votes == len(votes). If they are not equal we can be certain that something has gone 
wrong, most likely the result of malicious actions.
"""
