#!/usr/bin/env python3 -tt
"""
File: crypto.py
---------------
Assignment 1: Cryptography
Course: CS 41
Name: <YOUR NAME>
SUNet: <SUNet ID>

Replace this with a description of the program.
"""
import math
import utils

# Caesar Cipher

def encrypt_caesar(plaintext):
    """Encrypt plaintext using a Caesar cipher.

    Add more implementation details here.
    """
    encrypted = ""
    plaintext = plaintext.upper()
    for char in plaintext:
        if char.isalpha():
            shift = ord(char.upper()) + 3
            if shift > ord('Z'):
                shift -= 26
            encrypted += chr(shift)
        else:
            encrypted += char
    return encrypted



def decrypt_caesar(ciphertext):

    """Decrypt a ciphertext using a Caesar cipher.

    Add more implementation details here.
    """
    decrypt = ""
    ciphertext = ciphertext.upper()
    for char in ciphertext:
        if char.isalpha():
            shift = ord(char.upper())-3
            if shift < ord('A'):
                shift += 26
            decrypt += chr(shift)
        else:
            decrypt += char
    return decrypt


# Vigenere Cipher

def encrypt_vigenere(plaintext, keyword):
    """Encrypt plaintext using a Vigenere cipher with a keyword.

    Add more implementation details here.
    """
    i = 0
    encrypted = ""
    plaintext = plaintext.upper()
    keyword = keyword.upper()
    for char in plaintext:
        shift = ord(keyword[i % len(keyword)]) - ord('A')   
        encrypted += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        i += 1
    return encrypted      


def decrypt_vigenere(ciphertext, keyword):
    """Decrypt ciphertext using a Vigenere cipher with a keyword.

    Add more implementation details here.
    """
    i = 0
    decrypted = ""
    ciphertext = ciphertext.upper()
    keyword = keyword.upper()
    for char in ciphertext:
        shift = ord(keyword[i % len(keyword)]) - ord('A')
        decrypted += chr((ord(char) - ord('A') - shift) % 26 + ord('A')) 
        i += 1
    return decrypted


# Merkle-Hellman Knapsack Cryptosystem

def generate_private_key(n=8):
    """Generate a private key for use in the Merkle-Hellman Knapsack Cryptosystem.

    Following the instructions in the handout, construct the private key components
    of the MH Cryptosystem. This consistutes 3 tasks:

    1. Build a superincreasing sequence `w` of length n
        (Note: you can check if a sequence is superincreasing with `utils.is_superincreasing(seq)`)
    2. Choose some integer `q` greater than the sum of all elements in `w`
    3. Discover an integer `r` between 2 and q that is coprime to `q` (you can use utils.coprime)

    You'll need to use the random module for this function, which has been imported already

    Somehow, you'll have to return all of these values out of this function! Can we do that in Python?!

    @param n bitsize of message to send (default 8)
    @type n int

    @return 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.
    """
    raise NotImplementedError  # Your implementation here

def create_public_key(private_key):
    """Create a public key corresponding to the given private key.

    To accomplish this, you only need to build and return `beta` as described in the handout.

        beta = (b_1, b_2, ..., b_n) where b_i = r × w_i mod q

    Hint: this can be written in one line using a list comprehension

    @param private_key The private key
    @type private_key 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.

    @return n-tuple public key
    """
    raise NotImplementedError  # Your implementation here


def encrypt_mh(message, public_key):
    """Encrypt an outgoing message using a public key.

    1. Separate the message into chunks the size of the public key (in our case, fixed at 8)
    2. For each byte, determine the 8 bits (the `a_i`s) using `utils.byte_to_bits`
    3. Encrypt the 8 message bits by computing
         c = sum of a_i * b_i for i = 1 to n
    4. Return a list of the encrypted ciphertexts for each chunk in the message

    Hint: think about using `zip` at some point

    @param message The message to be encrypted
    @type message bytes
    @param public_key The public key of the desired recipient
    @type public_key n-tuple of ints

    @return list of ints representing encrypted bytes
    """
    raise NotImplementedError  # Your implementation here

def decrypt_mh(message, private_key):
    """Decrypt an incoming message using a private key

    1. Extract w, q, and r from the private key
    2. Compute s, the modular inverse of r mod q, using the
        Extended Euclidean algorithm (implemented at `utils.modinv(r, q)`)
    3. For each byte-sized chunk, compute
         c' = cs (mod q)
    4. Solve the superincreasing subset sum using c' and w to recover the original byte
    5. Reconsitite the encrypted bytes to get the original message back

    @param message Encrypted message chunks
    @type message list of ints
    @param private_key The private key of the recipient
    @type private_key 3-tuple of w, q, and r

    @return bytearray or str of decrypted characters
    """
    raise NotImplementedError  # Your implementation here

def encrypt_scytale(plaintext, circumference):
    num_col = len(plaintext) // circumference
    helper = 0
    if len(plaintext) % circumference:
        helper = len(plaintext) % circumference
        num_col += 1

    padded_length = num_col * circumference
    plaintext += '.' * (padded_length - len(plaintext))

    grid = [['.' for _ in range(num_col)] for _ in range(circumference)]

    index = 0
    col = 0
    row = 0
    while index < len(plaintext):
        if col == num_col:
            helper -= 1
            col = 0
            row += 1
        grid[row][col] = plaintext[index]
        index += 1
        row += 1
        if row == circumference:
            row  = 0
            col += 1    
    encrypt = ''
    for row in range(circumference):
        for col in range(num_col):
            if grid[row][col] != '.':
                encrypt += grid[row][col]

    return encrypt


def decrypt_scytale(ciphertext, circumference):
    num_col = len(ciphertext) // circumference
    helper = 0
    if len(ciphertext) % circumference:
        num_col += 1
        helper = len(ciphertext) % circumference
    grid = [['.' for _ in range(num_col)] for _ in range(circumference)]
    index = 0
    col = 0
    row = 0
    while index < len(ciphertext):
        if col  == num_col:
            helper -= 1
            col = 0
            row += 1
        grid[row][col] = ciphertext[index]
        index += 1
        col += 1
        if col == len(ciphertext) // circumference  and helper <= 0:
            row += 1
            col = 0
    decrypt = ''
    for col in range(num_col):
        for row in range(circumference):
            if grid[row][col] != '.':
                decrypt += grid[row][col]
    return decrypt

def encrypt_railfence(plaintext, num_rails):
    if num_rails == 1 or num_rails >= len(plaintext):
        return plaintext
    grid = [['.' for _ in range(len(plaintext))] for _ in range(num_rails)]
    rail = 0
    direction = 1
    for i, char in enumerate(plaintext):
        grid[rail][i] = char
        rail += direction
        if rail == 0 or rail == num_rails - 1:
            direction *= -1
    encrypt = ''
    for row in grid:
        for char in row:
            if char != '.':
                encrypt += char
    return encrypt
def decrypt_railfence(ciphertext, num_rails):
    if num_rails == 1 or num_rails >= len(ciphertext):
        return ciphertext
    grid = [['.' for _ in range(len(ciphertext))] for _ in range(num_rails)]
    rail = 0
    direction = 1
    for i in range(len(ciphertext)):
        grid[rail][i] = '*'
        rail += direction
        if rail == 0 or rail == num_rails - 1:
            direction *= -1
    index = 0
    for r in range(num_rails):
        for c in range(len(ciphertext)):
            if grid[r][c] == '*' and index < len(ciphertext):
                grid[r][c] = ciphertext[index]
                index += 1
    rail = 0
    direction = 1
    decrypt = ''
    for i in range(len(ciphertext)):
        decrypt += grid[rail][i] 
        rail += direction
        if rail == 0 or rail == num_rails - 1:
            direction *= -1
    
    return decrypt
