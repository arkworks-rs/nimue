"""
Use this program to find the number of bits that appear uniformly random
in the uniform distribution mod p.

While this function is trivial for byte-oriented hashes, for algebraic hashes, it requires proper implementation.
Many implementations simply truncate the least-significant bits, but this approach
results in a statistical deviation from uniform randomness. The number of useful bits, denoted as `n`,
has a statistical distance from uniformly random given by:

p is provided on stdin in any format that python can eval. For example,

$ python3 scripts/useful_bits_modp.py <<< 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
"""

def useful_bits(p):
    for n in range(p.bit_length()-1, 0, -1):
        alpha = p % 2^n
        if n+1 + p.bit_length() - alpha.bit_length() - (2^n-alpha).bit_length() >= 128:
            return n


if __name__ == '__main__':
   print(useful_bits(eval(input())))