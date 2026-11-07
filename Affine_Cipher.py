import math
import sys

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

P_ENG = {
    'A': .082, 'B': .015, 'C': .028, 'D': .043, 'E': .127, 'F': .022,
    'G': .020, 'H': .061, 'I': .070, 'J': .002, 'K': .008, 'L': .040,
    'M': .024, 'N': .067, 'O': .075, 'P': .019, 'Q': .001, 'R': .060,
    'S': .063, 'T': .091, 'U': .028, 'V': .010, 'W': .023, 'X': .001,
    'Y': .020, 'Z': .001
}

def clean_text(text):
    return "".join(c for c in text.upper() if c in ALPHABET)

def get_mod_inverse(a, m):
    try:
        return pow(a, -1, m)
    except ValueError:
        return None

def decrypt_text(ciphertext, a, b, m):
    a_inv = get_mod_inverse(a, m)
    if a_inv is None:
        return ""
    return "".join(ALPHABET[(a_inv * (ALPHABET.index(c) - b)) % m].lower() for c in ciphertext)

def solve_linear_congruence(p1, c1, p2, c2, m):
    dp = (p1 - p2) % m
    dc = (c1 - c2) % m
    dp_inv = get_mod_inverse(dp, m)
    
    if dp_inv is not None:
        a = (dc * dp_inv) % m
        if a != 0:
            b = (c1 - a * p1) % m
            return a, b
    return None, None

def run_cryptanalysis(ciphertext, m):
    ciphertext = clean_text(ciphertext)
    
    frequencies = {c: ciphertext.count(c) for c in ALPHABET}
    
    print("HISTOGRAM:")
    for char in ALPHABET:
        if frequencies[char] > 0:
            print(f"{char}: {frequencies[char]}")
    print("\n")
    
    sorted_cipher = sorted(ALPHABET, key=lambda c: (-frequencies[c], c))[:6]
    sorted_plain = sorted(ALPHABET, key=lambda c: -P_ENG[c])[:6]
    
    print(f"TOP CIPHERTEXT LETTERS: {sorted_cipher}")
    print(f"TOP PLAINTEXT LETTERS:  {sorted_plain}")
    print("\n")
    
    tested_keys = set()
    
    for i in range(len(sorted_plain)):
        for j in range(i + 1, len(sorted_plain)):
            plain1_char = sorted_plain[i]
            plain2_char = sorted_plain[j]
            
            for cipher1_char in sorted_cipher:
                for cipher2_char in sorted_cipher:
                    if cipher1_char == cipher2_char:
                        continue
                        
                    p1 = ALPHABET.index(plain1_char)
                    c1 = ALPHABET.index(cipher1_char)
                    p2 = ALPHABET.index(plain2_char)
                    c2 = ALPHABET.index(cipher2_char)
                    
                    a, b = solve_linear_congruence(p1, c1, p2, c2, m)
                    
                    if a is not None and b is not None:
                        if (a, b) not in tested_keys:
                            tested_keys.add((a, b))
                            print(f"HYPOTHESIS: {cipher1_char}={plain1_char}, {cipher2_char}={plain2_char}")
                            
                            if math.gcd(a, m) != 1:
                                print(f"KEY (a, b) = ({a}, {b}) -> INVALID (gcd({a}, {m}) != 1)\n")
                            else:
                                decrypted = decrypt_text(ciphertext, a, b, m)
                                print(f"KEY (a, b) = ({a}, {b}) -> VALID")
                                print(f"DECRYPTED TEXT: {decrypted}\n")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_ciphertext = " ".join(sys.argv[1:])
    else:
        target_ciphertext = "FMXVEDKAPHFERBNDKRXRSREFMORUDSDKDVSHVUFEDKAPRKDLYEVLRHHRH"
        
    run_cryptanalysis(target_ciphertext,26)