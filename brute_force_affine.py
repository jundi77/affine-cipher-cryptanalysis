import time

# Change to true for verbosity
DEBUG = False
MAX_BYTES = 0xFF

class AffineException(Exception):
    def __init__(self, str, code=0, dump=None):
        self.code = code
        self.dump = dump
        super().__init__(str)

def debug_msg(*args, **kwargs):
    if DEBUG: print(*args, **kwargs)

def decrypt_affine(m_inverse, n, b, C):
    # P = m^-1 . (C - b) (mod n)
    return (m_inverse * (C - b)) % n

def brute_force(ciphertext):
    """
    Brute force will attempt to give every possible number
    from 0 to MAX_BYTES based on affine decryption equation
    for m^-1 and b.

    P = m^-1 . (C - b) (mod n)

    How do we know the brute force is succesful? Because given
    ciphertext is known to be in JPEG format, the file's header,
    where for JPEG is the first two bytes, are used to determine
    if brute force is successful. Based on this website:
        https://www.garykessler.net/library/file_sigs.html
    JPEG's first two bytes are:
        FF D8
    """

    header = ciphertext[:2]

    for i in range(1, MAX_BYTES + 1):
        for j in range(MAX_BYTES + 1):
            # here i is m^-1 and j is b
            if DEBUG: debug_msg(f"Affine brute force ({(i - 1) * MAX_BYTES + j}/{MAX_BYTES * (MAX_BYTES)})", 3)
            if decrypt_affine(i, MAX_BYTES + 1, j, header[0]) == 0xFF and decrypt_affine(i, MAX_BYTES + 1, j, header[1]) == 0xD8:
                return i, j

    return None, None


def decrypt(file_ciphertext, plaintext_decrypted_name='decrypted'):
    with open(file_ciphertext, 'rb') as f:
        ciphertext = f.read()

    # time the attempt
    # time.time() and time.time_ns() delta sometimes results in 0 because it's too fast
    start_attempt = time.perf_counter_ns()
    m_inverse, b = brute_force(ciphertext)
    duration_attempt = time.perf_counter_ns() - start_attempt

    print(f'Affine decryption with brute force took {duration_attempt / 1000000000}s')

    if m_inverse == None:
        if DEBUG: debug_msg("Affine brute force failed: key unknown after trying.", 1)
        return

    if DEBUG: debug_msg(f"Affine brute force success: m^-1={m_inverse}, b={b}", 2)

    plaintext = bytearray()
    for i in range(len(ciphertext)):
        plaintext += bytearray([decrypt_affine(
            m_inverse,
            MAX_BYTES + 1,
            b,
            ciphertext[i]
        )])

    with open(plaintext_decrypted_name, 'wb') as f:
        f.write(plaintext)

decrypt('affinecipher.jpeg', 'dec_brute.jpeg')