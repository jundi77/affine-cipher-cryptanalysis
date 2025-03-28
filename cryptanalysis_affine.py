import random
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

def modulo_formula(p, q):
    """
    q = kp + r
    """

    if type(p) != int or type(q) != int:
        raise AffineException("Either p or q must be integers.", 1)

    # p must be less or equal to q so that the formula works
    if p > q: return modulo_formula(q, p)

    return {
        'p': p,
        'q': q,
        'k': q // p,
        'r': q % p
    }

def fill_gcd_affine(m, n):
    if n <= m:
        raise AffineException('m must be smaller than n.', 2)

    gcd_affine = []

    gcd_affine.append(modulo_formula(m, n))
    if DEBUG: debug_msg(f'fill_gcd_affine({m}, {n}):', gcd_affine[-1])

    while gcd_affine[-1]['r'] != 0:
        gcd_affine.append(
            modulo_formula(gcd_affine[-1]['r'], gcd_affine[-1]['p'])
        )

        if DEBUG: debug_msg(
            f'fill_gcd_affine({gcd_affine[-2]["r"]}, {gcd_affine[-2]["p"]}):', gcd_affine[-1]
        )

    if gcd_affine[-2]['r'] != 1:
        raise AffineException('m and n is not relatively prime to each other.', 3, gcd_affine)

    return gcd_affine

def m_inverse_affine(m, n):
    """
    (m, n) = d

    In affine, m as one of the encryption key must be relatively prime to
    n, while n stands for maximum value. Because of this, the d value become
    1:
        (m, n) = 1

    Then we need to find a combination that fulfills:
        mx + ny = 1
    
    We can find that combination by doing gcd until the r on the modulo
    formula is 1, then backtracks to substitute subsequent p and q on the
    combination formula to find what combination of m and n fulfills r = 1.
        q = kp + r
        q - kp = r
        q - kp = 1 (because they do be relatively prime to each other)

        1 = q - kp
    """

    if n <= m:
        raise AffineException(f'm must be smaller than n. (m={m}, n={n})', 4)

    # python list
    gcd_modulo_formulas = fill_gcd_affine(m, n)

    # initialize bezout's identity used for mx + ny = 1
    affine_bezout_identity = None

    """
    backtrack the gcd modulo formula from r = 1 until p and q on
    gcd_modulo_formulas equals to m and n.
    """
    while len(gcd_modulo_formulas) > 0:
        gcd_modulo_formula = gcd_modulo_formulas.pop()
        if gcd_modulo_formula['r'] == 0: continue

        """
        Because of
            q = kp + 1, 1 = q - kp
        backtracking to previous gcd iteration requires k to be
        multiplied by -1.
        """
        gcd_modulo_formula['k'] *= -1

        if affine_bezout_identity == None:
            """
            q = kp + 1, 1 = q - kp

            -k need to be stored so that the formula can resemble
            ax + by = d
                1 = q - kp
                1 = q + (-k)p
            
            following that n must be greater than m, n is filled with
            q because q also must be greater or equal than p in this case.
                1 = 1.n + (-k).m (first iteration)
            """
            affine_bezout_identity = {
                'm': gcd_modulo_formula['p'],
                'x': gcd_modulo_formula['k'],
                'n': gcd_modulo_formula['q'],
                'y': 1
            }
            if DEBUG: debug_msg(f'm_inverse_affine({m}, {n}), {len(gcd_modulo_formulas)} iteration left:', affine_bezout_identity)
            continue

        # multiply x with k, add the result to y
        affine_bezout_identity['y'] += affine_bezout_identity['x'] * gcd_modulo_formula['k']

        # update m with q
        affine_bezout_identity['m'] = gcd_modulo_formula['q']

        """
        Swap mx and ny, as this function needs strict enforcing where
        n must be greater than m.

        As more backtracking is done, m in (-k)m will always get bigger.
        """
        affine_bezout_identity['m'], affine_bezout_identity['n'] = affine_bezout_identity['n'], affine_bezout_identity['m']
        affine_bezout_identity['x'], affine_bezout_identity['y'] = affine_bezout_identity['y'], affine_bezout_identity['x']

        if DEBUG: debug_msg(f'm_inverse_affine({m}, {n}), {len(gcd_modulo_formulas)} iteration left:', affine_bezout_identity)
    

    """
    Alas, x is the modular inverse. But! If x is negative, it may cause
    problems since, in affine, character (if using character) position is
    indexed in positive value (e.g. 1 is a).
    """
    if affine_bezout_identity['x'] < 0:
        affine_bezout_identity['x'] = n + affine_bezout_identity['x']

    if DEBUG: debug_msg(f'm_inverse_affine({m}, {n}) =', affine_bezout_identity['x'])
    return affine_bezout_identity['x']

def decrypt_affine(m, n, b, C, is_m_inverse=False):
    # P = m^-1 . (C - b) (mod n)

    if is_m_inverse:
        # if given m is supposedly the inverse of the actual m value
        return (m * (C - b)) % n

    return (m_inverse_affine(m, n) * (C - b)) % n

def analyze_known_plaintext(known_plaintext, known_ciphertext):
    """
    known_plaintext and known ciphertext is a python list of a
    bytearray, read from a related file.
    related bytes (p => c) must be in order.
    """

    if len(known_plaintext) != len(known_ciphertext):
        raise AffineException("Known plaintext and known ciphertext has different size.", 5)
    elif len(known_plaintext) < 2:
        raise AffineException("Need more than one of known plaintext.", 6)

    # *_p and *_c here means plaintext and ciphertext

    first_eq_index = random.randint(0, len(known_plaintext) - 1)
    first_p, first_c = known_plaintext.pop(first_eq_index), known_ciphertext.pop(first_eq_index)

    second_eq_index = random.randint(0, len(known_plaintext) - 1)
    second_p, second_c = known_plaintext.pop(second_eq_index), known_ciphertext.pop(second_eq_index)

    # swap if first_p is smaller than second_p, may easier to debug due to consistency
    if first_p < second_p:
        first_p, first_c, second_p, second_c = second_p, second_c, first_p, first_c

    if DEBUG: debug_msg(f'analyze_known_plaintext(p1, c1, p2, c2): {first_p}, {first_c}, {second_p}, {second_c}')
    p = first_p - second_p
    c = first_c - second_c
    if DEBUG: debug_msg(f'analyze_known_plaintext after substraction(p, c): {p}, {c}')

    """
    At this point, we have p and c, so that:
        c ≡ m.p + b (mod n)
    where n stands for MAX_BYTES + 1 as we read from a binary file.

    Because first and second known plain-ciphertext has the same b,
    by substracting each other, the equation becomes:
        c ≡ m.p (mod n)
    
    By now it can branch to two possible situation:
    1. If p and n is relatively prime to each other, then the
    solution becomes:
        c.p^-1 ≡ m (mod n)
    because (p, n) = 1, there is a solution.
    2. If p and n is not relatively prime to each other, then it's
    needed to check if (p, n) divides c.
        2.1. If (p, n) does not divide c, there is no solution.
        2.2. If (p, n) divides c, divide p, n, and c with (p, n),
        then go back to 1.
    """
    n = MAX_BYTES + 1
    try:
        # Situation 1
        p_inverse = m_inverse_affine(p, n)
        m = (c * p_inverse) % n
        if DEBUG: debug_msg(f'analyze_known_plaintext, situation 1 (p^-1, m): {p_inverse}, {m}')
    except AffineException as ae:
        if ae.code == 3:
            # Situation 2
            if c % ae.dump[-1]['p'] == 0:
                # Situation 2.2
                p_inverse = m_inverse_affine(
                    p // ae.dump[-1]['p'],
                    n // ae.dump[-1]['p']
                )
                m = ((c // ae.dump[-1]['p']) * p_inverse) % (n // ae.dump[-1]['p'])
                if DEBUG: debug_msg(f'analyze_known_plaintext, situation 2.2 (p^-1, m): {p_inverse}, {m}')
            else:
                # Situation 2.1
                if DEBUG: debug_msg('analyze_known_plaintext, situation 2.1 (p^-1, m): None, None')
                raise AffineException("No solution exists from known plaintext.", 7)

    # m is found, now find b based on affine ciphertext equation
    b = (first_c - first_p * m) % n

    return {
        'm': m,
        'm^-1': m_inverse_affine(m, MAX_BYTES + 1),
        'b': b
    }

def analyze_affine(file_known_plaintext, file_known_ciphertext):
    with open(file_known_plaintext, 'rb') as f:
        known_plaintext = list(f.read())

    with open(file_known_ciphertext, 'rb') as f:
        known_ciphertext = list(f.read())

    return analyze_known_plaintext(known_plaintext, known_ciphertext)

def decrypt_from_known_plaintext(file_ciphertext, file_known_plaintext, file_known_ciphertext, plaintext_decrypted_name='decrypted'):
    # time the attempt
    # time.time() and time.time_ns() delta sometimes results in 0 because it's too fast
    start_attempt = time.perf_counter_ns()
    affine_parameters = analyze_affine(file_known_plaintext, file_known_ciphertext)
    duration_attempt = time.perf_counter_ns() - start_attempt

    print(f'Affine cryptanalysis with known plaintext took {duration_attempt / 1000000000}s, with m={affine_parameters["m"]} and b={affine_parameters["b"]}')

    with open(file_ciphertext, 'rb') as f:
        ciphertext = f.read()

    plaintext = bytearray()

    for i in range(len(ciphertext)):
        plaintext += bytearray([decrypt_affine(
            affine_parameters['m^-1'],
            MAX_BYTES + 1,
            affine_parameters['b'],
            ciphertext[i],
            is_m_inverse=True
        )])

    with open(plaintext_decrypted_name, 'wb') as f:
        f.write(plaintext)

decrypt_from_known_plaintext('affinecipher.jpeg', 'known_plaintext', 'known_ciphertext', 'dec.jpeg')