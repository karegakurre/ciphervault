"""
aes_core.py — Implementasi AES-128 dari nol (tanpa library kriptografi)
Fungsi dasar kriptografi yang diimplementasi:
  1. SubBytes       — substitusi nonlinear menggunakan S-Box
  2. ShiftRows      — permutasi baris
  3. MixColumns     — transformasi linear di GF(2^8)
  4. AddRoundKey    — XOR dengan kunci ronde
  5. KeyExpansion   — penjadwalan kunci (key schedule)
"""

# ─── S-Box dan Inverse S-Box ───────────────────────────────────────────────────
# Dibangun dari perkalian invers di GF(2^8) + transformasi affine

def _gf_mul(a, b):
    """Perkalian di Galois Field GF(2^8) dengan modulus 0x11B."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gf_inv(a):
    """Invers multiplikatif di GF(2^8). GF_INV(0) = 0."""
    if a == 0:
        return 0
    result = 1
    base = a
    exp = 254  # a^254 = a^(-1) mod 2^8
    while exp > 0:
        if exp & 1:
            result = _gf_mul(result, base)
        base = _gf_mul(base, base)
        exp >>= 1
    return result


def _build_sbox():
    sbox = []
    for i in range(256):
        inv = _gf_inv(i)
        # Transformasi affine
        b = inv
        b ^= ((inv << 1) | (inv >> 7)) & 0xFF
        b ^= ((inv << 2) | (inv >> 6)) & 0xFF
        b ^= ((inv << 3) | (inv >> 5)) & 0xFF
        b ^= ((inv << 4) | (inv >> 4)) & 0xFF
        b ^= 0x63
        sbox.append(b & 0xFF)
    return sbox


def _build_inv_sbox(sbox):
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return inv


SBOX     = _build_sbox()
INV_SBOX = _build_inv_sbox(SBOX)

# Rcon untuk KeyExpansion
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


# ─── Operasi State (4×4 bytes) ─────────────────────────────────────────────────

def _bytes_to_state(block):
    """16 bytes → state 4×4 (kolom-major)."""
    return [[block[r + 4*c] for c in range(4)] for r in range(4)]


def _state_to_bytes(state):
    return bytes(state[r][c] for c in range(4) for r in range(4))


# Fungsi Kriptografi 1: SubBytes — substitusi nonlinear
def sub_bytes(state):
    return [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def inv_sub_bytes(state):
    return [[INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]


# Fungsi Kriptografi 2: ShiftRows — permutasi baris
def shift_rows(state):
    return [
        [state[r][(c + r) % 4] for c in range(4)]
        for r in range(4)
    ]


def inv_shift_rows(state):
    return [
        [state[r][(c - r) % 4] for c in range(4)]
        for r in range(4)
    ]


# Fungsi Kriptografi 3: MixColumns — transformasi linear di GF(2^8)
def _mix_col(col):
    return [
        _gf_mul(0x02, col[0]) ^ _gf_mul(0x03, col[1]) ^ col[2] ^ col[3],
        col[0] ^ _gf_mul(0x02, col[1]) ^ _gf_mul(0x03, col[2]) ^ col[3],
        col[0] ^ col[1] ^ _gf_mul(0x02, col[2]) ^ _gf_mul(0x03, col[3]),
        _gf_mul(0x03, col[0]) ^ col[1] ^ col[2] ^ _gf_mul(0x02, col[3]),
    ]


def _inv_mix_col(col):
    return [
        _gf_mul(0x0E, col[0]) ^ _gf_mul(0x0B, col[1]) ^ _gf_mul(0x0D, col[2]) ^ _gf_mul(0x09, col[3]),
        _gf_mul(0x09, col[0]) ^ _gf_mul(0x0E, col[1]) ^ _gf_mul(0x0B, col[2]) ^ _gf_mul(0x0D, col[3]),
        _gf_mul(0x0D, col[0]) ^ _gf_mul(0x09, col[1]) ^ _gf_mul(0x0E, col[2]) ^ _gf_mul(0x0B, col[3]),
        _gf_mul(0x0B, col[0]) ^ _gf_mul(0x0D, col[1]) ^ _gf_mul(0x09, col[2]) ^ _gf_mul(0x0E, col[3]),
    ]


def mix_columns(state):
    cols = [[state[r][c] for r in range(4)] for c in range(4)]
    mixed = [_mix_col(col) for col in cols]
    return [[mixed[c][r] for c in range(4)] for r in range(4)]


def inv_mix_columns(state):
    cols = [[state[r][c] for r in range(4)] for c in range(4)]
    mixed = [_inv_mix_col(col) for col in cols]
    return [[mixed[c][r] for c in range(4)] for r in range(4)]


# Fungsi Kriptografi 4: AddRoundKey — XOR dengan kunci ronde
def add_round_key(state, round_key):
    return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]


# Fungsi Kriptografi 5: KeyExpansion — penjadwalan kunci
def key_expansion(key: bytes) -> list:
    """Hasilkan 11 round key dari kunci 16 byte."""
    assert len(key) == 16, "Kunci harus 16 byte (AES-128)"
    w = [list(key[i:i+4]) for i in range(0, 16, 4)]  # 4 kata awal

    for i in range(4, 44):
        temp = w[i-1][:]
        if i % 4 == 0:
            # RotWord + SubWord + Rcon
            temp = [SBOX[temp[j]] for j in [1, 2, 3, 0]]
            temp[0] ^= RCON[i // 4]
        w.append([w[i-4][j] ^ temp[j] for j in range(4)])

    # Susun jadi 11 round key, masing-masing state 4×4
    round_keys = []
    for rnd in range(11):
        words = w[rnd*4:(rnd+1)*4]
        rk = [[words[c][r] for c in range(4)] for r in range(4)]
        round_keys.append(rk)
    return round_keys


# ─── Enkripsi & Dekripsi Satu Blok ────────────────────────────────────────────

def aes_encrypt_block(plaintext: bytes, round_keys: list) -> bytes:
    state = _bytes_to_state(plaintext)
    state = add_round_key(state, round_keys[0])
    for rnd in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    return _state_to_bytes(state)


def aes_decrypt_block(ciphertext: bytes, round_keys: list) -> bytes:
    state = _bytes_to_state(ciphertext)
    state = add_round_key(state, round_keys[10])
    for rnd in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[rnd])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return _state_to_bytes(state)
