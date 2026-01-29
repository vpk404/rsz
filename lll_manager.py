#!/usr/bin/env python3
# ==============================================================================
# LLL ATTACK MANAGER (Phase 2 Recovery)
# Manages SageMath LLL attacks on collected signature data.
# ==============================================================================

import os
import sys
import shutil
import subprocess
import csv
import json
import time

# Config
OUTPUT_DIR = "reports"
OUTPUT_CSV = "RECOVERED_FUNDS_FINAL.csv"

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
        except Exception:
            pass
    return recovered

def start_batch_lll_recovery():
    print("\n" + "="*80)
    print("PHASE 2: LLL ATTACK MODULE (SageMath Manager)")
    print("="*80)

    # Check for Sage
    sage_path = shutil.which("sage")
    if not sage_path:
        print("[!] SageMath not found. Cannot execute LLL attacks.")
        print("    Please install SageMath or run 'sage attack_lll.sage <file>' manually.")
        return

    # Identify candidates
    candidates = []
    if os.path.isdir(OUTPUT_DIR):
        for f in os.listdir(OUTPUT_DIR):
            if f.endswith("_lll_data.json"):
                candidates.append(os.path.join(OUTPUT_DIR, f))

    if not candidates:
        print("[-] No LLL candidate files found in 'reports/'.")
        print("    Run 'python rszscan.py' first to collect data.")
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

            # Run Sage script
            # We use check=False so one failure doesn't stop the batch
            subprocess.run([sage_path, "attack_lll.sage", json_file], check=False)

            # Refresh recovered list in case the attack succeeded
            recovered = load_recovered_addresses()

        except Exception as e:
            print(f"[!] Error processing {json_file}: {e}")

if __name__ == "__main__":
    try:
        start_batch_lll_recovery()
    except KeyboardInterrupt:
        print("\n[!] LLL Manager interrupted.")
