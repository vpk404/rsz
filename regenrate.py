import sqlite3
import os
import sys

# Paths
DB_PATH = os.path.join("reports", "scanner.db")
RNON_TXT = os.path.join("reports", "rnon.txt")
RNONCE_TXT = os.path.join("reports", "rnonce.txt")

if not os.path.isfile(DB_PATH):
    print(f"ERROR: {DB_PATH} not found.")
    sys.exit(1)

print(f"Reading from {DB_PATH}...")
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

# Read all signatures using the correct column names
c.execute("SELECT address, txid, pubkey, r_hex, s_hex, z_hex FROM signatures")
rows = c.fetchall()
conn.close()

# Group by r
global_r_map = {}
for row in rows:
    addr, txid, pubkey, r_hex, s_hex, z_hexstr = row
    
    # Convert hex to integer
    if r_hex.startswith("0x"): r_hex = r_hex[2:]
    r_val = int(r_hex, 16)
    
    if s_hex.startswith("0x"): s_hex = s_hex[2:]
    s_val = int(s_hex, 16)
    
    if z_hexstr and z_hexstr.startswith("0x"): z_hexstr = z_hexstr[2:]
    z_val = int(z_hexstr, 16) if z_hexstr and z_hexstr != "N/A" else None
    
    if r_val not in global_r_map:
        global_r_map[r_val] = []
        
    global_r_map[r_val].append({
        "address": addr,
        "txid": txid,
        "pubkey": pubkey,
        "s": s_val,
        "z_original": z_val
    })

# Write reports
with open(RNONCE_TXT, "w", encoding="utf-8") as f_hr, open(RNON_TXT, "w", encoding="utf-8") as f_parse:
    for r_int, group in global_r_map.items():
        if len(group) < 2:
            continue
            
        r_hex = hex(r_int)[2:]
        if r_hex.endswith("L"): r_hex = r_hex[:-1]
        
        # Human readable
        f_hr.write("=" * 80 + "\n")
        f_hr.write("Reused Nonce Group\n")
        f_hr.write("=" * 80 + "\n")
        f_hr.write(f"r: {r_hex}\n")
        f_hr.write("Occurrences:\n")
        
        # Parsing friendly
        f_parse.write("=" * 80 + "\n")
        f_parse.write("Reused Nonce Group\n")
        f_parse.write("=" * 80 + "\n")
        f_parse.write(f"r: {r_hex}\n")
        f_parse.write("Occurrences:\n")
        
        seen = set()
        unique_sigs = []
        for item in group:
            key = (item.get("txid", "N/A"), item.get("s", "N/A"))
            if key in seen: continue
            seen.add(key)
            unique_sigs.append(item)
            
        if len(unique_sigs) < 2:
            continue
            
        for item in unique_sigs:
            txid = item.get("txid", "N/A")
            pk = item.get("pubkey") or "N/A"
            
            # Print human info
            f_hr.write(f" - txid={txid} pubkey={pk}\n")
            
            # Print parse info
            s_val = item.get("s", "N/A")
            s_format = hex(s_val)[2:] if isinstance(s_val, int) else str(s_val)
            z_val = item.get("z_original")
            z_format = hex(z_val)[2:] if z_val is not None else "N/A"
            
            f_parse.write(f" - txid={txid} s={s_format} z={z_format} pubkey={pk}\n")
            
        f_hr.write("\n")
        f_parse.write("\n")

print(f"Successfully generated {RNON_TXT} and {RNONCE_TXT}.")
