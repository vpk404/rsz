# VPK Bitcoin RSZ Toolkit

A high-performance toolkit for identifying and recovering Bitcoin private keys from ECDSA signature vulnerabilities (Nonce Reuse, Cyclic Matrix Loops, and Algebraic Chaining).

## 🚀 Overview

This toolkit provides a complete pipeline for Bitcoin forensic analysis:
1. **Scanning**: Extracting signatures from the blockchain and identifying vulnerabilities.
2. **Regeneration**: Rebuilding recovery groups from a SQLite database.
3. **Recovery**: Mathematically solving for private keys using a waterfall recovery engine.

---

## 🛠 Tools

### 1. `rszscan.py` (The Scanner)
The core high-speed scanner designed to ingest Bitcoin addresses and extract ECDSA signatures.
- **Functionality**: Extracts `(r, s, z)` components from transaction inputs.
- **Support**: Handles Legacy, SegWit (P2WPKH), Nested SegWit (P2SH-P2WPKH), and Multisig.
- **Database**: Saves all unique signatures to a SQLite database (`scanner.db`) for persistent analysis.
- **Usage**:
  ```bash
  python3 rszscan.py -i addresses.txt
  ```

### 2. `recover.py` (The Solver)
A standalone, highly optimized mathematical recovery engine.
- **Methods**:
  - **Bootstrap**: Recovers keys from a single public key using the same nonce ($r$) twice.
  - **Matrix Solver**: Uses Gaussian Elimination to solve complex cyclic loops where multiple keys share different nonces.
  - **Chaining**: Uses one recovered private key to unlock all other compromised signatures sharing the same nonces.
- **Output**: Generates `RECOVERED_FUNDS_FINAL.csv` (Pubkey, Address, PrivKey, WIF, Method).
- **Speed**: Capable of solving thousands of signatures in seconds.
- **Usage**:
  ```bash
  python3 recover.py
  ```

### 3. `regenrate.py` (The Data Rebuilder)
Utility to reconstruct recovery files from the database.
- **Functionality**: Reads the SQLite `signatures` table and generates `rnon.txt` and `rnonce.txt`.
- **Purpose**: Useful for moving data between different recovery environments or manually inspecting reused nonce groups.
- **Usage**:
  ```bash
  python3 regenrate.py
  ```

---

## 📂 Output Format

The recovery tool generates a professional report in `RECOVERED_FUNDS_FINAL.csv`:

| Column | Description |
| :--- | :--- |
| **pubkey** | The hex-encoded public key. |
| **address** | The Legacy P2PKH address (Compressed/Uncompressed). |
| **priv_hex** | The raw 32-byte private key in hex. |
| **wif** | Wallet Import Format (Ready for import into Electrum/Core). |
| **method** | The mathematical attack that recovered the key. |

---

## ⚠️ Requirements

- Python 3.8+
- `ecdsa`
- `coincurve` (highly recommended for 100x speed)
- `sqlite3`

---

## ⚖️ Disclaimer
This tool is for educational and forensic purposes only. Always ensure you have legal authorization before performing cryptographic analysis.
