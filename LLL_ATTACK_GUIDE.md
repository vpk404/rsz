# LLL Attack & Bit Leakage Guide

## 1. Understanding the Vulnerability (HNP)

The **Hidden Number Problem (HNP)** in the context of Bitcoin ECDSA signatures arises when the random nonce $k$ used in the signature generation is not perfectly uniform.

Standard ECDSA Signature:
$$ s = k^{-1} (z + r \cdot d) \pmod n $$

If $k$ is generated with a bias (e.g., the top 4 bits are always zero, or the value is always slightly smaller than $n$), information about the private key $d$ leaks.

With enough signatures (usually > 10) from the same private key, we can construct a **Lattice** and use the **LLL (Lenstra–Lenstra–Lovász)** algorithm to recover $d$.

---

## 2. Identifying Bit Leakage

"How do I know how many bits are leaking?"

### A. The "Black Box" Reality
In most cases, **you cannot look at the signatures ($r, s$) and "see" the leakage directly**, because the nonce $k$ is hidden behind the elliptic curve multiplication ($R = k \cdot G$).

However, there are two main ways to identify the leakage amount:

1.  **Statistical Heuristics (Weak Leakage)**:
    *   Occasionally, if the bias is *extreme* (e.g., 64-bit nonces), the value of $s$ might be smaller on average.
    *   `rszscan.py` automatically checks if the average bit-length of $s$ or $r$ is significantly lower than 256. If `avg_bits(s) < 250`, it's a strong indicator.

2.  **Iterative Guessing (The "Smart" Approach)**:
    *   This is what `attack_lll.sage` does.
    *   Most implementations that fail usually fail in specific ways (e.g., using a 32-bit PRNG, or having a 1-byte bias).
    *   **Common Leakages:**
        *   **4-bit Bias (252-bit nonce)**: Very common in some old Android wallets.
        *   **8-bit Bias (248-bit nonce)**: Common in implementations that mess up byte-arrays.
        *   **1-bit Bias (255-bit nonce)**: Very hard to crack, requires massive lattices (m > 100).

### B. Calculating the "Bias" Parameter
The "Bias" ($B$) is the number of bits *known* or *zero* in the nonce.
*   If $k$ is effectively 252 bits long (instead of 256), the Bias $B = 4$.
*   If $k$ is 240 bits long, Bias $B = 16$.

**Formula for Lattice Weight:**
To balance the LLL matrix, we scale the equations by $K$:
$$ K \approx 2^{256 - B} $$

---

## 3. How to Use the Tools Correctly

### Step 1: Scan & Collect Data
Run the scanner. It will automatically detect addresses with enough signatures (>10) to attempt an LLL attack.

```bash
# Scan a list of addresses
python rszscan.py -f targets.txt -l 50
```

*   **Note**: We set `-l 50` (limit 50 txs) because LLL attacks generally need between 10 and 50 signatures. Fetching thousands is unnecessary for the attack and slows down the lattice reduction.

### Step 2: Automatic vs Manual Attack
*   **Automatic**: If you have `sage` installed (Linux/WSL), `rszscan.py` will automatically run the attack for you when it finds a candidate.
*   **Manual**: If `rszscan.py` says "SageMath not found", look at the `reports/` folder.

```bash
# Example Output
reports/1A1z..._lll_data.json
```

Run the attack script manually:
```bash
sage attack_lll.sage reports/1A1z..._lll_data.json
```

### Step 3: Optimization for Low-End PCs

Lattice reduction is computationally expensive ($O(m^6)$ roughly).

*   **Lattice Dimension ($m$)**: The number of signatures used.
    *   $m=10$: Very fast (< 1 sec), but only works for HUGE bias (e.g., 64-bit nonces).
    *   $m=40$: Balanced (~10-30 secs), works for 4-bit to 8-bit bias.
    *   $m=80+$: Heavy (Minutes/Hours), needed for small bias (1-2 bits).

**Optimization Setting in `attack_lll.sage`:**
The script is currently optimized for low-end PCs:
```python
if m > 40:
    print("[!] Limiting analysis to first 40 signatures...")
    signatures = signatures[:40]
```
If you have a powerful PC and want to find smaller biases, increase this limit to 60 or 80 inside `attack_lll.sage`.

---

## 4. Troubleshooting Accuracy

**"100% Accuracy"** is achieved by verifying the answer.
The tool calculates a private key $d$, generates the corresponding public key $P' = d \cdot G$, and compares it to the target public key $P$.

*   If they match -> **100% Confirmed**.
*   If they don't match -> The attack failed (bias assumption was wrong, or not enough signatures).

The script does this verification automatically before saving to `RECOVERED_FUNDS_FINAL.csv`.

## 5. Summary of Attack Logic

1.  **Input**: $m$ signatures $(r_i, s_i)$ and message hashes (derived/approximated).
2.  **Matrix Construction**: Build a matrix where rows represent the equation $k_i - t_i d - u_i = 0$.
3.  **LLL Reduction**: Reduce the lattice to find short vectors.
4.  **Extraction**: The short vector contains the private key $d$ in the $(m)^{th}$ coefficient.
5.  **Check**: Does $d \cdot G == PubKey$?
    *   **Yes**: Save & Exit.
    *   **No**: Try next Bias assumption (e.g., try 248 bits instead of 252).
