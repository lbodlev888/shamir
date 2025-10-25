# Shamir's Secret Sharing — Python Implementation

[![PyPI](https://img.shields.io/pypi/v/shamir-lbodlev.svg?color=blue)](https://pypi.org/project/shamir-lbodlev/)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight and robust **Python implementation of Shamir’s Secret Sharing Scheme (SSS)**. This cryptographic technique splits a secret into multiple shares, requiring only a threshold number of shares to reconstruct the original secret. Ideal for secure key management and distributed systems. This implementation also incorporates Feldman's Verifiable Secret Sharing (VSS) for verifying the validity of shares using commitments.

## Features

- **Pure Python** with minimal dependencies (`pycryptodome`)
- Generate any number of secure shares with a configurable threshold
- Reconstruct secrets using only the threshold number of shares
- Support for both file-based and variable-based workflows
- Human-readable share export/import (Base64)
- Verifiable shares using Feldman's VSS scheme with commitments
- Simple and intuitive API
- MIT License for flexible use

## Installation

Install the package via PyPI:

```bash
pip install shamir-lbodlev
```

## Usage

### Importing the Package

```python
from shamir import Shamir
```

### Example 1: File-Based Workflow

#### Splitting a Secret

Create shares for a secret and export them to files. This example also computes commitments for later verification using Feldman's scheme.

```python
from shamir import Shamir
import json

# Initialize with secret, total shares (n), and threshold (k)
shamir = Shamir(secret=b"My secret message", n=5, k=3)

# Export public parameters and shares
shamir.export_public("public.json")
shamir.export_shares("share{}.dat")  # Creates share1.dat, share2.dat, ...

# Compute and export commitments for Feldman's VSS verification
commitments = shamir.compute_commitments()
with open("commitments.json", "w") as f:
    json.dump(commitments, f)
```

This generates:
- `public.json`: Contains public data (prime `p`, Sophie Germain prime `q`, generator `g`, threshold `k`)
- `share1.dat`, `share2.dat`, ...: Base64-encoded share files
- `commitments.json`: List of commitments for share verification

#### Verifying and Reconstructing the Secret

Verify shares using Feldman's scheme and recover the secret using at least `k` shares. Note: The `verify_share` method returns `True` if valid or raises `ValueError` if invalid.

```python
from shamir import Shamir
import json

# Initialize recovery instance
recoverer = Shamir()

# Load public parameters, commitments, and at least 3 shares
recoverer.load_public("public.json")
with open("commitments.json", "r") as f:
    commitments = json.load(f)
recoverer.set_commitments(commitments)

# Verify shares using Feldman's scheme (example for shares 1, 3, 5)
indexes = [1, 3, 5]
for index in indexes:
    filename = f"share{index}.dat"
    try:
        if recoverer.verify_share(filename=filename):
            print(f"{filename} is valid")
    except ValueError:
        print(f"{filename} is invalid")

# Load verified shares and recover the secret
recoverer.load_shares("share{}.dat", indexes=indexes)

# Recover the secret (uses the first k loaded shares)
secret = recoverer.recover()
print(secret.decode())  # Output: My secret message
```

### Example 2: Variable-Based Workflow

#### Splitting a Secret

Create shares and store them in variables. This example also computes commitments for later verification using Feldman's scheme.

```python
from shamir import Shamir

# Initialize with secret, total shares (n), and threshold (k)
shamir = Shamir(secret=b"My secret message", n=5, k=3)

# Get public parameters, shares, and commitments
public_data = shamir.get_public()
shares = shamir.get_shares()
commitments = shamir.compute_commitments()
```

#### Verifying and Reconstructing the Secret

Verify shares using Feldman's scheme and recover the secret using variables.

```python
from shamir import Shamir

# Initialize recovery instance
recoverer = Shamir()

# Set public parameters and commitments
recoverer.set_public(public_data)
recoverer.set_commitments(commitments)

# Verify shares using Feldman's scheme (example for first 3 shares)
selected_shares = shares[:3]
for share in selected_shares:
    try:
        if recoverer.verify_share(raw_share=share):
            print("Share is valid")
    except ValueError:
        print("Share is invalid")

# Set verified shares and recover the secret
recoverer.set_shares(selected_shares)

# Recover the secret (uses the first k loaded shares)
secret = recoverer.recover()
print(secret.decode())  # Output: My secret message
```

## API Reference

### `Shamir(secret: bytes | None = None, n: int | None = None, k: int | None = None)`

Initializes a Shamir instance for splitting or recovering a secret.

| Parameter | Type              | Description                                                |
|-----------|-------------------|------------------------------------------------------------|
| `secret`  | `bytes`, optional | The secret to split (as bytes).                            |
| `n`       | `int`, optional   | Total number of shares to generate.                        |
| `k`       | `int`, optional   | Minimum number of shares needed to reconstruct the secret. |

**Raises**: `ValueError` if `k > n`.

---

### `recover() -> bytes`

Reconstructs and returns the secret as bytes. Requires public parameters and at least `k` shares to be loaded. Uses the first `k` loaded shares for reconstruction.

**Example**:
```python
secret = recoverer.recover()
print(secret.decode())
```

---

### `export_public(filename: str) -> None`

Exports public parameters (`p`, `q`, `g`, `k`) to a JSON file.

**Example**:
```python
shamir.export_public("public.json")
```

---

### `load_public(filename: str) -> None`

Loads public parameters from a JSON file.

**Example**:
```python
recoverer.load_public("public.json")
```

---

### `get_public() -> dict`

Returns public parameters (`p`, `q`, `g`, `k`) as a dictionary.

**Example**:
```python
public_data = shamir.get_public()
# Returns: {'p': <prime>, 'q': <Sophie Germain prime>, 'g': <generator>, 'k': <threshold>}
```

---

### `set_public(public_data: dict) -> None`

Sets public parameters from a dictionary. Supports keys `p` (prime), `q` (Sophie Germain prime), `g` (generator), and `k` (threshold).

**Example**:
```python
recoverer.set_public({'p': 123456789, 'q': 61728394, 'g': 5, 'k': 3})
```

---

### `export_shares(template: str) -> None`

Exports shares to files using a filename template (e.g., `share{}.dat`).

**Example**:
```python
shamir.export_shares("share{}.dat")  # Creates share1.dat, share2.dat, ...
```

---

### `load_shares(template: str, indexes: list[int]) -> None`

Loads shares from files based on a template and a list of indexes. Loads all specified shares, but reconstruction uses only the first `k`.

**Example**:
```python
recoverer.load_shares("share{}.dat", indexes=[1, 3, 5])
```

---

### `get_shares() -> list`

Returns the list of generated shares as Base64-encoded strings.

**Example**:
```python
shares = shamir.get_shares()
```

---

### `set_shares(shares: list) -> None`

Sets shares from a list of Base64-encoded strings.

**Example**:
```python
recoverer.set_shares(shares[:3])  # Use first 3 shares
```

---

### `compute_commitments() -> list`

Generates and returns a list of commitments for verifying shares using Feldman's VSS scheme.

**Example**:
```python
commitments = shamir.compute_commitments()
```

---

### `set_commitments(commitments: list) -> None`

Sets the list of commitments used for verifying shares with Feldman's VSS scheme.

**Example**:
```python
recoverer.set_commitments(commitments)
```

---

### `verify_share(raw_share: str | None = None, filename: str | None = None) -> bool`

Verifies the validity of a share using Feldman's VSS scheme. Requires commitments to be set. Provide either a raw Base64-encoded share string or a filename.

Returns `True` if valid; raises `ValueError` if invalid or no input mode specified.

**Example**:
```python
try:
    if recoverer.verify_share(raw_share=share):
        print("Valid")
except ValueError:
    print("Invalid")
```

## Security Notes

- Shares are generated using a cryptographically secure random number generator (`secrets.token_bytes`).
- The finite field is defined by a large safe prime `p = 2q + 1` (where `q` is also prime) to ensure security.
- Feldman's VSS allows verification of shares without revealing the secret, using discrete logarithm commitments in the subgroup of order `q` modulo `p`.
- Ensure shares and commitments are stored securely, as any `k` valid shares can reconstruct the secret.
- The implementation uses `pycryptodome` for secure prime generation and number conversions.

## How It Works

1. **Splitting**: The secret is converted to an integer and used as the constant term of a random polynomial of degree `k-1` in a finite field modulo `q`. Shares are points `(x, y)` on this polynomial.
2. **Verification**: Using Feldman's VSS, commitments to the polynomial coefficients are generated modulo `p`. Each share can be verified against these commitments without revealing the secret.
3. **Reconstruction**: Using Lagrange interpolation modulo `q`, the secret is recovered from at least `k` shares.
4. **Storage**: Shares can be exported to files or handled as variables, with public parameters and commitments stored separately.

## 👤 Author

- Bodlev Laurentiu
- 📍 Cahul, Republic of Moldova
- 💡 Passionate about cryptography, networking, and distributed systems.
- 🌐 GitHub: https://github.com/lbodlev888

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
