# Shamir's Secret Sharing — Python Implementation

[![PyPI](https://img.shields.io/pypi/v/shamir-lbodlev.svg?color=blue)](https://pypi.org/project/shamir-lbodlev/)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight and robust **Python implementation of Shamir’s Secret Sharing Scheme (SSS)**. This cryptographic technique splits a secret into multiple shares, requiring only a threshold number of shares to reconstruct the original secret. Ideal for secure key management and distributed systems.

## Features

- **Pure Python** with minimal dependencies (`pycryptodome`)
- Generate any number of secure shares with a configurable threshold
- Reconstruct secrets using only the threshold number of shares
- Support for both file-based and variable-based workflows
- Human-readable share export/import (JSON + Base64)
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

Create shares for a secret and export them to files.

```python
from shamir import Shamir

# Initialize with secret, total shares (n), and threshold (k)
shamir = Shamir(secret=b"My secret message", n=5, k=3)

# Export public parameters and shares
shamir.export_public("public.json")
shamir.export_shares("share{}.dat")  # Creates share1.dat, share2.dat, ...
```

This generates:
- `public.json`: Contains public data (prime `p`, total shares `n`, threshold `k`)
- `share1.dat`, `share2.dat`, ...: Base64-encoded share files

#### Reconstructing the Secret

Recover the secret using at least `k` shares.

```python
from shamir import Shamir

# Initialize recovery instance
recoverer = Shamir()

# Load public parameters and at least 3 shares
recoverer.load_public("public.json")
recoverer.load_shares("share{}.dat", indexes=[1, 3, 5])

# Recover the secret
secret = recoverer.recover()
print(secret.decode())  # Output: My secret message
```

### Example 2: Variable-Based Workflow

#### Splitting a Secret

Create shares and store them in variables.

```python
from shamir import Shamir

# Initialize with secret, total shares (n), and threshold (k)
shamir = Shamir(secret=b"My secret message", n=5, k=3)

# Get public parameters and shares
public_data = shamir.get_public()
shares = shamir.get_shares()
```

#### Reconstructing the Secret

Recover the secret using variables.

```python
from shamir import Shamir

# Initialize recovery instance
recoverer = Shamir()

# Set public parameters and at least 3 shares
recoverer.set_public(public_data)
recoverer.set_shares(shares[:3])  # Use first 3 shares

# Recover the secret
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

Reconstructs and returns the secret as bytes. Requires public parameters and at least `k` shares to be loaded.

**Example**:
```python
secret = recoverer.recover()
print(secret.decode())
```

---

### `export_public(filename: str) -> None`

Exports public parameters (`p`, `n`, `k`) to a JSON file.

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

Returns public parameters (`p`, `k`) as a dictionary.

**Example**:
```python
public_data = shamir.get_public()
# Returns: {'p': <prime>, 'k': <threshold>}
```

---

### `set_public(public_data: dict) -> None`

Sets public parameters from a dictionary. Requires keys `p` (prime) and `k` (threshold).

**Raises**: `ValueError` if `p` or `k` is missing.

**Example**:
```python
recoverer.set_public({'p': 123456789, 'k': 3})
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

Loads shares from files based on a template and a list of indexes. If more than `k` shares are provided, only the first `k` are used.

**Example**:
```python
recoverer.load_shares("share{}.dat", indexes=[1, 3, 5])
```

---

### `get_shares() -> list`

Returns the list of generated shares.

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

## Security Notes

- Shares are generated using a cryptographically secure random number generator (`secrets.token_bytes`).
- The finite field is defined by a large prime (`p`) to ensure security.
- Ensure shares are stored securely, as any `k` shares can reconstruct the secret.
- The implementation uses `pycryptodome` for secure prime generation and number conversions.

## How It Works

1. **Splitting**: The secret is converted to an integer and used as the constant term of a random polynomial of degree `k-1` in a finite field defined by a large prime `p`. Shares are points `(x, y)` on this polynomial.
2. **Reconstruction**: Using Lagrange interpolation modulo `p`, the secret is recovered from at least `k` shares.
3. **Storage**: Shares can be exported to files or handled as variables, with public parameters stored separately.

## 👤 Author

[Your Name and Details Here]

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
