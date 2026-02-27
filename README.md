# crypto
Utility for generating keys and signing/verifying files with Dilithium and ML‑DSA keys.

## Table of Contents
- [Requirements](#requirements)
- [Build](#build)
- [Run](#run)
- [Supported algorithms](#supported-algorithms)
- [CLI Reference](#cli-reference)

## Requirements
- Rust toolchain (`cargo`, `rustc`)
- Git (required to fetch git-based dependencies during build)

## Build
1. Install Rust
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
    ```bash
    source "$HOME/.cargo/env"
    ```
2. Build project
    ```bash
    cargo build --release
    ```

## Run
```bash
cargo run -- <COMMAND> [OPTIONS]
```

After build, binary is available at:
```bash
./target/release/crypto
```

## Supported algorithms
- `dilithium2` (`dil2`)
- `dilithium3` (`dil3`)
- `dilithium5` (`dil5`)
- `mldsa44`
- `mldsa65`
- `mldsa87`

## CLI Reference
Main usage:
```bash
crypto <COMMAND> [OPTIONS]
```

Global options:
- `-h, --help` - show help
- `-V, --version` - show version

Accepted values:
- Algorithms (`--algorithm`):
  - `dilithium2` or `dil2`
  - `dilithium3` or `dil3`
  - `dilithium5` or `dil5`
  - `mldsa44`
  - `mldsa65`
  - `mldsa87`
- Formats (`--inform`, `--outform`):
  - `PEM`
  - `DER`

Important:
- `--inform` and `--outform` currently accept uppercase values only: `PEM` or `DER`.

### `generate`
Generate a key pair (private key is written to output).

Usage:
```bash
crypto generate --algorithm <ALGORITHM> [--outform PEM|DER] [--out FILE] [--entropy ENTROPY]
```

Arguments:
- `-a, --algorithm <ALGORITHM>` (required) - algorithm used for key generation
- `--outform <PEM|DER>` (optional, default: `PEM`) - output key format
- `--out <FILE>` (optional) - output path
- `--entropy <ENTROPY>` (optional) - base64 entropy/seed bytes

### `public`
Extract public key from the private key file.

Usage:
```bash
crypto public --in <FILE> [--inform PEM|DER] [--outform PEM|DER] [--out FILE]
```

Arguments:
- `-i, --in <FILE>` (required) - input private key file
- `--inform <PEM|DER>` (optional, default: `PEM`) - input key format
- `--outform <PEM|DER>` (optional, default: `PEM`) - output key format
- `-o, --out <FILE>` (optional) - output public key path

### `sign`
Sign file bytes with a private key.

Usage:
```bash
crypto sign --sec <FILE> --file <FILE> [--inform PEM|DER] [--out FILE]
```

Arguments:
- `--sec <FILE>` (required) - input private key file
- `--file <FILE>` (required) - file to sign
- `--inform <PEM|DER>` (optional, default: `PEM`) - private key format
- `--out <FILE>` (optional) - output signature path

### `verify`
Verify signature for a file using a public key.

Usage:
```bash
crypto verify --pub <FILE> --sig <FILE> --file <FILE> [--inform PEM|DER]
```

Arguments:
- `--pub <FILE>` (required) - input public key file
- `--sig <FILE>` (required) - input signature file
- `--file <FILE>` (required) - file to verify
- `--inform <PEM|DER>` (optional, default: `PEM`) - public key format
