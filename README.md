# crypto
Utility for generating keys and signing/verifying files with Dilithium and ML‑DSA keys.
## Build
1. install rust
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
    ```bash
    $HOME/.cargo/env
    ```
2. install make
    ```bash
    sudo apt update
    ```
    ```bash
    sudo apt install make
    ```
3. build project
    ```bash
    make
    ```
## Comands
Supported algorithms:
- `dilithium2` (`dil2`)
- `dilithium3` (`dil3`)
- `dilithium5` (`dil5`)
- `mldsa44`
- `mldsa65`
- `mldsa87`

Formats:
- `PEM` (default)
- `DER`

1. generate - generate key pair 
    ```bash
    crypto generate --algorithm dilithium5 --out key.pem
    crypto generate --algorithm mldsa44 --out key_m44.der --outform DER
    ```
2. public - pull the public key from the pair
    ```bash
    crypto public --in key.pem --out pub.pem
    crypto public --in key_m44.der --inform DER --out pub_m44.der --outform DER
    ```
3. sign - sign the file (signs the full file bytes)
    ```bash
    crypto sign --sec key.pem --out signature --file <PATH>
    ```
4. verify - verification the file
   ```bash
    crypto verify --sig signature --pub pub.pem --file <PATH>
    ```
