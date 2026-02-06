# Public Key PEM Structure (This App)

This document describes exactly how the application builds a public key in PEM format.
PEM is just Base64 of DER bytes with header/footer. The real structure is DER.

## 1) PEM envelope

```
-----BEGIN PUBLIC KEY-----
BASE64(DER)
-----END PUBLIC KEY-----
```

The label is fixed to `PUBLIC KEY`.

## 2) DER structure (SPKI)

The DER bytes follow X.509 SubjectPublicKeyInfo:

```
SubjectPublicKeyInfo ::= SEQUENCE {
  algorithm         AlgorithmIdentifier,
  subjectPublicKey  BIT STRING
}

AlgorithmIdentifier ::= SEQUENCE {
  algorithm  OBJECT IDENTIFIER
}
```

### Byte layout (DER)

```
30 xx                      ; SEQUENCE (whole SPKI)
   30 yy                   ; SEQUENCE (AlgorithmIdentifier)
      06 zz                ; OBJECT IDENTIFIER
         <OID bytes>       ; OID of the algorithm
   03 ww                   ; BIT STRING
      00                   ; number of unused bits = 0
      <PUBLIC_KEY_BYTES>   ; raw public key bytes
```

Important detail: BIT STRING always starts with a single `00` byte
(unused bits count), then raw key bytes.

## 3) Where PUBLIC_KEY_BYTES come from

`PUBLIC_KEY_BYTES` are the raw public key bytes for the selected algorithm.
They are placed directly into the BIT STRING after the single `00` byte
(unused bits count).

## 4) Public key sizes (bytes)

Sizes depend on algorithm:

- Dilithium2: 1312
- Dilithium3: 1952
- Dilithium5: 2592
- ML-DSA-44: 1312
- ML-DSA-65: 1952
- ML-DSA-87: 2592

## 5) DER length encoding (quick rules)

- If length < 128: one byte length.
- If length >= 128: first length byte is `0x80 + N`,
  followed by `N` bytes with the length.

Example: `0x03 0x82 0x05 0x1B` means BIT STRING, length 0x051B.

## 6) Example layout (schematic)

For ML-DSA-44 (public key 1312 bytes):

```
30 82 05 xx          ; SEQUENCE, total length (example)
   30 0B             ; AlgorithmIdentifier, length 11 (example)
      06 09 <OID>    ; OID bytes
   03 82 05 21       ; BIT STRING, length 0x0521
      00             ; unused bits
      <1312 bytes>   ; public key
```

Actual lengths depend on the chosen OID and DER encoder output.
