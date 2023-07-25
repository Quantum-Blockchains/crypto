# crypto
Utility for generating, sign and verification message with Dilithium keys.
## Comands
1. generate - generate key pair
    ```bash
   crypto generate --alg dilithium5 --out keypair
    ```
2. public - pull the public key from the pair
    ```bash
    crypto public --in keypair --out key.pub
    ```
3. sign - sign the message
    ```bash
    crypto sign -m message.txt --in keypair --out signature
    ```
4. verify - message verification
   ```bash
    crypto verify -m message.txt --sig signature --in key.pub
    ```

