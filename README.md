# ModelSim Decryptor
## Disclaimer

This repository and the code within it are provided **for security research and education only**.

Only use it on systems and files you own or are explicitly authorized to test. Decrypting third-party protected IP may violate license agreements and local, state, national, or international law. You are solely responsible for how you use this software.

The software is provided "as is", without warranty of any kind, express or implied. The authors and contributors accept no liability for any damages, legal consequences, or misuse arising from its use.

This project allows people to decrypt IEEE 1735 Design IP for ModelSim V2022.3 and older. This is due to an improper white-box decryption implementation: CVE-2021-42023.

The inspiration for this project comes from "How Not to Protect Your IP – An Industry-Wide Break of IEEE 1735 Implementations" (https://doi.org/10.48550/arXiv.2112.04838), and the final lab for 469.

*This is my first attempt at using AI agents for security research.*

## Usage

The decryptor lives in `src/ms_decrypt.py`. It uses the standard
[`cryptography`](https://cryptography.io) library and loads the RSA private key
from a PEM file (`keys/mgc_verif_sim_rsa_1.pem` by default). No ModelSim
installation is needed at run time.

Install the dependency first:

```bash
pip install -r requirements.txt
```

Decrypt a single protected file (writes `file.svp.decrypted` next to it):

```bash
python3 src/ms_decrypt.py rtl/file.svp
```

Decrypt every `.svp` in a directory into `out/`:

```bash
python3 src/ms_decrypt.py --outdir out rtl/*.svp
```

Print the plaintext instead of writing a file:

```bash
python3 src/ms_decrypt.py --stdout rtl/file.svp
```

Full option list:

```bash
python3 src/ms_decrypt.py --help
```

| Option            | Description                                                   |
| ----------------- | ------------------------------------------------------------- |
| `files`           | One or more `.svp` files; shell globs are expanded.           |
| `--key PATH`      | RSA private key PEM (default `keys/mgc_verif_sim_rsa_1.pem`). |
| `--outdir DIR`    | Write decrypted files into `DIR`.                             |
| `--suffix SUFFIX` | Output suffix (default `.decrypted`).                         |
| `--stdout`        | Print plaintext to standard output.                           |

### How it works

For each file the script parses the IEEE 1735 digital envelope, then:

1. RSA-decrypts the `key_block` (PKCS#1 v1.5) to recover the 128-bit AES session key.
2. AES-128-CBC decrypts the `data_block`; ModelSim stores the 16-byte IV prepended
   in the clear to the ciphertext.
3. Strips the PKCS#7 padding and writes the recovered HDL source.

The value of this vulnerability is that ModelSim hard-codes its RSA private keys in
the `vlog`/`vcom` binaries. They are only lightly obscured: each byte is mangled with
`mangle(b) = ror8(b, 7) ^ 0x77`, and the `get_sim_1_key_*` accessors expose the
components. Applying the inverse (`rol8(b ^ 0x77, 7)`) and validating `n == p*q` and
`d*e ≡ 1 (mod (p-1)(q-1))` recovers the plaintext key, which is stored as
`keys/mgc_verif_sim_rsa_1.pem`. The same method works for the other built-in keys
(e.g. `MGC-DVT-MTI` via `get_mti_key_*`); recover one, save it as a PEM, and pass it
with `--key`.
