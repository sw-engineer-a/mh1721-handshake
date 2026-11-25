# MH1721 RSA handshake

Two separate projects that use the `mh-rsa` parameters:

| Folder | What it is |
|---|---|
| `keil` | Keil µVision 5 project. Open `MH1721_Handshake.uvprojx`. |
| `android` | Android app. Open this folder in Android Studio. |

The key is the 512-bit `mh-rsa` sample. `u16NBits` is 512, so N and D are 64 bytes. `u16EBits` is 32, so E is the 4 bytes `00 01 00 01`. Public and private operations are raw modular exponentiation, the same as `MHRSA_Pub`, `MHRSA_Pri`, and `MHRSA_Crt`. Input and output are both 64 bytes. The firmware opens a ciphertext with `MHRSA_Crt`.

The bytes live in `keil/src/key.h` and `android/.../Keys.java`.

- **N** (`pu8N`): public modulus. Encryption and decryption reduce modulo N. N = P × Q.
- **E** (`pu8E`): public exponent. `MHRSA_Pub` computes plaintext^E mod N.
- **D** (`pu8D`): private exponent. `MHRSA_Pri` computes ciphertext^D mod N.
- **P, Q**: the two prime factors of N.
- **DP**: D mod (P − 1). One half of the `MHRSA_Crt` private operation.
- **DQ**: D mod (Q − 1). The other half of `MHRSA_Crt`.
- **QI**: Q⁻¹ mod P. `MHRSA_Crt` uses it to join the two halves into the plaintext.

| Function | Parameter | mh-rsa | Keil | Android |
|---|---|---|---|---|
| `MHRSA_SetKey` | `u16NBits` | 512 | `RSA_N_BITS` 512 | 64-byte modulus |
| `MHRSA_SetKey` | `pu8N` | `RSA_N_512`, 64 bytes | `RSA_N` | `Keys.MODULUS` |
| `MHRSA_SetKey` | `u16EBits` | 32 | `RSA_E_BITS` 32 | 4-byte exponent |
| `MHRSA_SetKey`, `MHRSA_Pub` | `pu8E` | `00010001` | `RSA_E` | `Keys.PUBLIC_EXPONENT` |
| `MHRSA_SetKey`, `MHRSA_Pri` | `pu8D` | `RSA_D_512`, 64 bytes | `RSA_D` | `Keys.PRIVATE_EXPONENT` |
| `MHRSA_SetKey`, `MHRSA_Crt` | `pu8P`, `pu8Q`, `pu8Dp`, `pu8Dq`, `pu8Qi` | 32 bytes each | the same 32-byte values | not stored; the phone decrypts with D |
| `MHRSA_Pub` | `pu8Input`, `u32InLen` | `PLAIN_512`, 64 bytes | `RSA_PLAIN` | `RsaBox.encrypt` input |
| `MHRSA_Pub` | `pu8Output`, `u32OutLen` | `CIPHER_512`, 64 bytes | `RSA_CIPHER` | `RsaBox.encrypt` output |
| `MHRSA_Pri` | `pu8Input` / `pu8Output` | 64-byte ciphertext in, 64-byte plaintext out | self-test decrypts with D | `RsaBox.decrypt` |
| `MHRSA_Crt` | `pu8Input` / `pu8Output` | 64-byte ciphertext in, 64-byte plaintext out | `rsa_open` | phone checks the 64 bytes that come back |
| `rsa_public_block` | Hello `0x01` |  | returns the 64-byte modulus, then the 4-byte exponent | compares both before sending data |
| `rsa_open` | Open `0x02` |  | 64-byte ciphertext in, 64-byte plaintext out, only after Hello | sends the ciphertext only when N and E match |

## Keil

Select the Simulator target. In Options for Target, Debug, choose Use Simulator. Build and run. View, Serial Windows, Debug (printf) Viewer should show:

```text
MH1721 handshake
self-test ok
waiting for the phone
```

The self-test checks `MHRSA_Pub` of the sample plaintext against the sample ciphertext, then `MHRSA_Pri` and `MHRSA_Crt` back to the plaintext.

The image is sized for the MH1721: 256 KB flash at `0x00000000` and 16 KB RAM at `0x20000000`. The stack is 6 KB, and the RSA limbs are sized for the 512-bit key so the buffers fit in that RAM. A build writes `Objects/MH1721_Handshake.hex`.

Keil Download still cannot program the chip. The target has no MH1721 flash algorithm. MegaHunt’s boot tool writes that hex over the boot UART (GPIO0 receive, GPIO1 transmit) or the boot SPI pins. The public brief does not publish the UART register addresses, so `board_get_byte` and `board_write` remain the byte link in `board.c`. Each frame is one command or status byte, a 16-bit big-endian length, then that many payload bytes. Status 0 means success.

| Command | Value | Phone sends | Firmware returns |
|---|---|---|---|
| Hello | `0x01` | empty | 64-byte modulus, then the 4-byte exponent `00010001` |
| Open | `0x02` | 64-byte ciphertext | 64-byte plaintext |

Hello comes first. The phone checks that modulus and exponent, and only then sends the ciphertext. Open before Hello returns status 4 and no plaintext. After Hello, Open decrypts with `MHRSA_Crt` and returns the plaintext so the phone can check that the encryption matches.

Each Hello field is a 16-bit big-endian length followed by the bytes. ARM Compiler 6 is required. `mh_rsa.c`, `mh_misc.c`, and `mh_rand.c` are in `keil/src` with the rest of the firmware.

## Android

**Try on this phone** encrypts the sample 64-byte plaintext and checks the ciphertext and the decrypted plaintext.

**Handshake with MH1721** asks the board for its public key and checks the 64-byte modulus and the 4-byte exponent. The ciphertext is sent only after that check. The board returns the plaintext, and the phone checks it against the block it encrypted. The leading `00` on the exponent is part of the value. The board must speak the frames above on a USB bulk in/out pair. Connect it with a USB OTG adapter.
