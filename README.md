# MH1721 RSA handshake

Two separate projects that use the `mh-rsa` parameters:

| Folder | What it is |
|---|---|
| `keil` | Keil µVision 5 project. Open `MH1721_Handshake.uvprojx`. |
| `android` | Android app. Open this folder in Android Studio. |

The key is the 512-bit `mh-rsa` sample. `u16NBits` is 512, so N and D are 64 bytes. `u16EBits` is 32, so E is the 4 bytes `00 01 00 01`. Public and private operations are raw modular exponentiation, the same as `MHRSA_Pub`, `MHRSA_Pri`, and `MHRSA_Crt`. Input and output are both 64 bytes. The firmware opens a ciphertext with `MHRSA_Crt`.

The bytes live in `keil/src/key.h` and `android/.../Keys.java`.

## Keil

Select the Simulator target. In Options for Target, Debug, choose Use Simulator. Build and run. View, Serial Windows, Debug (printf) Viewer should show:

```text
MH1721 handshake
self-test ok
waiting for the phone
```

The self-test checks `MHRSA_Pub` of the sample plaintext against the sample ciphertext, then `MHRSA_Pri` and `MHRSA_Crt` back to the plaintext.

`board_get_byte` and `board_write` in `board.c` are the byte link. Replace them with the MH1721 UART or USB. Each frame is one command or status byte, a 16-bit big-endian length, then that many payload bytes. Status 0 means success.

| Command | Value | Phone sends | Firmware returns |
|---|---|---|---|
| Hello | `0x01` | empty | 64-byte modulus, then the 4-byte exponent `00010001` |
| Open | `0x02` | 64-byte ciphertext | 64-byte plaintext |

Each Hello field is a 16-bit big-endian length followed by the bytes. ARM Compiler 6 is required. `mh_rsa.c`, `mh_misc.c`, and `mh_rand.c` are in `keil/src` with the rest of the firmware.

## Android

**Try on this phone** encrypts the sample 64-byte plaintext and checks the ciphertext and the decrypted plaintext.

**Handshake with MH1721** asks the board for its public key, checks the 64-byte modulus and the 4-byte exponent, then sends the ciphertext and checks the plaintext that comes back. The leading `00` on the exponent is part of the value. The board must speak the frames above on a USB bulk in/out pair. Connect it with a USB OTG adapter.
