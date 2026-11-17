# MH1721 RSA handshake

Two separate projects:

| Folder | What it is |
|---|---|
| `keil` | Keil µVision 5 project. Open `MH1721_Handshake.uvprojx`. |
| `android` | Android app. Open this folder in Android Studio. |

The phone encrypts a 16-byte secret with the 2048-bit public key. The side that has the private key opens it. Both sides use PKCS#1 v1.5, the same padding as Android `RSA/ECB/PKCS1Padding`.

The demo key is in `keil/src/key.h` and `android/.../Keys.java`. It is only for this handshake. Use a new 2048-bit key, or larger, outside the demo.

## Keil

Select the Simulator target. In Options for Target, Debug, choose Use Simulator. Build and run. View, Serial Windows, Debug (printf) Viewer should show:

```text
MH1721 handshake
self-test ok
waiting for the phone
```

`board_get_byte` and `board_write` in `board.c` are the byte link. Replace them with the MH1721 UART or USB. Each frame is one command or status byte, a 16-bit big-endian length, then that many payload bytes. Status 0 means success.

| Command | Value | Phone sends | Firmware returns |
|---|---|---|---|
| Hello | `0x01` | empty | modulus length, modulus, exponent length, public exponent |
| Open | `0x02` | 256-byte ciphertext | the 16-byte secret |

ARM Compiler 6 is required.

## Android

**Try on this phone** encrypts a random secret and opens it on the phone.

**Handshake with MH1721** asks the board for its public key, checks that it matches, then sends the ciphertext and checks the secret that comes back. The board must speak the frames above on a USB bulk in/out pair. Connect it with a USB OTG adapter.
