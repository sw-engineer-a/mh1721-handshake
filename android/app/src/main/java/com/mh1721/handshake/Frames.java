package com.mh1721.handshake;

import java.io.IOException;
import java.util.Arrays;

/** Command, 16-bit big-endian length, payload. Status 0 means success. */
final class Frames {
    static final int HELLO = 0x01;
    static final int OPEN = 0x02;

    private Frames() {
    }

    static byte[] request(int command, byte[] payload) {
        int length = payload == null ? 0 : payload.length;
        byte[] frame = new byte[3 + length];
        frame[0] = (byte) command;
        frame[1] = (byte) (length >> 8);
        frame[2] = (byte) length;
        if (length > 0) {
            System.arraycopy(payload, 0, frame, 3, length);
        }
        return frame;
    }

    static final class PublicKey {
        final byte[] modulus;
        final byte[] exponent;

        PublicKey(byte[] modulus, byte[] exponent) {
            this.modulus = modulus;
            this.exponent = exponent;
        }
    }

    static PublicKey parsePublic(byte[] payload) throws IOException {
        int offset = 0;
        int modulusLength = readLength(payload, offset);
        offset += 2;
        byte[] modulus = readBlock(payload, offset, modulusLength);
        offset += modulusLength;
        int exponentLength = readLength(payload, offset);
        offset += 2;
        byte[] exponent = readBlock(payload, offset, exponentLength);
        offset += exponentLength;
        if (offset != payload.length) {
            throw new IOException("public key has extra bytes");
        }
        return new PublicKey(modulus, exponent);
    }

    private static int readLength(byte[] payload, int offset) throws IOException {
        if (payload == null || offset + 2 > payload.length) {
            throw new IOException("public key is too short");
        }
        return ((payload[offset] & 0xff) << 8) | (payload[offset + 1] & 0xff);
    }

    private static byte[] readBlock(byte[] payload, int offset, int length) throws IOException {
        if (length <= 0 || offset + length > payload.length) {
            throw new IOException("public key block does not fit");
        }
        return Arrays.copyOfRange(payload, offset, offset + length);
    }
}
