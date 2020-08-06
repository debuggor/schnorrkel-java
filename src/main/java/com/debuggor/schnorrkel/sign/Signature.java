package com.debuggor.schnorrkel.sign;

import cafe.cryptography.curve25519.CompressedRistretto;
import cafe.cryptography.curve25519.Scalar;

/**
 * @Author:yong.huang
 * @Date:2020-08-02 19:44
 */
public class Signature {

    private CompressedRistretto R;

    private Scalar s;

    public Signature(CompressedRistretto R, Scalar s) {
        this.R = R;
        this.s = s;
    }

    public CompressedRistretto getR() {
        return R;
    }

    public Scalar getS() {
        return s;
    }

    public byte[] to_bytes() {
        byte[] bytes = new byte[64];
        byte[] rBytes = R.toByteArray();
        byte[] sBytes = s.toByteArray();
        System.arraycopy(rBytes, 0, bytes, 0, 32);
        System.arraycopy(sBytes, 0, bytes, 32, 32);
        bytes[63] |= 128;
        return bytes;
    }

    public static Signature from_bytes(byte[] bytes) throws Exception {
        if (bytes.length != 64) {
            throw new Exception("An error in the length of bytes handed to a constructor");
        }
        byte[] lower = new byte[32];
        byte[] upper = new byte[32];
        System.arraycopy(bytes, 0, lower, 0, 32);
        System.arraycopy(bytes, 32, upper, 0, 32);
        if ((upper[31] & 128) == 0) {
            throw new Exception(" Signature not marked as schnorrkel, maybe try ed25519 instead");
        }
        upper[31] &= 127;
        return new Signature(new CompressedRistretto(lower), Scalar.fromCanonicalBytes(upper));
    }

}
