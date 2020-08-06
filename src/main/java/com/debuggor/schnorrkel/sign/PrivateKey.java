package com.debuggor.schnorrkel.sign;

import cafe.cryptography.curve25519.Scalar;
import com.debuggor.schnorrkel.merlin.Transcript;
import com.debuggor.schnorrkel.utils.ScalarUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * @Author:yong.huang
 * @Date:2020-07-30 13:23
 */
public class PrivateKey {

    private byte[] seed;
    private byte[] key;
    private byte[] nonce;
    private byte[] h;

    public PrivateKey(byte[] seed, ExpansionMode mode) {
        this.seed = seed;
        if (mode != null && mode.equals(ExpansionMode.Ed25519)) {
            expand_ed25519(seed);
        } else {
            expand_uniform(seed);
        }
    }


    private void expand_uniform(byte[] seed) {
        try {
            Transcript t = Transcript.createTranscript("ExpandSecretKeys".getBytes());
            t.append_message("mini".getBytes(), seed);
            byte[] scalar_bytes = new byte[64];
            t.challenge_bytes("sk".getBytes(), scalar_bytes);
            Scalar scalar = Scalar.fromBytesModOrderWide(scalar_bytes);
            key = scalar.toByteArray();
            nonce = new byte[32];
            t.challenge_bytes("no".getBytes(), nonce);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private void expand_ed25519(byte[] seed) {
        try {
            MessageDigest hash = MessageDigest.getInstance("SHA-512");
            h = hash.digest(seed);
            h[0] &= 248;
            h[31] &= 63;
            h[31] |= 64;
            key = Arrays.copyOfRange(h, 0, 32);
            key = ScalarUtils.divide_scalar_bytes_by_cofactor(key);
            nonce = Arrays.copyOfRange(h, 32, 64);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unsupported hash algorithm");
        }
    }

    public byte[] getSeed() {
        return seed;
    }

    public byte[] getKey() {
        return key;
    }

    public byte[] getNonce() {
        return nonce;
    }

    /**
     * @return the hash of the seed
     */
    public byte[] getH() {
        return h;
    }
}
