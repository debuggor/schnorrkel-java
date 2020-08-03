package com.debuggor.merlin;

import com.debuggor.utils.NumberUtils;

import java.security.SecureRandom;

/**
 * @Author:yong.huang
 * @Date:2020-08-02 17:32
 */
public class TranscriptRngBuilder {

    private Strobe128 strobe;

    public TranscriptRngBuilder(Strobe128 strobe) {
        this.strobe = strobe;
    }

    public TranscriptRngBuilder rekey_with_witness_bytes(byte[] label, byte[] witness) throws Exception {
        byte[] witness_len = new byte[4];
        NumberUtils.uint32ToBytes(witness.length, witness_len, 0);
        this.strobe.meta_ad(label, false);
        this.strobe.meta_ad(witness_len, true);
        this.strobe.key(witness, false);
        return this;
    }

    public TranscriptRngBuilder commit_witness_bytes(byte[] label, byte[] witness) throws Exception {
        return this.rekey_with_witness_bytes(label, witness);
    }

    public TranscriptRng tFinalize() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] random_bytes = new byte[32];
        random.nextBytes(random_bytes);
        this.strobe.meta_ad("rng".getBytes(), false);
        this.strobe.key(random_bytes, false);
        return new TranscriptRng(this.strobe.clone());
    }
}
