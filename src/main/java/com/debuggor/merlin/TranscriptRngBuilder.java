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

    /**
     * pub fn rekey_with_witness_bytes(
     * mut self,
     * label: &'static [u8],
     * witness: &[u8],
     * ) -> TranscriptRngBuilder {
     * let witness_len = encode_usize_as_u32(witness.len());
     * self.strobe.meta_ad(label, false);
     * self.strobe.meta_ad(&witness_len, true);
     * self.strobe.key(witness, false);
     * <p>
     * self
     * }
     */
    public TranscriptRngBuilder rekey_with_witness_bytes(byte[] label, byte[] witness) throws Exception {
        byte[] witness_len = new byte[4];
        NumberUtils.uint32ToBytes(witness.length, witness_len, 0);
        this.strobe.meta_ad(label, false);
        this.strobe.meta_ad(witness_len, true);
        this.strobe.key(witness, false);
        return this;
    }

    /**
     * pub fn commit_witness_bytes(
     * self,
     * label: &'static [u8],
     * witness: &[u8],
     * ) -> TranscriptRngBuilder {
     * self.rekey_with_witness_bytes(label, witness)
     * }
     */
    public TranscriptRngBuilder commit_witness_bytes(byte[] label, byte[] witness) throws Exception {
        return this.rekey_with_witness_bytes(label, witness);
    }

    /**
     * pub fn finalize<R>(mut self, rng: &mut R) -> TranscriptRng
     * where
     * R: rand_core::RngCore + rand_core::CryptoRng,
     * {
     * let random_bytes = {
     * let mut bytes = [0u8; 32];
     * rng.fill_bytes(&mut bytes);
     * bytes
     * };
     * <p>
     * self.strobe.meta_ad(b"rng", false);
     * self.strobe.key(&random_bytes, false);
     * <p>
     * TranscriptRng {
     * strobe: self.strobe,
     * }
     * }
     */
    public TranscriptRng tFinalize() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] random_bytes = new byte[32];
        random.nextBytes(random_bytes);
        this.strobe.meta_ad("rng".getBytes(), false);
        this.strobe.key(random_bytes, false);
        return new TranscriptRng(this.strobe);
    }
}
