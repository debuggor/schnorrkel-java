package com.debuggor.schnorrkel;

import cafe.cryptography.curve25519.CompressedRistretto;
import cafe.cryptography.curve25519.Scalar;
import com.debuggor.merlin.Strobe128;
import com.debuggor.merlin.Transcript;
import com.debuggor.merlin.TranscriptRng;
import com.debuggor.merlin.TranscriptRngBuilder;

/**
 * @Author:yong.huang
 * @Date:2020-08-02 16:56
 */
public class SigningTranscript extends Transcript {

    public SigningTranscript(Strobe128 strobe128) {
        super(strobe128);
    }

    /**
     * /// Extend transcript with a protocol name
     * fn proto_name(&mut self, label: &'static [u8]) {
     * self.commit_bytes(b"proto-name", label);
     * }
     */
    public void proto_name(byte[] label) throws Exception {
        commit_bytes("proto-name".getBytes(), label);
    }

    /**
     * fn commit_point(&mut self, label: &'static [u8], compressed: &CompressedRistretto) {
     * self.commit_bytes(label, compressed.as_bytes());
     * }
     */
    public void commit_point(byte[] label, CompressedRistretto compressed) throws Exception {
        this.commit_bytes(label, compressed.toByteArray());
    }

    /**
     * fn witness_scalar(&self, label: &'static [u8], nonce_seeds: &[&[u8]]) -> Scalar {
     * let mut scalar_bytes = [0u8; 64];
     * self.witness_bytes(label, &mut scalar_bytes, nonce_seeds);
     * Scalar::from_bytes_mod_order_wide(&scalar_bytes)
     * }
     */
    public Scalar witness_scalar(byte[] nonce_seeds) throws Exception {
        byte[] scalar_bytes = new byte[64];
        this.witness_bytes(scalar_bytes, nonce_seeds);
        // fromBytesModOrderWide
        Scalar scalar = Scalar.fromBytesModOrderWide(scalar_bytes);
        return scalar;
    }

    /**
     * fn witness_bytes(&self, label: &'static [u8], dest: &mut [u8], nonce_seeds: &[&[u8]]) {
     * self.witness_bytes_rng(label, dest, nonce_seeds, super::rand_hack())
     * }
     */
    public void witness_bytes(byte[] dest, byte[] nonce_seeds) throws Exception {
        this.witness_bytes_rng(dest, nonce_seeds);
    }

    /**
     * fn witness_bytes_rng<R>(&self, label: &'static [u8], dest: &mut [u8], nonce_seeds: &[&[u8]], mut rng: R)
     * where R: RngCore+CryptoRng
     * {
     * let mut br = self.build_rng();
     * for ns in nonce_seeds {
     * br = br.rekey_with_witness_bytes(label, ns);
     * }
     * let mut r = br.finalize(&mut rng);
     * r.fill_bytes(dest)
     * }
     */
    public void witness_bytes_rng(byte[] dest, byte[] nonce_seeds) throws Exception {
        TranscriptRngBuilder br = build_rng();
        br = br.commit_witness_bytes("".getBytes(), nonce_seeds);
        TranscriptRng r = br.tFinalize();
        r.fill_bytes(dest);
    }


    /**
     * fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
     * let mut buf = [0; 64];
     * self.challenge_bytes(label, &mut buf);
     * Scalar::from_bytes_mod_order_wide(&buf)
     * }
     */
    public Scalar challenge_scalar(byte[] label) throws Exception {
        byte[] buf = new byte[64];
        this.challenge_bytes(label, buf);
        Scalar scalar = Scalar.fromBytesModOrderWide(buf);
        return scalar;
    }
}
