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

    public void proto_name(byte[] label) throws Exception {
        commit_bytes("proto-name".getBytes(), label);
    }

    public void commit_point(byte[] label, CompressedRistretto compressed) throws Exception {
        this.commit_bytes(label, compressed.toByteArray());
    }

    public Scalar witness_scalar(byte[] nonce_seeds) throws Exception {
        byte[] scalar_bytes = new byte[64];
        this.witness_bytes(scalar_bytes, nonce_seeds);
        // fromBytesModOrderWide
        Scalar scalar = Scalar.fromBytesModOrderWide(scalar_bytes);
        return scalar;
    }

    public void witness_bytes(byte[] dest, byte[] nonce_seeds) throws Exception {
        this.witness_bytes_rng(dest, nonce_seeds);
    }

    public void witness_bytes_rng(byte[] dest, byte[] nonce_seeds) throws Exception {
        TranscriptRngBuilder br = build_rng();
        br = br.commit_witness_bytes("".getBytes(), nonce_seeds);
        TranscriptRng r = br.tFinalize();
        r.fill_bytes(dest);
    }

    public Scalar challenge_scalar(byte[] label) throws Exception {
        byte[] buf = new byte[64];
        this.challenge_bytes(label, buf);
        Scalar scalar = Scalar.fromBytesModOrderWide(buf);
        return scalar;
    }
}
