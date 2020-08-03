package com.debuggor.merlin;

import com.debuggor.utils.NumberUtils;

/**
 * @Author:yong.huang
 * @Date:2020-08-01 15:11
 */
public class Transcript {

    protected Strobe128 strobe;

    private static byte[] MERLIN_PROTOCOL_LABEL = "Merlin v1.0".getBytes();

    public Transcript(Strobe128 strobe128) {
        this.strobe = strobe128;
    }

    public Strobe128 getStrobe() {
        return strobe;
    }

    public static Transcript createTranscript(byte[] label) throws Exception {
        Strobe128 strobe = Strobe128.createStrobe(MERLIN_PROTOCOL_LABEL);
        Transcript transcript = new Transcript(strobe);
        transcript.append_message("dom-sep".getBytes(), label);
        return transcript;
    }

    /**
     * pub fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
     * let data_len = encode_usize_as_u32(message.len());
     * self.strobe.meta_ad(label, false);
     * self.strobe.meta_ad(&data_len, true);
     * self.strobe.ad(message, false);
     */
    public void append_message(byte[] label, byte[] message) throws Exception {
        byte[] data_len = new byte[4];
        NumberUtils.uint32ToBytes(message.length, data_len, 0);
        this.strobe.meta_ad(label, false);
        this.strobe.meta_ad(data_len, true);
        this.strobe.ad(message, false);
    }

    /**
     * pub fn commit_bytes(&mut self, label: &'static [u8], message: &[u8]) {
     * self.append_message(label, message);
     * }
     */
    public void commit_bytes(byte[] label, byte[] message) throws Exception {
        this.append_message(label, message);
    }

    /**
     * pub fn append_u64(&mut self, label: &'static [u8], x: u64) {
     * self.append_message(label, &encode_u64(x));
     * }
     */
    public void append_u64(byte[] label, long x) throws Exception {
        byte[] data = new byte[8];
        NumberUtils.uint64ToBytes(x, data, 0);
        this.append_message(label, data);
    }

    /**
     * pub fn commit_u64(&mut self, label: &'static [u8], x: u64) {
     * self.append_u64(label, x);
     * }
     */
    public void commit_u64(byte[] label, long x) throws Exception {
        this.append_u64(label, x);
    }

    /**
     * pub fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
     * let data_len = encode_usize_as_u32(dest.len());
     * self.strobe.meta_ad(label, false);
     * self.strobe.meta_ad(&data_len, true);
     * self.strobe.prf(dest, false);
     */
    public void challenge_bytes(byte[] label, byte[] dest) throws Exception {
        byte[] data_len = new byte[4];
        NumberUtils.uint32ToBytes(dest.length, data_len, 0);
        this.strobe.meta_ad(label, false);
        this.strobe.meta_ad(data_len, true);
        this.strobe.prf(dest, false);
    }

    /**
     * pub fn build_rng(&self) -> TranscriptRngBuilder {
     * TranscriptRngBuilder {
     * strobe: self.strobe.clone(),
     * }
     * }
     */
    public TranscriptRngBuilder build_rng() {
        Strobe128 strobe = this.strobe.clone();
        return new TranscriptRngBuilder(strobe);
    }

    public static void main(String[] args) throws Exception {
        Transcript transcript = Transcript.createTranscript("test protocol".getBytes());

        transcript.append_message("some label".getBytes(), "some data".getBytes());

        byte[] data = new byte[32];
        transcript.challenge_bytes("challenge".getBytes(), data);

        System.out.println(true);

    }
}
