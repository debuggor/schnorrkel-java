package com.debuggor.schnorrkel;

import com.debuggor.merlin.Transcript;

/**
 * @Author:yong.huang
 * @Date:2020-08-02 16:48
 */
public class SigningContext {

    private Transcript transcript;

    public SigningContext(Transcript transcript) {
        this.transcript = transcript;
    }

    /**
     * pub fn new(context : &[u8]) -> SigningContext {
     * let mut t = Transcript::new(b"SigningContext");
     * t.append_message(b"",context);
     * SigningContext(t)
     * }
     */
    public static SigningContext createSigningContext(byte[] context) throws Exception {
        Transcript transcript = Transcript.createTranscript("SigningContext".getBytes());
        transcript.append_message("".getBytes(), context);
        return new SigningContext(transcript);
    }

    /**
     * pub fn bytes(&self, bytes: &[u8]) -> Transcript {
     * let mut t = self.0.clone();
     * t.append_message(b"sign-bytes", bytes);
     * t
     * }
     */
    public SigningTranscript bytes(byte[] bytes) throws Exception {
        SigningTranscript t = new SigningTranscript(this.transcript.getStrobe());
        t.append_message("sign-bytes".getBytes(), bytes);
        return t;
    }

    /**
     * pub fn xof<D: ExtendableOutput>(&self, h: D) -> Transcript {
     * let mut prehash = [0u8; 32];
     * h.xof_result().read(&mut prehash);
     * let mut t = self.0.clone();
     * t.append_message(b"sign-XoF", &prehash);
     * t
     * }
     */
    public void xof() {

    }

}
