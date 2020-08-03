package com.debuggor.schnorrkel.sign;

import com.debuggor.schnorrkel.merlin.Transcript;

/**
 * @Author:yong.huang
 * @Date:2020-08-02 16:48
 */
public class SigningContext {

    private Transcript transcript;

    public SigningContext(Transcript transcript) {
        this.transcript = transcript;
    }

    public static SigningContext createSigningContext(byte[] context) throws Exception {
        Transcript transcript = Transcript.createTranscript(context);
        return new SigningContext(transcript);
    }

    public SigningTranscript bytes(byte[] bytes) throws Exception {
        SigningTranscript t = new SigningTranscript(this.transcript.getStrobe());
        t.append_message("sign-bytes".getBytes(), bytes);
        return t;
    }

}
