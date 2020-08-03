package com.debuggor.merlin;

import com.debuggor.utils.NumberUtils;

import java.security.SecureRandom;

/**
 * @Author:yong.huang
 * @Date:2020-08-02 17:41
 */
public class TranscriptRng {

    private Strobe128 strobe;

    public TranscriptRng(Strobe128 strobe) {
        this.strobe = strobe;
    }

    public long next_u32() {
        return new SecureRandom().nextLong();
    }

    public void fill_bytes(byte[] dest) throws Exception {
        byte[] dest_len = new byte[4];
        NumberUtils.uint32ToBytes(dest.length, dest_len, 0);
        this.strobe.meta_ad(dest_len, false);
        this.strobe.prf(dest, false);
    }

    public void try_fill_bytes(byte[] dest) throws Exception {
        this.fill_bytes(dest);
    }

}
