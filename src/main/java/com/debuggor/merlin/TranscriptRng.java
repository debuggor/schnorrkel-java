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

    /**
     * fn next_u32(&mut self) -> u32 {
     * rand_core::impls::next_u32_via_fill(self)
     * }
     */
    public long next_u32() {
        return new SecureRandom().nextLong();
    }


    /**
     * fn fill_bytes(&mut self, dest: &mut [u8]) {
     * let dest_len = encode_usize_as_u32(dest.len());
     * self.strobe.meta_ad(&dest_len, false);
     * self.strobe.prf(dest, false);
     * }
     */
    public void fill_bytes(byte[] dest) throws Exception {
        byte[] dest_len = new byte[4];
        NumberUtils.uint32ToBytes(dest.length, dest_len, 0);
        this.strobe.meta_ad(dest_len, false);
        this.strobe.prf(dest, false);
    }

    /**
     * fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
     * self.fill_bytes(dest);
     * Ok(())
     * }
     */
    public void try_fill_bytes(byte[] dest) throws Exception {
        this.fill_bytes(dest);
    }

}
