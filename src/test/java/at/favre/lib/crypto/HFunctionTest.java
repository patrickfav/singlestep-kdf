package at.favre.lib.crypto;

import at.favre.lib.bytes.Bytes;
import org.junit.Test;

import javax.crypto.Mac;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.*;

public class HFunctionTest {

    @Test
    public void testMessageDigestHmacSha256() throws NoSuchAlgorithmException {
        HFunction digest = new HFunction.MacHFunction(Mac.getInstance("HmacSHA256"));
        assertTrue(digest.requireInit());
        assertEquals(32, digest.getHFuncOutputBytes());

        digest.init(new byte[32]);
        digest.update(new byte[0]);
        assertEquals("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad", Bytes.wrap(digest.calculate()).encodeHex());

        digest.reset();
    }

    @Test
    public void testMessageDigestHmacSha512() throws NoSuchAlgorithmException {
        HFunction digest = new HFunction.MacHFunction(Mac.getInstance("HmacSHA512"));
        assertTrue(digest.requireInit());
        assertEquals(64, digest.getHFuncOutputBytes());

        digest.init(new byte[64]);
        digest.update(new byte[0]);
        assertEquals("b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47", Bytes.wrap(digest.calculate()).encodeHex());

        digest.reset();
    }

    @Test
    public void testMessageDigestSha256() throws NoSuchAlgorithmException {
        HFunction digest = new HFunction.MessageDigestHFunction(MessageDigest.getInstance("SHA-256"));
        assertFalse(digest.requireInit());
        assertEquals(32, digest.getHFuncOutputBytes());

        digest.update(new byte[0]);
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Bytes.wrap(digest.calculate()).encodeHex());

        digest.reset();
    }

    @Test
    public void testMessageDigestSha512() throws NoSuchAlgorithmException {
        HFunction digest = new HFunction.MessageDigestHFunction(MessageDigest.getInstance("SHA-512"));
        assertFalse(digest.requireInit());
        assertEquals(64, digest.getHFuncOutputBytes());

        digest.update(new byte[0]);
        assertEquals("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", Bytes.wrap(digest.calculate()).encodeHex());

        digest.reset();
    }

}
