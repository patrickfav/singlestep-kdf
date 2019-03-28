package at.favre.lib.crypto.singlestepkdf;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.singlstepkdf.HFunctionFactory;
import at.favre.lib.crypto.singlstepkdf.SingleStepKdf;
import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

public class SingleStepKdfTest {

    @Test
    public void quickstart() {
        // a shared secret provided by your protocol
        byte[] sharedSecret = Bytes.random(16).array();
        // a salt; if you don't have access to a salt use SingleStepKdf.fromSha256() or similar
        byte[] salt = Bytes.random(16).array();
        // fixed info to bind the key to the context, see the NIST spec for more detail (previously otherInfo)
        byte[] fixedInfo = "macKey".getBytes();
        byte[] keyMaterial = SingleStepKdf.fromHmacSha256().derive(sharedSecret, 32, salt, fixedInfo);
        SecretKey secretKey = new SecretKeySpec(keyMaterial, "AES");
        assertNotNull(secretKey);
    }

    @Test
    public void quickstartMessageDigest() {
        // a shared secret provided by your protocol
        byte[] sharedSecret = Bytes.random(16).array();
        // fixed info to bind the key to the context
        byte[] fixedInfo = "macKey".getBytes();
        // salt is not directly supported with message digest, you may include it in fixedInfo
        byte[] keyMaterial = SingleStepKdf.fromSha256().derive(sharedSecret, 32, fixedInfo);
        SecretKey secretKey = new SecretKeySpec(keyMaterial, "AES");
        assertNotNull(secretKey);
    }

    @Test
    public void quickstartHmac() {
        byte[] salt = Bytes.random(16).array();
        // a shared secret provided by your protocol
        byte[] sharedSecret = Bytes.random(16).array();
        // fixed info to bind the key to the context
        byte[] fixedInfo = "macKey".getBytes();
        // salt is not directly supported with message digest, you may include it in fixedInfo
        byte[] keyMaterial = SingleStepKdf.fromHmacSha256().derive(sharedSecret, 32, salt, fixedInfo);
        SecretKey secretKey = new SecretKeySpec(keyMaterial, "AES");
        assertNotNull(secretKey);
    }

    @Test
    public void quickstartCustomImpl() {
        // create instance with sha1 as backing hash function
        SingleStepKdf sha1Kdf = SingleStepKdf.from(new HFunctionFactory.Default.DigestFactory("SHA-1"));
        // creat instance with HMAC-SHA1 as backing h function
        SingleStepKdf hmacSha1Kdf = SingleStepKdf.from(new HFunctionFactory.Default.DigestFactory("HmacSHA1"));


    }

    @Test
    public void testIllegalOutLength() {
        SingleStepKdf kdf = SingleStepKdf.fromSha256();
        try {
            kdf.derive(Bytes.random(16).array(), 0);
            fail();
        } catch (IllegalArgumentException ignored) {

        }
    }

    @Test
    public void testDoesNotSupportSalt() {
        SingleStepKdf kdf = SingleStepKdf.fromSha256();
        try {
            kdf.derive(Bytes.random(16).array(), 16, Bytes.random(16).array(), Bytes.random(16).array());
            fail();
        } catch (IllegalArgumentException ignored) {

        }
    }
}
