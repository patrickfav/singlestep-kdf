package at.favre.lib.crypto;

import at.favre.lib.bytes.Bytes;
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
        // other info to bind the key to the context, see the NIST spec for more detail
        byte[] otherInfo = "macKey".getBytes();
        byte[] keyMaterial = SingleStepKdf.fromHmacSha256().derive(sharedSecret, 32, salt, otherInfo);
        SecretKey secretKey = new SecretKeySpec(keyMaterial, "AES");
        assertNotNull(secretKey);
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
