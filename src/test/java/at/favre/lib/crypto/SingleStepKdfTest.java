package at.favre.lib.crypto;

import at.favre.lib.bytes.Bytes;
import org.junit.Test;

import static org.junit.Assert.fail;

public class SingleStepKdfTest {

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
            kdf.derive(Bytes.random(16).array(), Bytes.random(16).array(), Bytes.random(16).array(), 16);
            fail();
        } catch (IllegalArgumentException ignored) {

        }
    }
}
