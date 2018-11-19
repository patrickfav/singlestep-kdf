package at.favre.lib.crypto;

import at.favre.lib.bytes.Bytes;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class SingleStepKdfTest {

    @Test
    public void compareAgainstRefValue() {
        byte[] ikm = Bytes.from("My secret").array();
        byte[] out = SingleStepKdf.fromSha256().derive(ikm, null, new byte[16], 34);
        assertEquals(Bytes.wrap(out).encodeHex(), "5f225b4801843ed861b95f5b0a3afd78473498f0b5cb6d7769e67458e057da8c0311");
    }
}
