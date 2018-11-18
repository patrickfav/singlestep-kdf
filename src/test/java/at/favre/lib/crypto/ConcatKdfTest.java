package at.favre.lib.crypto;

import at.favre.lib.bytes.Bytes;
import org.junit.Test;

public class ConcatKdfTest {

    @Test
    public void generateBytes() {
        byte[] ikm = Bytes.from("My secret").array();
        byte[] out = ConcatKdf.fromSha256().deriveKey(ikm, new byte[16], 16);
        System.out.println(Bytes.wrap(out).encodeHex());
    }
}
