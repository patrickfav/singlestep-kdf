package at.favre.lib.crypto.singlestepkdf;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.singlestepkdf.kmac.KMACFunction;
import at.favre.lib.crypto.singlstepkdf.SingleStepKdf;
import org.junit.Test;

public class KMacTest {

    @Test
    public void testLeftEncode() {
        System.out.println(Bytes.wrap(KMACFunction.leftEncode(0)).encodeBinary());
        System.out.println(Bytes.wrap(KMACFunction.rightEncode(0)).encodeBinary());
    }

    @Test
    public void testKmacSingleStep() {
        SingleStepKdf kdf = SingleStepKdf.from(new KMACFunction.Factory());
        byte[] ikm = Bytes.from("My secret").array();
        byte[] out = kdf.derive(ikm, 16);
        System.out.println(Bytes.wrap(out).encodeHex());
    }

}
