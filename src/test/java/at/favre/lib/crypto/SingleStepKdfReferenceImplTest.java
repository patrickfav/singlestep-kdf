package at.favre.lib.crypto;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.references.SingleStepKdfReference1;
import at.favre.lib.crypto.references.SingleStepKdfReference2;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;

public class SingleStepKdfReferenceImplTest {

    @Test
    public void testReference1() throws NoSuchAlgorithmException {
        SingleStepKdfReference1 ref1 = new SingleStepKdfReference1();
        byte[] z = Bytes.from("My secret").array();
        byte[] otherInfo = Bytes.parseHex("5f225b4801843ed861b95f5b0a3afd78473498f0b5cb6d7769e67458e057da8c0311").array();


        checkReferenceImpl1(ref1, z, otherInfo);

        for (int i = 0; i < 10; i++) {
            checkReferenceImpl1(ref1, Bytes.random(16).array(), Bytes.random(16 + i).array());
        }
    }

    private void checkReferenceImpl1(SingleStepKdfReference1 ref1, byte[] z, byte[] otherInfo) throws NoSuchAlgorithmException {
        byte[] outARef1 = ref1.concatKDF("SHA-256", z, 32, otherInfo);
        byte[] outARef2 = SingleStepKdf.fromSha256().derive(z, otherInfo, 32);

        assertEquals(Bytes.wrap(outARef1).encodeHex(), Bytes.wrap(outARef2).encodeHex());
    }

    @Test
    public void testReference2() throws NoSuchAlgorithmException {
        SingleStepKdfReference2 ref2 = new SingleStepKdfReference2("SHA-256");
        byte[] z = Bytes.from("My secret").array();
        byte[] otherInfo = Bytes.parseHex("5f225b4801843ed861b95f5b0a3afd78473498f0b5cb6d7769e67458e057da8c0311").array();


        checkReferenceImpl2(ref2, z, otherInfo);

        for (int i = 0; i < 10; i++) {
            checkReferenceImpl2(ref2, Bytes.random(16).array(), Bytes.random(16 + i).array());
        }
    }

    private void checkReferenceImpl2(SingleStepKdfReference2 ref2, byte[] z, byte[] otherInfo) {
        byte[] outARef1 = ref2.concatKDF(z, 32 * 8, otherInfo);
        byte[] outARef2 = SingleStepKdf.fromSha256().derive(z, otherInfo, 32);

        assertEquals(Bytes.wrap(outARef1).encodeHex(), Bytes.wrap(outARef2).encodeHex());

        byte[] outBRef1 = ref2.concatKDF(z, 16 * 8, otherInfo);
        byte[] outBRef2 = SingleStepKdf.fromSha256().derive(z, otherInfo, 16);

        assertEquals(Bytes.wrap(outBRef1).encodeHex(), Bytes.wrap(outBRef2).encodeHex());
    }
}
