package at.favre.lib.crypto.singlestepkdf.references;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.crypto.singlstepkdf.HFunctionFactory;
import at.favre.lib.crypto.singlstepkdf.SingleStepKdf;
import org.junit.Test;

public class TestVectorGen {


    @Test
    public void print() {
        System.out.println("Since there seem to be no official test vectors, I generated my own to be able to compare them to other implementations.\n\n");
        System.out.println("\n## SHA-1");
        printMessageDigestTestCases(SingleStepKdf.from(new HFunctionFactory.Default.DigestFactory("SHA-1")));
        System.out.println("\n## SHA-256");
        printMessageDigestTestCases(SingleStepKdf.fromSha256());
        System.out.println("\n## SHA-512");
        printMessageDigestTestCases(SingleStepKdf.fromSha512());

        System.out.println("\n## HMAC-SHA256");
        printHmacTestCases(SingleStepKdf.fromHmacSha256());

        System.out.println("\n## HMAC-SHA512");
        printHmacTestCases(SingleStepKdf.fromHmacSha512());
    }

    private void printMessageDigestTestCases(SingleStepKdf mdKdf) {

        // total random
        for (int i = 0; i < 10; i++) {
            printTestCase(mdKdf, Bytes.random(16).array(), 16, null, Bytes.random(12).array());
        }

        // increasing out length
        byte[] z = Bytes.random(16).array();
        byte[] fixedInfo = Bytes.random(12).array();
        for (int i = 2; i < 70; i += 2) {
            printTestCase(mdKdf, z, i, null, fixedInfo);
        }

        // increasing z
        fixedInfo = Bytes.random(12).array();
        for (int i = 2; i < 18; i += 2) {
            z = Bytes.random(i).array();
            printTestCase(mdKdf, z, 16, null, fixedInfo);
        }

        // increasing fixed info
        z = Bytes.random(16).array();
        for (int i = 2; i < 18; i += 2) {
            fixedInfo = Bytes.random(i).array();
            printTestCase(mdKdf, z, 16, null, fixedInfo);
        }

        for (int i = 8; i < 72; i += 8) {
            printTestCase(mdKdf, Bytes.random(16).array(), i, null, Bytes.empty().array());
        }
    }

    private void printHmacTestCases(SingleStepKdf mdKdf) {

        // total random
        for (int i = 0; i < 10; i++) {
            printTestCase(mdKdf, Bytes.random(16).array(), 16, Bytes.random(16).array(), Bytes.random(12).array());
        }

        // increasing out length
        byte[] z = Bytes.random(16).array();
        byte[] salt = Bytes.random(16).array();
        byte[] fixedInfo = Bytes.random(12).array();
        for (int i = 2; i < 70; i += 2) {
            printTestCase(mdKdf, z, i, salt, fixedInfo);
        }

        // increasing z
        fixedInfo = Bytes.random(12).array();
        salt = Bytes.random(16).array();
        for (int i = 2; i < 18; i += 2) {
            z = Bytes.random(i).array();
            printTestCase(mdKdf, z, 16, salt, fixedInfo);
        }

        // increasing fixed info
        z = Bytes.random(16).array();
        salt = Bytes.random(16).array();
        for (int i = 2; i < 18; i += 2) {
            fixedInfo = Bytes.random(i).array();
            printTestCase(mdKdf, z, 16, salt, fixedInfo);
        }

        // increasing salt
        z = Bytes.random(16).array();
        fixedInfo = Bytes.random(12).array();
        for (int i = 2; i < 18; i += 2) {
            salt = Bytes.random(i).array();
            printTestCase(mdKdf, z, 16, salt, fixedInfo);
        }

        salt = Bytes.random(16).array();
        for (int i = 8; i < 72; i += 8) {
            printTestCase(mdKdf, Bytes.random(16).array(), i, salt, Bytes.empty().array());
        }

        fixedInfo = Bytes.random(12).array();
        for (int i = 8; i < 72; i += 8) {
            printTestCase(mdKdf, Bytes.random(16).array(), i, null, fixedInfo);
        }
    }

    private void printTestCase(SingleStepKdf kdf, byte[] z, int outLengthByte, byte[] salt, byte[] fixedInfo) {
        byte[] dkm = kdf.derive(z, outLengthByte, salt, fixedInfo);


        String msg = "    (z: " + Bytes.wrap(z).encodeHex() + ", L: " + String.format("%02d", outLengthByte);

        if (salt != null) {
            msg += ", salt: " + Bytes.wrap(salt).encodeHex();
        }

        msg += ", fixedInfo: " + Bytes.wrap(fixedInfo).encodeHex() + ") = " + Bytes.wrap(dkm).encodeHex();

        System.out.println(msg);
    }
}
