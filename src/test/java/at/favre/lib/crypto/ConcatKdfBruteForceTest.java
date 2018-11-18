package at.favre.lib.crypto;

import at.favre.lib.bytes.Bytes;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

@RunWith(Parameterized.class)
public class ConcatKdfBruteForceTest {
    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {ConcatKdf.fromSha256()},
                {ConcatKdf.fromSha512()},
                {ConcatKdf.fromHmacSha256()},
                {ConcatKdf.fromHmacSha512()},
                {ConcatKdf.from(new HFunctionFactory.Default.DigestFactory("SHA-1"))},
                {ConcatKdf.from(new HFunctionFactory.Default.MacFactory("HmacSHA256"))}
        });
    }

    private final ConcatKdf concatKdf;

    public ConcatKdfBruteForceTest(ConcatKdf concatKdf) {
        this.concatKdf = concatKdf;
    }

    @Test
    public void generateBytesFromFixedSecret() {
        byte[] ikm = Bytes.from("My secret").array();
        byte[] out = concatKdf.derive(ikm, 16);
        System.out.println(Bytes.wrap(out).encodeHex());
    }

    @Test
    public void getDescription() {
        System.out.println(concatKdf.getHFunctionDescription());
    }

    @Test
    public void deriveWithVariousLengths() {
        for (int i = 1; i < 128; i++) {
            byte[] out = concatKdf.derive(Bytes.random(16).array(), i);
            System.out.println(Bytes.wrap(out).encodeHex());
        }
    }

    @Test
    public void deriveWithVariousInputLengths() {
        for (int i = 1; i < 128; i++) {
            byte[] out = concatKdf.derive(Bytes.random(i).array(), 16);
            System.out.println(Bytes.wrap(out).encodeHex());
        }

        for (int i = 1; i < 128; i++) {
            byte[] out = concatKdf.derive(Bytes.random(i).array(), 32);
            System.out.println(Bytes.wrap(out).encodeHex());
        }
    }
}
