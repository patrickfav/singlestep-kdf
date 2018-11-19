package at.favre.lib.crypto;

import at.favre.lib.bytes.Bytes;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

@RunWith(Parameterized.class)
public class SingleStepKdfBruteForceTest {
    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {SingleStepKdf.fromSha256()},
                {SingleStepKdf.fromSha512()},
                {SingleStepKdf.fromHmacSha256()},
                {SingleStepKdf.fromHmacSha512()},
                {SingleStepKdf.from(new HFunctionFactory.Default.DigestFactory("SHA-1"))},
                {SingleStepKdf.from(new HFunctionFactory.Default.MacFactory("HmacSHA256"))}
        });
    }

    private final SingleStepKdf singleStepKdf;

    public SingleStepKdfBruteForceTest(SingleStepKdf singleStepKdf) {
        this.singleStepKdf = singleStepKdf;
    }

    @Test
    public void generateBytesFromFixedSecret() {
        byte[] ikm = Bytes.from("My secret").array();
        byte[] out = singleStepKdf.derive(ikm, 16);
        System.out.println(Bytes.wrap(out).encodeHex());
    }

    @Test
    public void getDescription() {
        System.out.println(singleStepKdf.getHFunctionDescription());
    }

    @Test
    public void deriveWithVariousLengths() {
        for (int i = 1; i < 128; i++) {
            byte[] out = singleStepKdf.derive(Bytes.random(16).array(), i);
            System.out.println(Bytes.wrap(out).encodeHex());
        }
    }

    @Test
    public void deriveWithVariousInputLengths() {
        for (int i = 1; i < 128; i++) {
            byte[] out = singleStepKdf.derive(Bytes.random(i).array(), 16);
            System.out.println(Bytes.wrap(out).encodeHex());
        }

        for (int i = 1; i < 128; i++) {
            byte[] out = singleStepKdf.derive(Bytes.random(i).array(), 32);
            System.out.println(Bytes.wrap(out).encodeHex());
        }
    }
}
