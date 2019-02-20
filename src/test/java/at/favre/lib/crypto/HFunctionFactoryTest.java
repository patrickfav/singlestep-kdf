package at.favre.lib.crypto;

import at.favre.lib.bytes.Bytes;
import org.junit.Test;

import java.security.Security;

import static org.junit.Assert.*;

public class HFunctionFactoryTest {

    @Test(expected = IllegalStateException.class)
    public void testIllegalHashFunctionMessageDigest() {
        new HFunctionFactory.Default.DigestFactory("NOT IMPLEMENTED").createInstance();
    }

    @Test(expected = IllegalStateException.class)
    public void testIllegalHashFunctionHmac() {
        new HFunctionFactory.Default.MacFactory("NOT IMPLEMENTED").createInstance();
    }

    @Test
    public void testSimpleChecks() {
        simpleCheck(new HFunctionFactory.Default.DigestFactory("SHA-256"));
        simpleCheck(new HFunctionFactory.Default.DigestFactory("SHA-256", Security.getProvider("BC")));
        simpleCheck(new HFunctionFactory.Default.DigestFactory("SHA-384"));
        simpleCheck(new HFunctionFactory.Default.DigestFactory("SHA-512"));
        simpleCheck(new HFunctionFactory.Default.MacFactory("HmacSha256"));
        simpleCheck(new HFunctionFactory.Default.MacFactory("HmacSha256", Security.getProvider("BC")));
        simpleCheck(new HFunctionFactory.Default.MacFactory("HmacSha512"));
        simpleCheck(HFunctionFactory.Default.sha256());
        simpleCheck(HFunctionFactory.Default.sha512());
        simpleCheck(HFunctionFactory.Default.hmacSha256());
        simpleCheck(HFunctionFactory.Default.hmacSha512());
    }

    private void simpleCheck(HFunctionFactory factory) {
        HFunction function1 = factory.createInstance();
        HFunction function2 = factory.createInstance();

        assertNotSame(function1, function2);

        if (function2.requireInit()) {
            function2.init(Bytes.random(function2.getHFuncInputBlockLengthBytes()).array());
        }
        function2.update(Bytes.random(4).array());
        function2.update(Bytes.random(12).array());
        byte[] out = function2.calculate();
        assertEquals(out.length, function2.getHFuncOutputBytes());
        assertNotNull(out);
        assertNotNull(function2);
        assertNotNull(factory.getDescription());

        System.out.println(factory.getDescription());
    }
}
