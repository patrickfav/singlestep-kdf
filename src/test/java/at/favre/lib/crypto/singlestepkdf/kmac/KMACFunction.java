package at.favre.lib.crypto.singlestepkdf.kmac;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.bytes.BytesTransformer;
import at.favre.lib.crypto.singlstepkdf.HFunction;
import at.favre.lib.crypto.singlstepkdf.HFunctionFactory;
import org.bouncycastle.crypto.digests.CSHAKEDigest;
import org.bouncycastle.util.Arrays;

public final class KMACFunction implements HFunction {
    private CSHAKEDigest shakeDigest;
    private byte[] key;
    private final int outputLength;
    private Bytes byteBuffer = Bytes.empty();

    public KMACFunction(int outputLength) {
        if (
                outputLength != (160 / 8) &&
                        outputLength != (224 / 8) &&
                        outputLength != (256 / 8) &&
                        outputLength != (384 / 8) &&
                        outputLength != (512 / 8)

        ) {
            throw new IllegalArgumentException("illegal output-length, check Table 3 in NIST.SP.800-56Cr1 for valid lengths");
        }
        this.outputLength = outputLength;
        this.shakeDigest = new CSHAKEDigest(outputLength * 8, Bytes.from("KMAC").array(), null);
    }

    @Override
    public void init(byte[] key) {
        this.key = Bytes.wrap(encodeString(key)).resize(168 / 8, BytesTransformer.ResizeTransformer.Mode.RESIZE_KEEP_FROM_ZERO_INDEX).array();
    }

    @Override
    public boolean requireInit() {
        return true;
    }

    @Override
    public int getHFuncInputBlockLengthBytes() {
        return 16;
    }

    @Override
    public int getHFuncOutputBytes() {
        return outputLength;
    }

    @Override
    public void update(byte[] array) {

//            KMAC concatenates a padded version of the key K with the input X and an encoding of the
//            requested output length L. The result is then passed to cSHAKE, along with the requested output
//            length L, the name N ="KMAC" = 11010010 10110010 10000010 110000109
//                    , and the
//            optional customization string S.
//            KMAC128(K, X, L, S):
//            Validity Conditions: len(K) < 22040 and 0 ≤ L < 22040 and len(S) < 22040
//            1. newX = bytepad(encode_string(K), 168) || X || right_encode(L).
//            2. return cSHAKE128(newX, L, “KMAC”, S).

        byteBuffer.append(array);
    }

    @Override
    public byte[] calculate() {
        byte[] newX = Bytes.from(key, byteBuffer.array(), rightEncode(outputLength)).array();
        shakeDigest.update(newX, 0, newX.length);
        byte[] out = new byte[outputLength];
        shakeDigest.doOutput(out, 0, out.length);
        return out;
    }

    @Override
    public void reset() {
        shakeDigest.reset();
    }

    private static byte[] encodeString(byte[] str) {
        if (str == null || str.length == 0) {
            return leftEncode(0);
        }

        return Arrays.concatenate(leftEncode(str.length * 8L), str);
    }

    public static byte[] leftEncode(long strLen) {
        byte n = 1;

        long v = strLen;
        while ((v >>= 8) != 0) {
            n++;
        }

        byte[] b = new byte[n + 1];

        b[0] = n;

        for (int i = 1; i <= n; i++) {
            b[i] = (byte) (strLen >> (8 * (n - i)));
        }

        return b;
    }

    public static byte[] rightEncode(long strLen) {
        byte n = 1;

        long v = strLen;
        while ((v >>= 8) != 0) {
            n++;
        }

        byte[] b = new byte[n + 1];

        for (int i = 0; i < n; i++) {
            b[i] = (byte) (strLen >> (8 * (n - i)));
        }

        b[n] = n;

        return b;
    }

    public static final class Factory implements HFunctionFactory {

        @Override
        public HFunction createInstance() {
            return new KMACFunction(256 / 8);
        }

        @Override
        public String getDescription() {
            return "KMAC";
        }
    }
}
