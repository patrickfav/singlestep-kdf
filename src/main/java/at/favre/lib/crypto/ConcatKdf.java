package at.favre.lib.crypto;

import at.favre.lib.bytes.Bytes;

import java.nio.ByteBuffer;

@SuppressWarnings("WeakerAccess")
public final class ConcatKdf {

    /**
     * Cache instances
     */
    private static ConcatKdf concatKdfSha256;
    private static ConcatKdf concatKdfSha512;

    public static ConcatKdf fromSha256() {
        if (concatKdfSha256 == null) {
            concatKdfSha256 = from(HFunctionFactory.Default.sha256());
        }
        return concatKdfSha256;
    }

    public static ConcatKdf fromSha512() {
        if (concatKdfSha512 == null) {
            concatKdfSha512 = from(HFunctionFactory.Default.sha512());
        }
        return concatKdfSha512;
    }

    public static ConcatKdf from(HFunctionFactory factory) {
        return new ConcatKdf(factory);
    }

    private final HFunctionFactory digestFactory;

    private ConcatKdf(HFunctionFactory digestFactory) {
        this.digestFactory = digestFactory;
    }

    public byte[] deriveKey(byte[] shared, int outLength) {
        return deriveKey(shared, new byte[0], outLength);
    }

    public byte[] deriveKey(byte[] shared, byte[] otherInfo, int outLength) {
        final HFunction digest = digestFactory.createInstance();
        final int hashLength = digest.getOutByteLength();
        int counter = 1;
        int outputLenSum = 0;

        ByteBuffer buffer = ByteBuffer.allocate(outLength);

        if (outLength > hashLength) {
            do {
                outputLenSum += hashLength;
                buffer.put(createHashRound(shared, otherInfo, counter, digest), 0, hashLength);
            }
            while ((counter++) < (outLength / hashLength));
        }

        if (outputLenSum < outLength) {
            buffer.put(createHashRound(shared, otherInfo, counter, digest), 0, outLength - outputLenSum);
        }

        return buffer.array();
    }

    private byte[] createHashRound(byte[] shared, byte[] otherInfo, int counter, HFunction digest) {
        digest.update(Bytes.from(counter).array());
        digest.update(shared);
        digest.update(otherInfo);

        return digest.calculate();
    }
}
