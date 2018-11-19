package at.favre.lib.crypto;

import at.favre.lib.bytes.Bytes;

import java.nio.ByteBuffer;
import java.util.Objects;

@SuppressWarnings("WeakerAccess")
public final class SingleStepKdf {

    /**
     * Cache instances
     */
    private static SingleStepKdf singleStepKdfSha256;
    private static SingleStepKdf singleStepKdfHmacSha256;

    public static SingleStepKdf fromSha256() {
        if (singleStepKdfSha256 == null) {
            singleStepKdfSha256 = from(HFunctionFactory.Default.sha256());
        }
        return singleStepKdfSha256;
    }

    public static SingleStepKdf fromSha512() {
        return from(HFunctionFactory.Default.sha512());
    }

    public static SingleStepKdf fromHmacSha256() {
        if (singleStepKdfHmacSha256 == null) {
            singleStepKdfHmacSha256 = from(HFunctionFactory.Default.hmacSha256());
        }
        return singleStepKdfHmacSha256;
    }

    public static SingleStepKdf fromHmacSha512() {
        return from(HFunctionFactory.Default.hmacSha512());
    }

    public static SingleStepKdf from(HFunctionFactory factory) {
        return new SingleStepKdf(factory);
    }

    private final HFunctionFactory digestFactory;

    private SingleStepKdf(HFunctionFactory digestFactory) {
        this.digestFactory = Objects.requireNonNull(digestFactory, "digestFactory");
    }

    /**
     * Get a user readable description of the used H-function (e.g. SHA-256 or HmacSha1 or similar)
     *
     * @return description
     */
    public String getHFunctionDescription() {
        return digestFactory.getDescription();
    }

    /**
     * KDM - a one step key derivation function as described in NIST SP 800-56C REV. 1 Chapter 4.1.
     * <p>
     * Derives a new key from given parameters. This call omits the salt which is applicable for KDFs
     * which use a {@link java.security.MessageDigest} as underlying H function. This call also uses a
     * zero length byte array as fixedInfo. Using an empty fixedInfo is a special case and the caller
     * should have specific reasons to omit it.
     *
     * @param sharedSecretZ  called 'Z' in the spec: a byte string that represents the shared secret
     * @param outLengthBytes called 'L' in the spec: a positive integer that indicates the length
     *                       (in bytes) of the secret keying material to be derived (ie. how long the output
     *                       will be in bytes)
     * @return derived keying material (to use as secret key)
     */
    public byte[] derive(byte[] sharedSecretZ,
                         int outLengthBytes) {
        return derive(sharedSecretZ, null, new byte[0], outLengthBytes);
    }

    /**
     * KDM - a one step key derivation function as described in NIST SP 800-56C REV. 1 Chapter 4.1.
     * <p>
     * Derives a new key from given parameters. This call omits the salt which is applicable for KDFs
     * which use a {@link java.security.MessageDigest} as underlying H function.
     *
     * @param sharedSecretZ  called 'Z' in the spec: a byte string that represents the shared secret
     * @param fixedInfo      a bit string of context-specific data that is appropriate for the relying
     *                       key-establishment scheme. FixedInfo may, for example, include appropriately
     *                       formatted representations of the values of salt and/or L. The inclusion of
     *                       additional copies of the values of salt and L in FixedInfo would ensure that
     *                       each block of derived keying material is affected by all of the information
     *                       conveyed in OtherInput. See [SP 800-56A] and [SP 800-56B] for more detailed
     *                       recommendations concerning the format and content of FixedInfo.
     * @param outLengthBytes called 'L' in the spec: a positive integer that indicates the length
     *                       (in bytes) of the secret keying material to be derived (ie. how long the output
     *                       will be in bytes)
     * @return derived keying material (to use as secret key)
     */
    public byte[] derive(byte[] sharedSecretZ,
                         byte[] fixedInfo,
                         int outLengthBytes) {
        return derive(sharedSecretZ, null, fixedInfo, outLengthBytes);
    }


    /**
     * KDM - a one step key derivation function as described in NIST SP 800-56C REV. 1 Chapter 4.1.
     * <p>
     * Derives a new key from given parameters.
     *
     * @param sharedSecretZ  called 'Z' in the spec: a byte string that represents the shared secret
     * @param salt           (secret or non-secret) byte string that should be provided when HMAC h
     *                       function is used, if null is passed the default_salt is used
     * @param fixedInfo      a bit string of context-specific data that is appropriate for the relying
     *                       key-establishment scheme. FixedInfo may, for example, include appropriately
     *                       formatted representations of the values of salt and/or L. The inclusion of
     *                       additional copies of the values of salt and L in FixedInfo would ensure that
     *                       each block of derived keying material is affected by all of the information
     *                       conveyed in OtherInput. See [SP 800-56A] and [SP 800-56B] for more detailed
     *                       recommendations concerning the format and content of FixedInfo.
     * @param outLengthBytes called 'L' in the spec: a positive integer that indicates the length
     *                       (in bytes) of the secret keying material to be derived (ie. how long the output
     *                       will be in bytes)
     * @return derived keying material (to use as secret key)
     */
    public byte[] derive(byte[] sharedSecretZ,
                         byte[] salt,
                         byte[] fixedInfo,
                         int outLengthBytes) {

        Objects.requireNonNull(sharedSecretZ, "sharedSecretZ");
        Objects.requireNonNull(fixedInfo, "fixedInfo");
        checkOutLength(outLengthBytes);

        final HFunction digest = digestFactory.createInstance();
        final int hashLengthBytes = digest.getHFuncOutputBytes();

        int counter = 1;
        int outputLenSum = 0;

        if (digest.requireInit()) {
            digest.init(salt);
        } else if (salt != null) {
            // fail fast so caller is not under the impression a salt is used if it is just discarded
            throw new IllegalArgumentException("used h-function does not require a salt and none should be provided");
        }

        ByteBuffer buffer = ByteBuffer.allocate(outLengthBytes);

        int reps = (int) Math.ceil((float) outLengthBytes / (float) hashLengthBytes);

        do {
            buffer.put(
                    createHashRound(sharedSecretZ, fixedInfo, counter, digest), 0,
                    reps == counter ? outLengthBytes - outputLenSum : hashLengthBytes);
            outputLenSum += hashLengthBytes;
        } while (counter++ < reps);

        return buffer.array();
    }

    private void checkOutLength(long outLengthByte) {
        if (outLengthByte == 0) {
            throw new IllegalArgumentException("outLength must be greater 0");
        }
    }

    private byte[] createHashRound(byte[] sharedSecretZ, byte[] fixedInfo, int counter, HFunction digest) {
        digest.update(Bytes.from(counter).array());
        digest.update(sharedSecretZ);
        digest.update(fixedInfo);

        return digest.calculate();
    }
}
