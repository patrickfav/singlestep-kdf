package at.favre.lib.crypto;

import at.favre.lib.bytes.Bytes;

import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * Single Step Key Derivation Function (KDF) as described in NIST SP 800-56Cr1 chapter 4.
 * <p>
 * Formally described as:
 *
 * <blockquote>
 * A family of one-step key-derivation functions is specified as follows:
 * Function call: KDM( Z, OtherInput ).
 * </blockquote>
 * <p>
 * Options for the Auxiliary Function H:
 * <ul>
 * <li>H(x) = hash(x), where hash is an approved hash function meeting
 * the selection requirements specified in Section 7, and the input, x, is a bit string.</li>
 * <li>H(x) = HMAC-hash(salt, x), where HMAC-hash is an implementation of the
 * HMAC algorithm (as defined in [FIPS 198]) employing an approved hash function,
 * hash, that meets the selection requirements specified in Section 7.
 * An implementation-dependent byte string, salt, whose (non-null) value may
 * be optionally provided in OtherInput, serves as the HMAC key, and x (the
 * input to H) is a bit string that serves as the HMAC “message” – as specified
 * in [FIPS 198]. </li>
 * <li>H(x) = KMAC#(salt, x, H_outputBits, S), where KMAC# is a particular
 * implementation of either KMAC128 or KMAC256 (as defined in [SP 800-185])
 * that meets the selection requirements specified in Section 7. An
 * implementation-dependent byte string, salt, whose (non-null) value may be
 * optionally provided in OtherInput, serves as the KMAC# key, and x (the input
 * to H) is a bit string that serves as the KMAC# “message” – as specified in [SP800-185].
 * The parameter H_outputBits determines the bit length chosen for the output of the
 * KMAC variant employed. The “customization string” S shall be the byte string
 * 01001011 || 01000100 || 01000110, which represents the
 * sequence of characters “K”, “D”, and “F” in 8-bit ASCII. (This three-byte
 * string is denoted by “KDF” in this document.)</li>
 * </ul>
 * <p>
 * <p>
 * see https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr1.pdf
 */
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

        /*
        1. If L > 0, then set reps = [L / H_outputBits]
           otherwise, output an error indicator and exit
           this process without performing the remaining
           actions (i.e., omitting steps 2 through 8).
        2. If reps > (2^32 −1), then output an error indicator
           and exit this process without performing the remaining
           actions (i.e., omitting steps 3 through 8).
        3. Initialize a big-endian 4-byte unsigned integer
           counter as 0x00000000, corresponding to a 32-bit
           binary representation of the number zero.
        4. If counter || Z || FixedInfo is more tha
           max_H_inputBits bits long, then output an
           error indicator and exit this process without
           performing any of the remaining actions (i.e.,
           omitting steps 5 through 8).
        5. Initialize Result(0) as an empty bit string
           (i.e., the null string).
        6. For i = 1 to reps, do the following:
           6.1 Increment counter by 1.
           6.2 Compute K(i) = H(counter || Z || FixedInfo).
           6.3 Set Result(i) = Result(i – 1) ||K(i).
        7. Set DerivedKeyingMaterial equal to the leftmost L
           bits of Result(reps).
        8. Output DerivedKeyingMaterial.
        */

        int reps = (int) Math.ceil((float) outLengthBytes / (float) hashLengthBytes);

        do {
            digest.reset();
            digest.update(Bytes.from(counter).array());
            digest.update(sharedSecretZ);
            digest.update(fixedInfo);

            buffer.put(digest.calculate(), 0,
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
}