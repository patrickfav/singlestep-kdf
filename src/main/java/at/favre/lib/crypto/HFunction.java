package at.favre.lib.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.util.Objects;

/**
 * The auxiliary function used to produce blocks of keying
 * material during the execution of the one-step key-derivation
 * method. Basically an abstraction of either {@link MessageDigest} or {@link Mac}
 * <p>
 * Options for the Auxiliary Function H:
 * <ul>
 * <li>hash(x), where hash is an approved hash function</li>
 * <li>HMAC-hash(salt, x), where HMAC-hash is an implementation of the HMAC algorithm</li>
 * <li>KMAC#(salt, x, H_outputBits, S), where KMAC# is a particular implementation of either KMAC128 or KMAC256 </li>
 * </ul>
 * <p>
 * An example on how to use a H-function
 * <pre>
 *     final HFunction func = factory.createInstance();
 *     final int hashLength = func.getHFuncOutputBytes();
 *     byte[] out = new byte[hashLength];
 *     func.update(keyData);
 *     out = func.calculate()
 * </pre>
 * <p>
 * see https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr1.pdf
 */
@SuppressWarnings("WeakerAccess")
public interface HFunction {

    /**
     * Optional keying of the H function. This is not supported
     * with hash type functions and may throw an {@link UnsupportedOperationException}. Call this before {@link #update(byte[])}
     *
     * @param key to be used; if null is passed, default_salt is used, which is in the case of
     *            HMAC a empty byte array the length of the underyling hash function (e.g. 32
     *            bytes for SHA-256)
     */
    void init(byte[] key);

    /**
     * If the function requires a key to be provided in the {@link #init(byte[])}
     *
     * @return true if user must initialize with init()
     */
    boolean requireInit();

    /**
     * Formally: a positive integer that indicates the length of the output of
     * the auxiliary function, H, that is used to derive blocks of secret keying material.
     * <p>
     * The spec describes the length in bits, but for practical reasons it will return bytes.
     * <p>
     * Practically the length of output hash/hmac/kmac function. E.g. SHA-256 or HMAC_SHA-256
     * will output 32 byte long block.
     *
     * @return output length in byte
     */
    int getHFuncOutputBytes();

    /**
     * Update the function with a new input that will internally added to the
     * already available input
     *
     * @param array to process
     */
    void update(byte[] array);

    /**
     * After adding the input through {@link #update(byte[])} calculate the output of the
     * H-function
     *
     * @return output (usually a hash)
     */
    byte[] calculate();

    /**
     * Hash implementation of the H function.
     */
    final class MessageDigestHFunction implements HFunction {
        private final MessageDigest digest;

        public MessageDigestHFunction(MessageDigest digest) {
            this.digest = Objects.requireNonNull(digest, "digest");
        }

        @Override
        public void init(byte[] key) {
            throw new UnsupportedOperationException("message digest does not support keying");
        }

        @Override
        public boolean requireInit() {
            return false;
        }

        @Override
        public int getHFuncOutputBytes() {
            return digest.getDigestLength();
        }

        @Override
        public void update(byte[] array) {
            digest.update(array);
        }

        @Override
        public byte[] calculate() {
            return digest.digest();
        }
    }

    /**
     * HMAC implementation of the H function
     */
    final class MacHFunction implements HFunction {
        private final Mac mac;

        public MacHFunction(Mac mac) {
            this.mac = Objects.requireNonNull(mac, "mac");
        }

        @Override
        public void init(byte[] key) {
            /*
             * If a salt value required by H is omitted from OtherInput (or if a required salt value
             * included in OtherInput is the null string), then the value of default_salt shall be
             * used as the value of salt when H is executed.
             *
             * default_salt: a non-null (secret or non-secret) byte string that is needed only if
             * either Option 2 (HMAC-hash) or Option 3 (KMAC#) is chosen for the implementation
             * of the auxiliary function H. This byte string is used as the value of salt if a
             * (non-null) value is not included in OtherInput. If H(x) = HMAC-hash(salt, x), then,
             * in the absence of an agreed-upon alternative, the default_salt shall be an all-zero
             * byte string whose bit length equals that specified as the bit length of an input
             * block for the hash function, hash.
             */
            if (key == null) {
                key = new byte[getHFuncOutputBytes()];
            }

            try {
                mac.init(new SecretKeySpec(key, mac.getAlgorithm()));
            } catch (InvalidKeyException e) {
                throw new IllegalArgumentException("invalid key", e);
            }
        }

        @Override
        public boolean requireInit() {
            return true;
        }

        @Override
        public int getHFuncOutputBytes() {
            return mac.getMacLength();
        }

        @Override
        public void update(byte[] array) {
            mac.update(array);
        }

        @Override
        public byte[] calculate() {
            return mac.doFinal();
        }
    }
}
