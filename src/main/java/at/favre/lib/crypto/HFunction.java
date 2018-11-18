package at.favre.lib.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;

/**
 * The auxiliary function used to produce blocks of keying
 * material during the execution of the one-step key-derivation
 * method.
 * <p>
 * Options for the Auxiliary Function H:
 * <ul>
 * <li>hash(x), where hash is an approved hash function</li>
 * <li>HMAC-hash(salt, x), where HMAC-hash is an implementation of the HMAC algorithm</li>
 * <li>KMAC#(salt, x, H_outputBits, S), where KMAC# is a particular implementation of either KMAC128 or KMAC256 </li>
 * </ul>
 * <p>
 * see https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr1.pdf
 */
public interface HFunction {

    /**
     * Optional keying of the H function. This is not supported
     * with hash type functions and may throw an {@link UnsupportedOperationException}. Call this before {@link #update(byte[])}
     *
     * @param key to be used
     */
    void init(byte[] key);

    /**
     * The output length of the hash/hmac/kmac. E.g. SHA-256 will output a
     * 32 byte long hash
     *
     * @return output length in byte
     */
    int getOutByteLength();

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
            this.digest = digest;
        }

        @Override
        public void init(byte[] key) {
            throw new UnsupportedOperationException("message digest does not support keying");
        }

        @Override
        public int getOutByteLength() {
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
    final class HmacHFunction implements HFunction {
        private final Mac mac;

        public HmacHFunction(Mac mac) {
            this.mac = mac;
        }

        @Override
        public void init(byte[] key) {
            try {
                mac.init(new SecretKeySpec(key, mac.getAlgorithm()));
            } catch (InvalidKeyException e) {
                throw new IllegalArgumentException("invalid key", e);
            }
        }

        @Override
        public int getOutByteLength() {
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
