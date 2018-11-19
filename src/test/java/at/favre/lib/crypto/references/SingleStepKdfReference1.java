package at.favre.lib.crypto.references;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Reference implementation of NIST SP 800-56.
 * Found: https://stackoverflow.com/a/10971402/774398
 *
 * @author Rasmus Faber
 * <p>
 * Note: This implementation does not seem to support key out length longer than hash length
 */
public class SingleStepKdfReference1 {
    public byte[] concatKDF(String hashAlg, byte[] z, int keyDataLen, byte[] algorithmID, byte[] partyUInfo, byte[] partyVInfo, byte[] suppPubInfo, byte[] suppPrivInfo) throws NoSuchAlgorithmException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            baos.write(algorithmID);
            baos.write(partyUInfo);
            baos.write(partyVInfo);
            baos.write(suppPubInfo);
            baos.write(suppPrivInfo);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        byte[] otherInfo = baos.toByteArray();
        return concatKDF(hashAlg, z, keyDataLen, otherInfo);
    }

    public byte[] concatKDF(String hashAlg, byte[] z, int keyDataLen, byte[] otherInfo) throws NoSuchAlgorithmException {
        byte[] key = new byte[keyDataLen];
        MessageDigest md = MessageDigest.getInstance(hashAlg);
        int hashLen = md.getDigestLength();
        int reps = keyDataLen / hashLen;
        for (int i = 1; i <= reps; i++) {
            md.reset();
            md.update(intToFourBytes(i));
            md.update(z);
            md.update(otherInfo);
            byte[] hash = md.digest();
            if (i < reps) {
                System.arraycopy(hash, 0, key, hashLen * (i - 1), hashLen);
            } else {
                if (keyDataLen % hashLen == 0) {
                    System.arraycopy(hash, 0, key, hashLen * (i - 1), hashLen);
                } else {
                    System.arraycopy(hash, 0, key, hashLen * (i - 1), keyDataLen % hashLen);
                }
            }
        }
        return key;
    }

    private byte[] intToFourBytes(int i) {
        byte[] res = new byte[4];
        res[0] = (byte) (i >>> 24);
        res[1] = (byte) ((i >>> 16) & 0xFF);
        res[2] = (byte) ((i >>> 8) & 0xFF);
        res[3] = (byte) (i & 0xFF);
        return res;
    }
}
