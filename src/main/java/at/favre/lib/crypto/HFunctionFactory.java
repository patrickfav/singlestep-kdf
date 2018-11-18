/*
 * Copyright 2017 Patrick Favre-Bulle
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package at.favre.lib.crypto;

import javax.crypto.Mac;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * Factory class for creating {@link MessageDigest}
 */

@SuppressWarnings({"unused", "WeakerAccess"})
public interface HFunctionFactory {

    /**
     * Creates a new instance of {@link MessageDigest}
     *
     * @return a new message digest instance
     */
    HFunction createInstance();

    /**
     * Get a user readable description of the used H-function (e.g. SHA-256 or HmacSha1 or similar)
     *
     * @return description
     */
    String getDescription();

    /**
     * Default implementation
     */
    final class Default {

        private Default() {
        }

        /**
         * Creates a factory creating SHA-256
         *
         * @return factory
         */
        public static HFunctionFactory sha256() {
            return new DigestFactory("SHA-256", null);
        }

        /**
         * Creates a factory creating SHA-512. Be aware that it is not guaranteed that this algorithm
         * is implemented in all JVMs.
         *
         * @return factory
         */
        public static HFunctionFactory sha512() {
            return new DigestFactory("SHA-512", null);
        }

        /**
         * Creates a factory creating HMAC with SHA-256
         *
         * @return factory
         */
        public static HFunctionFactory hmacSha256() {
            return new MacFactory("HmacSHA256", null);
        }

        /**
         * Creates a factory creating HMAC with SHA-512
         *
         * @return factory
         */
        public static HFunctionFactory hmacSha512() {
            return new MacFactory("HmacSHA512", null);
        }

        /**
         * Simple factory for message digests
         */
        public static final class DigestFactory implements HFunctionFactory {
            private final String algorithmName;
            private final Provider provider;

            /**
             * Creates a mac factory
             *
             * @param messageDigestAlgorithmName as used by {@link MessageDigest#getInstance(String)}
             */
            public DigestFactory(String messageDigestAlgorithmName) {
                this(messageDigestAlgorithmName, null);
            }

            /**
             * Creates a message digest factory
             *
             * @param messageDigestAlgorithmName as used by {@link MessageDigest#getInstance(String)}
             * @param provider                   what security provider, see {@link MessageDigest#getInstance(String, Provider)}; may be null to use default
             */
            public DigestFactory(String messageDigestAlgorithmName, Provider provider) {
                this.algorithmName = messageDigestAlgorithmName;
                this.provider = provider;
            }

            @Override
            public HFunction createInstance() {
                try {
                    MessageDigest messageDigest;

                    if (provider == null) {
                        messageDigest = MessageDigest.getInstance(algorithmName);
                    } else {
                        messageDigest = MessageDigest.getInstance(algorithmName, provider);
                    }

                    return new HFunction.MessageDigestHFunction(messageDigest);
                } catch (NoSuchAlgorithmException e) {
                    throw new IllegalStateException("defined message digest algorithm was not found", e);
                } catch (Exception e) {
                    throw new IllegalStateException("could not make message digest in concat kdf", e);
                }
            }

            @Override
            public String getDescription() {
                return "MessageDigest[" + algorithmName + "]";
            }
        }

        /**
         * Simple factory for MAC
         */
        public static final class MacFactory implements HFunctionFactory {
            private final String algorithmName;
            private final Provider provider;

            /**
             * Creates a mac factory
             *
             * @param macAlgorithmName as used by {@link Mac#getInstance(String)}
             */
            public MacFactory(String macAlgorithmName) {
                this(macAlgorithmName, null);
            }

            /**
             * Creates a message digest factory
             *
             * @param macAlgorithmName as used by {@link Mac#getInstance(String)}
             * @param provider         what security provider, see {@link Mac#getInstance(String, Provider)}; may be null to use default
             */
            public MacFactory(String macAlgorithmName, Provider provider) {
                this.algorithmName = macAlgorithmName;
                this.provider = provider;
            }

            @Override
            public HFunction createInstance() {
                try {
                    Mac mac;

                    if (provider == null) {
                        mac = Mac.getInstance(algorithmName);
                    } else {
                        mac = Mac.getInstance(algorithmName, provider);
                    }

                    return new HFunction.MacHFunction(mac);
                } catch (NoSuchAlgorithmException e) {
                    throw new IllegalStateException("defined mac algorithm was not found", e);
                } catch (Exception e) {
                    throw new IllegalStateException("could not make mac in concat kdf", e);
                }
            }

            @Override
            public String getDescription() {
                return "MAC[" + algorithmName + "]";
            }
        }
    }
}
