# Single Step KDF (NIST SP 800-56C)

This is an implementation of the single-step key derivation function as described in [NIST SP 800-56C revision 1, chapter 4](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr1.pdf). It is an unopinionated approach towards the subject, allowing all 3 options (message digest, hmac and kmac) as H function and leaving open the exact format of the `fixedInfo` parameter.

[![Download](https://api.bintray.com/packages/patrickfav/maven/singlestep-kdf/images/download.svg)](https://bintray.com/patrickfav/maven/singlestep-kdf/_latestVersion)
[![Build Status](https://travis-ci.org/patrickfav/singlestep-kdf.svg?branch=master)](https://travis-ci.org/patrickfav/singlestep-kdf)
[![Javadocs](https://www.javadoc.io/badge/at.favre.lib/singlestep-kdf.svg)](https://www.javadoc.io/doc/at.favre.lib/singlestep-kdf)
[![Coverage Status](https://coveralls.io/repos/github/patrickfav/singlestep-kdf/badge.svg?branch=master)](https://coveralls.io/github/patrickfav/singlestep-kdf?branch=master)

This is supposed to be a standalone, lightweight, simple to use, fully tested and stable implementation in Java. The code is compiled with [Java 7](https://en.wikipedia.org/wiki/Java_version_history#Java_SE_7) to be compatible with most [_Android_](https://www.android.com/) versions as well as normal Java applications.

## Quickstart

Add dependency to your `pom.xml`:

    <dependency>
        <groupId>at.favre.lib</groupId>
        <artifactId>singlestep-kdf</artifactId>
        <version>{latest-version}</version>
    </dependency>

A very simple example:

```java
// a shared secret provided by your protocol
byte[] sharedSecret = ...
// a salt; if you don't have access to a salt use SingleStepKdf.fromSha256() or similar
byte[] salt = ...
// other info to bind the key to the context, see the NIST spec for more detail
byte[] otherInfo = "macKey".getBytes();
byte[] keyMaterial = SingleStepKdf.fromHmacSha256().derive(sharedSecret, 32, salt, otherInfo);
SecretKey secretKey = new SecretKeySpec(keyMaterial, "AES");
```

### Full Example

NIST 800-56C specifies the KDF with an H-function which may be a [hash](https://en.wikipedia.org/wiki/Cryptographic_hash_function), [HMAC](https://en.wikipedia.org/wiki/HMAC) or [KMAC](https://keccak.team/index.html).

### Using with Message Digest (Option 1)

Using Option 1, ie. `H(x) = hash(x)`, where hash is an approved hash function. Note that when you use this option, the salt parameter is not supported. If you want to incorporate a salt just include it into the `fixedInfo` parameter. **If you have no specific reason for choosing Option 1, I would always prefer Option 2 (HMAC) over this one.**

```java
// a shared secret provided by your protocol
byte[] sharedSecret = Bytes.random(16).array();
// fixed info to bind the key to the context
byte[] fixedInfo = "macKey".getBytes();
// salt is not directly supported with message digest, you may include it in fixedInfo
byte[] keyMaterial = SingleStepKdf.fromSha256().derive(sharedSecret, 32, fixedInfo);
SecretKey secretKey = new SecretKeySpec(keyMaterial, "AES");
```
### Using with HMAC (Option 2)
Using Option 2, ie. `H(x) = HMAC-hash(salt, x)`, where HMAC-hash is an implementation of the HMAC algorithm (as defined in FIPS 198) employing an approved hash function. A salt which serves as the HMAC key, and x (the input to H) is a bit string that serves as the HMAC "message". This implemention can use any `Mac` implementation. If no salt is provided, an empty array is internally initialized.

```java
byte[] keyMaterial = SingleStepKdf.fromHmacSha256().derive(sharedSecret, 32, salt, fixedInfo);
        SecretKey secretKey = new SecretKeySpec(keyMaterial, "AES");
```

### Using with KMAC (Option 3)

KMAC is a MAC using [SHA-3/Keccak](https://en.wikipedia.org/wiki/SHA-3). Unlike SHA-1 and SHA-2, [Keccak](http://keccak.noekeon.org/) does not have the [length-extension weakness](https://en.wikipedia.org/wiki/Length_extension_attack), hence does not need the HMAC nested construction. Instead, MAC computation can be performed by simply prepending the message with the key. Java has a SHA-3 implementation [since version 9](https://openjdk.java.net/jeps/287). This implementation supports Java 7, so no default implementation is present for KMAC. It is probably quite easy to implement it yourself using either the `HFunctionFactory.MacFactory` or implementing yourself with `HFunction`.

### Using custom Message Digest / HMAC implementation

Default implementation exists for the h-function which can be used for any `MessageDigest` or `Mac`. It is also possible to implement it from scratch by using the `HFunction` interface. A factory is used to generate instances. Thes can be used like this:

```java
// create instance with sha1 as backing hash function
SingleStepKdf sha1Kdf = SingleStepKdf.from(new HFunctionFactory.Default.DigestFactory("SHA-1"));
// creat instance with HMAC-SHA1 as backing h function
SingleStepKdf hmacSha1Kdf = SingleStepKdf.from(new HFunctionFactory.Default.DigestFactory("HmacSHA1"));
```

### How to use the Fixed-Info Parameter 

A bit string of context-specific data that is appropriate for the relying key-establishment scheme. As its name suggests, the value of `FixedInfo` does not change during the execution of the process.

`FixedInfo` may, for example, include appropriately formatted representations of the values of salt and/or the output length. The inclusion of additional copies of the values of salt and the output length in `FixedInfo` would ensure that each block of derived keying material is affected by all of the information conveyed in `OtherInput`. See [SP 800-56A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf) and [SP 800-56B](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-56br1.pdf) for more detailed recommendations concerning the format and content of `FixedInfo` (also known as OtherInfo in earlier versions of those documents).

## Download

The artifacts are deployed to [jcenter](https://bintray.com/bintray/jcenter) and [Maven Central](https://search.maven.org/).

### Maven

Add dependency to your `pom.xml`:

    <dependency>
        <groupId>at.favre.lib</groupId>
        <artifactId>singlestep-kdf</artifactId>
        <version>{latest-version}</version>
    </dependency>

### Gradle

Add to your `build.gradle` module dependencies:

    compile group: 'at.favre.lib', name: 'singlestep-kdf', version: '{latest-version}'

### Local Jar

[Grab jar from latest release.](https://github.com/patrickfav/singlestep-kdf/releases/latest)


## Description

The following is summarized and shorted version of [NIST 800-56C Rev1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr1.pdf):

Single Step KDF specifies a family of approved key-derivation functions (KDFs) that are executed in a single step; The input to each specified KDF includes the shared secret generated during the execution of a key-establishment scheme specified in [SP 800-56A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf) or [SP 800-56B](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-56br1.pdf), an indication of the desired bit length of the keying material to be output, and, perhaps, other information (as determined by the particular implementation of the key-establishment scheme and/or key-derivation function).

Implementations of these one-step KDFs depend upon the choice of an auxiliary function H, which can be either:
 
 1. an approved hash function, denoted as hash, as defined in [FIPS 180](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.180-4.pdf) or [FIPS 202](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf); 
 2. HMAC with an approved hash function, hash, denoted as HMAC-hash, and defined in [FIPS 198](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf); or 
 3. a KMAC variant, as defined in [SP 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf). H shall be chosen in accordance with the selection requirements specified in [800-56C Rev1/Section 7](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr1.pdf).

When an approved MAC algorithm (HMAC or KMAC) is used to define the auxiliary function H, it is permitted to use a known salt value as the MAC key. In such cases, it is assumed that the MAC algorithm will satisfy the following property (for each of its supported security strengths):

Given knowledge of the key `k`, and (perhaps) partial knowledge of a message `x` that includes an unknown substring `z`, it must be computationally infeasible to predict the (as-yet-unseen) value of `MAC(k, x, …)` with a probability of success that is a significant improvement over simply guessing either the MAC value or the value of `z`, even if one has already seen the values of `MAC(kj, xj, …)` for a feasible number of other `(kj, xj)` pairs, where each key `kj` is known and each (partially known) message `xj` includes the same unknown substring `z`, provided that none of the `(kj, xj)` pairs is identical to `(k, x)`.

This property is consistent with the use of the MAC algorithm as the specification of a family of pseudorandom functions defined on the appropriate message space and indexed by the choice of MAC key. Under Option 2 and Option 3 of the KDF specification below, the auxiliary function H is a particular selection from such a family.

### Two Step Key Derivation Function

NIST 800-56C Rev1 also describes a two step kdf with a extract and expand phase. The most prominent implementation of it is [HKDF (RFC5869)](https://tools.ietf.org/html/rfc5869). A java implementation of it can be [found here](https://github.com/patrickfav/hkdf).

## Digital Signatures

### Signed Jar

The provided JARs in the Github release page are signed with my private key:

    CN=Patrick Favre-Bulle, OU=Private, O=PF Github Open Source, L=Vienna, ST=Vienna, C=AT
    Validity: Thu Sep 07 16:40:57 SGT 2017 to: Fri Feb 10 16:40:57 SGT 2034
    SHA1: 06:DE:F2:C5:F7:BC:0C:11:ED:35:E2:0F:B1:9F:78:99:0F:BE:43:C4
    SHA256: 2B:65:33:B0:1C:0D:2A:69:4E:2D:53:8F:29:D5:6C:D6:87:AF:06:42:1F:1A:EE:B3:3C:E0:6D:0B:65:A1:AA:88

Use the jarsigner tool (found in your `$JAVA_HOME/bin` folder) folder to verify.

### Signed Commits

All tags and commits by me are signed with git with my private key:

    GPG key ID: 4FDF85343912A3AB
    Fingerprint: 2FB392FB05158589B767960C4FDF85343912A3AB

## Build

### Jar Sign

If you want to jar sign you need to provide a file `keystore.jks` in the
root folder with the correct credentials set in environment variables (
`OPENSOURCE_PROJECTS_KS_PW` and `OPENSOURCE_PROJECTS_KEY_PW`); alias is
set as `pfopensource`.

If you want to skip jar signing just change the skip configuration in the
`pom.xml` jar sign plugin to true:

    <skip>true</skip>

### Build with Maven

Use maven (3.1+) to create a jar including all dependencies

    mvn clean install

## Tech Stack

* Java 7
* Maven

## Relevant Libraries

* [BCyrpt Password Hash Function (Java)](https://github.com/patrickfav/bcrypt)
* [HKDF [RFC5869] Two-Step KDF (Java)](https://tools.ietf.org/html/rfc5869)

# License

Copyright 2018 Patrick Favre-Bulle

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
