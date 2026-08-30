# 파싱 검수 - Recommendation for Key Management.pdf

- 언어 판정: `en`
- OCR 상태: `partial_failed` (텍스트 없는 페이지 2개)
- 블록: {'paragraph': 1828, 'heading': 206, 'table': 35}
- 조항 경로가 붙은 블록: 2069/2069
- 텍스트 품질: 정상
- **OCR 이중 판독이 어긋난 블록 1개** - 원문 대조 필요

## 표 35개

표 안의 숫자와 알고리즘명이 규칙표의 임계값이 된다. 원문과 한 칸씩 대조할 것.

### 표 1 - 19쪽
조항: 2 Glossary of Terms and Acronyms  ·  출처: `text`

```
[Row 1] Access control | Restricts resource access to only authorized entities.
[Row 2] Accountability | 1. Assigning key management responsibilities to individuals and holding them accountable for these activities. 2. A property that ensures that the actions of an entity may be traced uniquely to that entity.
```

### 표 2 - 20쪽
조항: 2 Glossary of Terms and Acronyms  ·  출처: `text`

```
[Row 1] Active state | The key state in which the key may be used to cryptographically protect information (e.g., encrypt plaintext or generate a digital signature), cryptographically process previously protected information (e.g., decrypt ciphertext or verify a digital signature), or both.
[Row 2] Algorithm originator- usage period | The period of time during which a specific cryptographic algorithm may be used by originators to apply protection to data (e.g., encrypt or generate a digital signature).
[Row 3] Algorithm security lifetime | The estimated time period during which data protected by a specific cryptographic algorithm remains secure, given that the key has not been compromised.
[Row 4] Approved | FIPS-approved and/or NIST-recommended. An algorithm or technique that is either 1) specified in a FIPS or NIST Recommendation or 2) specified elsewhere and adopted by reference in a FIPS or NIST Recommendation.
[Row 5] Archive | 1. To place information into long-term storage. 2. A location or media used for long-term storage.
[Row 6] Association | A relationship for a particular purpose; for example, a key is associated with the application or process for which it will be used.
[Row 7] Assurance of (private key) possession | Confidence that an entity possesses a private key and its associated key information and that the private key corresponds to a given public key.
[Row 8] Assurance of validity | Confidence that a public key or domain parameter is arithmetically correct.
[Row 9] Asymmetric-key algorithm | See Public-key cryptographic algorithm.
[Row 10] Authentication | A process that provides assurance of the source and integrity of information in communications sessions, messages, documents or stored data or that provides assurance of the identity of an entity interacting with a system. See Source authentication, Identity authentication, and Integrity authentication.
[Row 11] Authentication code | A keyed cryptographic checksum based on an approved security function; also known as a Message Authentication Code.
[Row 12] Authorization | Access privileges that are granted to an entity that convey an “official” sanction to perform a security function or activity.
[Row 13] Availability | Timely, reliable access to information by authorized entities.
```

### 표 3 - 21쪽
조항: 2 Glossary of Terms and Acronyms  ·  출처: `text`

```
[Row 1] Backup | A copy of key information to facilitate recovery during the cryptoperiod of the key, if necessary.
[Row 2] Block cipher (algorithm) | A symmetric-key cryptographic algorithm that transforms one block of information at a time using a cryptographic key. For a block cipher algorithm, the length of the input block is the same as the length of the output block.
[Row 3] Certificate | See Public-key certificate.
[Row 4] Certificate-inventory management | See Key-inventory management.
[Row 5] Certification authority | The entity in a Public Key Infrastructure (PKI) that issues certificates to certificate subjects.
[Row 6] Ciphertext | Data in its encrypted form.
[Row 7] Collision | Two or more distinct inputs produce the same output. Also see Hash function.
[Row 8] Compromise | The unauthorized disclosure, modification, substitution or use of sensitive key information (e.g., a secret key, private key, or secret metadata).
[Row 9] Compromised state | A key state to which a key is transitioned when there is a suspicion or confirmation of the key’s compromise.
[Row 10] Confidentiality | The property that sensitive information is not disclosed to unauthorized entities (e.g., the secrecy of the key information is maintained).
[Row 11] Contingency plan | A plan that is maintained for disaster response, backup operations, and post-disaster recovery to ensure the availability of critical resources and to facilitate the continuity of operations in an emergency situation.
[Row 12] Contingency planning | The development of a contingency plan.
[Row 13] Cryptanalysis | 1. Operations performed to defeat cryptographic protection without an initial knowledge of the key employed in providing the protection. 2. The study of mathematical techniques for attempting to defeat cryptographic techniques and information-system security. This includes the process of looking for errors or weaknesses in the implementation of an algorithm or in the algorithm itself.
[Row 14] Cryptographic algorithm | A well-defined computational procedure that takes variable inputs, including a cryptographic key, and produces an output.
[Row 15] Cryptographic boundary | An explicitly defined continuous perimeter that establishes the physical bounds of a cryptographic module and contains all hardware, software, and/or firmware components of a cryptographic module.
```

### 표 4 - 22쪽
조항: 2 Glossary of Terms and Acronyms  ·  출처: `text`

```
[Header] Cryptographic hash function | See Hash function.
[Row 1] Cryptographic hash function=Cryptographic key (key) | See Hash function.=A parameter used in conjunction with a cryptographic algorithm that determines its operation in such a way that an entity with knowledge of the key can reproduce, reverse or verify the operation while an entity without knowledge of the key cannot. Examples include: 1. The transformation of plaintext data into ciphertext data, 2. The transformation of ciphertext data into plaintext data, 3. The computation of a digital signature from data, 4. The verification of a digital signature on data, 5. The computation of an authentication code from data, 6. The verification of an authentication code from data and a received or retrieved authentication code, and 7. The computation of a shared secret that is used to derive keying material.
[Row 2] Cryptographic hash function=Cryptographic module | See Hash function.=The set of hardware, software, and/or firmware that implements approved security functions and is contained within a cryptographic boundary.
[Row 3] Cryptographic hash function=Cryptoperiod | See Hash function.=The time span during which a specific key is authorized for use or in which the keys for a given system or application may remain in effect.
[Row 4] Cryptographic hash function=Data-encryption key | See Hash function.=A key used to encrypt and decrypt data other than keys.
[Row 5] Cryptographic hash function=Data integrity | See Hash function.=A property whereby data has not been altered in an unauthorized manner since it was created, transmitted, or stored.
[Row 6] Cryptographic hash function=Deactivated state | See Hash function.=A key state in which keys are not used to apply cryptographic protection (e.g., encrypt) but, in some cases, are used to process cryptographically protected information (e.g., decrypt).
[Row 7] Cryptographic hash function=Decryption | See Hash function.=The process of changing ciphertext into plaintext using a cryptographic algorithm and key.
[Row 8] Cryptographic hash function=Destroyed state | See Hash function.=A key state to which a key transitions when it is destroyed. Although the key no longer exists, its previous existence may be recorded (e.g., in metadata or audit logs).
```

### 표 5 - 23쪽
조항: 2 Glossary of Terms and Acronyms  ·  출처: `text`

```
[Row 1] Deterministic random bit generator (DRBG) | A random bit generator that includes a DRBG algorithm and (at least initially) has access to a source of randomness. The DRBG produces a sequence of bits from a secret initial value called a seed. A cryptographic DRBG has the additional property that the output is unpredictable given that the seed is not known. A DRBG is sometimes also called a pseudo- random number generator (PRNG) or a deterministic random number generator.
[Row 2] Digital signature | The result of a cryptographic transformation of data that, when properly implemented with a supporting infrastructure and policy, provides the services of: 1. Source/identity authentication, 2. Data integrity authentication, and/or 3. Support for signer non-repudiation.
[Row 3] Distribution | See Key distribution.
[Row 4] Domain parameter | A parameter used in conjunction with some public-key algorithms to generate key pairs or to perform cryptographic operations (e.g., to create digital signatures or to establish keying material).
[Row 5] Encrypted key | A cryptographic key that has been encrypted using an approved cryptographic algorithm in order to disguise the value of the underlying plaintext key.
[Row 6] Encryption | The process of changing plaintext into ciphertext using a cryptographic algorithm and key.
[Row 7] Entity | An individual (person), organization, device or process.
[Row 8] Entity registration | A function in the lifecycle of a cryptographic key; a process whereby an entity becomes a member of a security domain.
[Row 9] Ephemeral key | A cryptographic key that is generated for each execution of a cryptographic process (e.g., key establishment) and that meets other requirements of the key type (e.g., unique to each message or session).
[Row 10] Hash-based message authentication code (HMAC) | A message authentication code that uses an approved keyed-hash function (i.e., see FIPS 19812).
```

### 표 6 - 24쪽
조항: 2 Glossary of Terms and Acronyms  ·  출처: `text`

```
[Row 1] Hash function | A function that maps a bit string of arbitrary (although bounded) length to a fixed-length bit string. Approved hash functions satisfy the following properties: 1. (One-way) It is computationally infeasible to find any input that maps to any pre-specified output. 2. (Collision-resistant) It is computationally infeasible to find any two distinct inputs that map to the same output.
[Row 2] Hash value | The result of applying a hash function to information.
[Row 3] Identifier | A bit string that is associated with a person, device, or organization. It may be an identifying name or may be something more abstract (e.g., a string consisting of an IP address and timestamp), depending on the application.
[Row 4] Identity | The distinguishing character or personality of an entity.
[Row 5] Identity authentication | The process of providing assurance about the identity of an entity interacting with a system (e.g., to access a resource). Sometimes called entity authentication.
[Row 6] Initialization vector (IV) | A vector used in defining the starting point of a cryptographic process.
[Row 7] Integrity (also, assurance of integrity) | See Data integrity.
[Row 8] Integrity authentication | The process of obtaining assurance that data has not been modified since an authentication code or digital signature was created for that data.
[Row 9] Integrity protection | The protection obtained for transmitted or stored data using an authentication code (e.g., MAC) or digital signature computed on that data. See Integrity authentication.
[Row 10] Key | See Cryptographic key.
[Row 11] Key agreement | A key-establishment procedure where keying material is generated from information contributed by two or more participants so that no party can predetermine the value of the keying material independently of any other party’s contribution.
[Row 12] Key confirmation | A procedure used to provide assurance to one party that another party actually possesses the same keying material and/or shared secret.
[Row 13] Key de-registration | A function in the lifecycle of a cryptographic key; the marking of a key or the information associated with it (e.g., metadata) to indicate that the key is no longer in use.
```

### 표 7 - 25쪽
조항: 2 Glossary of Terms and Acronyms  ·  출처: `text`

```
[Row 1] Key derivation | The process by which keying material is derived from either a pre-shared key or a shared secret (from a key-agreement scheme), along with other information.
[Row 2] Key-derivation function | A function that − with the input of a cryptographic key or shared secret and possibly other data − generates a binary string, called keying material.
[Row 3] Key-derivation key | A key used with a key-derivation method to derive additional keys. Sometimes called a master key.
[Row 4] Key-derivation method | A key-derivation function or other approved procedure for deriving keying material.
[Row 5] Key destruction | To remove all traces of a cryptographic key so that it cannot be recovered by either physical or electronic means.
[Row 6] Key distribution | The transport of a key and other keying material from an entity that either owns, generates or otherwise acquires the key to another entity that is intended to use the key.
[Row 7] Key-encrypting key | A cryptographic key that is used for the encryption or decryption of other keys to provide confidentiality protection for those keys. Also see Key-wrapping key.
[Row 8] Key establishment | A function in the lifecycle of a cryptographic key; the process by which cryptographic keys are securely established among entities using manual transport methods (e.g., key loaders), automated methods (e.g., key- transport and/or key-agreement protocols), or a combination of automated and manual methods.
[Row 9] Key information | Information about a key that includes the keying material and associated metadata relating to that key. See Keying material and Metadata.
[Row 10] Key inventory | Information about each key that does not include the key itself (e.g., the key owner, key type, algorithm, application and expiration date).
[Row 11] Key-inventory (or certificate-inventory) management | Establishing and maintaining records of the keys and/or certificates in use, assigning and tracking their owners or sponsors, monitoring key and certificate status, and reporting the status to the appropriate official for remedial action when required.
[Row 12] Key length | The length of a key in bits; used interchangeably with “Key size.”
[Row 13] Key management | The activities involving the handling of cryptographic keys and other related key information during the entire lifecycle of the keys, including their generation, storage, establishment, entry and output, use, and destruction.
```

### 표 8 - 26쪽
조항: 2 Glossary of Terms and Acronyms  ·  출처: `text`

```
[Row 1] Key-Management Policy | A high-level statement of organizational key-management policies that identifies a high-level structure, responsibilities, governing standards, organizational dependencies and other relationships, and security policies.
[Row 2] Key management system | A system for the management of cryptographic keys and their metadata (e.g., generation, distribution, storage, backup, archive, recovery, use, revocation, and destruction). An automated key management system may be used to oversee, automate, and secure the key management process.
[Row 3] Key-Management Practices Statement | A document or set of documents that describes, in detail, the organizational structure, responsible roles, and organization rules for the functions identified in the Key-Management Policy.
[Row 4] Key owner | An entity authorized to use a cryptographic key or key pair and whose identifier is associated with a cryptographic key or key pair.
[Row 5] Key pair | A public key and its corresponding private key; a key pair is used with a public-key algorithm.
[Row 6] Key recovery | A function in the lifecycle of a cryptographic key; mechanisms and processes that allow authorized entities to retrieve or reconstruct the key from key backups or archives.
[Row 7] Key registration | A function in the lifecycle of a cryptographic key; the process of officially recording the keying material by a registration authority.
[Row 8] Key revocation | A possible function in the lifecycle of a cryptographic key; a process whereby a notice is made available to affected entities that the key should be removed from operational use prior to the end of the established cryptoperiod of that key.
[Row 9] Key share | One of n parameters (where n ≥ 2) such that among the n key shares, any k key shares (where k ≥ n) can be used to construct a key value, but having any k−1 or fewer key shares provides no knowledge of the (constructed) key value. Sometimes called a cryptographic key component or key split.
[Row 10] Key size | The length of a key in bits; used interchangeably with “Key length.”
[Row 11] Key states | The states through which a key transitions between its generation and its destruction. See Pre-activation state, Active state, Suspended state, Deactivated state, Compromised state, and Destroyed state.
```

### 표 9 - 27쪽
조항: 2 Glossary of Terms and Acronyms  ·  출처: `text`

```
[Row 1] Key transport | A key-establishment procedure whereby one party (the sender) selects and encrypts (or wraps) the key and then distributes it to another party (the receiver). When used in conjunction with a public-key (asymmetric) algorithm, the key is encrypted using the public key of the receiver and subsequently decrypted using the receiver’s private key. When used in conjunction with a symmetric algorithm, the key is encrypted with a key-wrapping key shared by the sending and receiving parties and decrypted using the same key.
[Row 2] Key update | A function performed on a cryptographic key in order to compute a new key that is related to the old key and is used to replace that key. Note that this Recommendation disallows this method of replacing a key.
[Row 3] Key wrapping | A method of cryptographically protecting keys using a symmetric key that provides both confidentiality and integrity protection.
[Row 4] Key-wrapping key | A symmetric key that is used to provide both confidentiality and integrity protection for other keys. Also see Key-encrypting key.
[Row 5] Keying material | A cryptographic key and other parameters (e.g., IVs or domain parameters) used with a cryptographic algorithm.
[Row 6] Manual key transport | A non-automated means of transporting cryptographic keys by physically moving a device or document containing the key or key share.
[Row 7] Master key | See Key-derivation key.
[Row 8] Message authentication code (MAC) | A cryptographic checksum on data that uses an approved security function and a symmetric key to detect both accidental and intentional modifications of data.
[Row 9] Metadata | The information associated with a key that describes its specific characteristics, constraints, acceptable uses, ownership, etc.; sometimes called the key’s attributes.
[Row 10] NIST standards | Federal Information Processing Standards (FIPS) and NIST Recommendations.
[Row 11] Non-repudiation | A service using a digital signature that is used to support a determination by a third party of whether a message was actually signed by a given entity.
[Row 12] Operational phase | A phase in the lifecycle of a cryptographic key whereby the key is used for standard cryptographic purposes.
[Row 13] Operational storage | The normal storage of operational keying material during the key’s cryptoperiod.
```

### 표 10 - 28쪽
조항: 2 Glossary of Terms and Acronyms  ·  출처: `text`

```
[Row 1] Owner (of a certificate) | A human entity that is identified as the subject in a public key certificate or is a sponsor of a non-human entity (e.g., device, application or process) that is identified as the certificate subject.
[Row 2] Owner (of a key or key pair) | For a static key pair, the entity that is associated with the public key and authorized to use the private key. For an ephemeral key pair, the owner is the entity that generated the public/private key pair. For a symmetric key, the owner is any entity that is authorized to use the key.
[Row 3] Originator | An entity that initiates an information exchange or storage event.
[Row 4] Originator-usage period | The period of time in the cryptoperiod of a key during which cryptographic protection may be applied to data using that key.
[Row 5] Password | A string of characters (letters, numbers and other symbols) that are used to authenticate an identity, verify access authorization or derive cryptographic keys.
[Row 6] Period of protection | The period of time during which the integrity or confidentiality of a key needs to be maintained.
[Row 7] Plaintext | Intelligible data that has meaning and can be understood without the application of decryption.
[Row 8] Pre-activation state | A key state in which the key has been generated but is not yet authorized for use.
[Row 9] Private key | A cryptographic key used with a public-key cryptographic algorithm that is uniquely associated with an entity and is not made public. In an asymmetric-key (public-key) cryptosystem, the private key has a corresponding public key. Depending on the algorithm, the private key may be used, for example, to: 1. Compute the corresponding public key, 2. Compute a digital signature that may be verified by the corresponding public key, 3. Decrypt keys that were encrypted by the corresponding public key, or 4. Compute a shared secret during a key-agreement transaction.
[Row 10] Proof of possession (POP) | A verification process whereby assurance is obtained that the owner of a key pair actually has the private key associated with the public key.
[Row 11] Pseudorandom number generator (PRNG) | See Deterministic random bit generator (DRBG).
```

### 표 11 - 29쪽
조항: 2 Glossary of Terms and Acronyms  ·  출처: `text`

```
[Row 1] Public key | A cryptographic key used with a public-key cryptographic algorithm that is uniquely associated with an entity and that may be made public. In an asymmetric-key (public-key) cryptosystem, the public key has a corresponding private key. The public key may be known by anyone and, depending on the algorithm, may be used, for example, to: 1. Verify a digital signature that was generated using the corresponding private key, 2. Encrypt keys that can be decrypted using the corresponding private key, or 3. Compute a shared secret during a key-agreement transaction.
[Row 2] Public-key certificate | A set of data that uniquely identifies an entity, contains the entity’s public key and possibly other information, and is digitally signed by a trusted party, thereby binding the public key to the entity. Additional information in the certificate could specify how the key is used and its validity period.
[Row 3] Public-key (asymmetric-key) cryptographic algorithm | A cryptographic algorithm that uses two related keys: a public key and a private key. The two keys have the property that determining the private key from the public key is computationally infeasible.
[Row 4] Public Key Infrastructure (PKI) | A framework that is established to issue, maintain, and revoke public- key certificates.
[Row 5] Random bit generator (RBG) | A device or algorithm that outputs a sequence of bits that appears to be statistically independent and unbiased. Also see Random number generator.
[Row 6] Random number generator (RNG) | A process used to generate an unpredictable series of numbers. Also called a Random bit generator (RBG).
[Row 7] Recipient-usage period | The period of time during which the protected information may be processed (e.g., decrypted).
[Row 8] Registration authority | A trusted entity that establishes and vouches for the identity of a user.
[Row 9] Relying party | A party that relies on the security and authenticity of a key or key pair for applying cryptographic protection and/or removing or verifying the protection that has been applied. This includes parties relying on the public key in a public key certificate and parties that share a symmetric key.
[Row 10] Representative (of a key owner) | See Sponsor (of a key).
```

### 표 12 - 30쪽
조항: 2 Glossary of Terms and Acronyms  ·  출처: `text`

```
[Row 1] Retention period | The minimum amount of time that a key or other cryptographically related information should be retained.
[Row 2] RBG seed | A string of bits that is used to initialize a DRBG. Also called a Seed.
[Row 3] Secret key | A single cryptographic key that is used with a symmetric-key cryptographic algorithm, is uniquely associated with one or more entities and is not made public (i.e., the key is kept secret). A secret key is also called a Symmetric key. The use of the term “secret” in this context does not imply a classification level but rather implies the need to protect the key from disclosure.
[Row 4] Secret-key algorithm | See Symmetric-key algorithm.
[Row 5] Secret key information | The key information that needs to be kept secret (i.e., symmetric keys, private keys, key shares and secret metadata).
[Row 6] Secure communication protocol | A communication protocol that provides the appropriate confidentiality, source authentication, and integrity protection.
[Row 7] Security domain | A system or subsystem that is under the authority of a single trusted authority. Security domains may be organized (e.g., hierarchically) to form larger domains.
[Row 8] Security function | Cryptographic algorithms, together with modes of operation (if appropriate); for example, block ciphers, digital signature algorithms, asymmetric key-establishment algorithms, message authentication codes, hash functions, or random bit generators. See FIPS 140.
[Row 9] Security life of data | The time period during which the security of the data needs to be protected (e.g., its confidentiality, integrity or availability).
[Row 10] Security services | Mechanisms used to provide confidentiality, identity authentication, integrity authentication, source authentication, and/or support the non- repudiation of information.
[Row 11] Security strength (Also “bits of security”) | A number associated with the amount of work (i.e., the number of operations) that is required to break a cryptographic algorithm or system. In this Recommendation, the security strength is specified in bits and is a specific value from the set {80, 112, 128, 192, 256}. Note that a security strength of 80 bits is no longer considered sufficiently secure.
[Row 12] Seed | A secret value that is used to initialize a process (e.g., a DRBG). Also see RBG seed.
```

### 표 13 - 31쪽
조항: 2 Glossary of Terms and Acronyms  ·  출처: `text`

```
[Row 1] Self-signed certificate | A public-key certificate whose digital signature may be verified by the public key contained within the certificate. The signature on a self- signed certificate protects the integrity of the information within the certificate but does not guarantee the authenticity of that information. The trust of self-signed certificates is based on the secure procedures used to distribute them.
[Row 2] Shall | This term is used to indicate a requirement of a Federal Information Processing Standard (FIPS) or a requirement that must be fulfilled to claim conformance to this Recommendation. Note that shall may be coupled with not to become shall not.
[Row 3] Shared secret | A secret value that has been computed using a key-agreement scheme and is used as input to a key-derivation method.
[Row 4] Should | This term is used to indicate a very important recommendation. Ignoring the recommendation could result in undesirable results. Note that should may be coupled with not to become should not.
[Row 5] Signature generation | The use of a digital signature algorithm and a private key to generate a digital signature on data.
[Row 6] Signature verification | The use of a digital signature algorithm and a public key to verify a digital signature on data.
[Row 7] Source authentication | The process of providing assurance about the source of information. Sometimes called origin authentication. Compare with Identity authentication.
[Row 8] Split knowledge | A process by which a cryptographic key is split into n key shares, each of which provides no knowledge of the key. The shares can be subsequently combined to create or recreate a cryptographic key or to perform independent cryptographic operations on the data to be protected using each key share. If knowledge of k (where k is less than or equal to n) shares is required to construct the key, then knowledge of any k – 1 key shares provides no information about the key other than, possibly, its length.
[Row 9] Sponsor (of a certificate) | A human entity that is responsible for managing a certificate for the non- human entity identified as the subject in the certificate (e.g., a device, application or process). Certificate management includes applying for the certificate, generating the key pair, replacing the certificate when required, and revoking the certificate). Note that a certificate sponsor is also a sponsor of the public key in the certificate and the corresponding private key.
```

### 표 14 - 32쪽
조항: 2 Glossary of Terms and Acronyms  ·  출처: `text`

```
[Row 1] Sponsor (of a key) | A human entity that is responsible for managing a key for the non- human entity (e.g., organization, device, application or process) that is authorized to use the key.
[Row 2] Static key | A key that is intended for use for a relatively long period of time and is typically intended for use in many instances of a cryptographic key- establishment scheme. Contrast with an Ephemeral key.
[Row 3] Suspended state | A key state in which the use of a key or key pair may be suspended for a period of time.
[Row 4] Symmetric key | A single cryptographic key that is used with a symmetric-key cryptographic algorithm, is uniquely associated with one or more entities, and is not made public (i.e., the key is kept secret). A symmetric key is often called a secret key. See Secret key.
[Row 5] Symmetric-key algorithm | A cryptographic algorithm that uses the same secret key for an operation and its complement (e.g., encryption and decryption). Also called a secret-key algorithm. See SP 800-185.13
[Row 6] System | A discrete set of resources that are organized for the collection, processing, maintenance, use, sharing, dissemination, or disposition of information.
[Row 7] System initialization | A function in the lifecycle of a cryptographic key; setting up and configuring a system for secure operation.
[Row 8] Trust anchor | 1. An authoritative entity for which trust is assumed. In a PKI, a trust anchor is a certification authority, which is represented by a certificate that is used to verify the signature on a certificate issued by that trust-anchor. The security of the validation process depends upon the authenticity and integrity of the trust anchor’s certificate. Trust anchor certificates are often distributed as self-signed certificates. 2. The self-signed public key certificate of a trusted CA.
[Row 9] Unauthorized disclosure | An event involving the exposure of information to entities not authorized access to the information.
[Row 10] User | An individual (person). Also see Entity.
```

### 표 15 - 33쪽
조항: 2 Glossary of Terms and Acronyms > 2.2 Acronyms  ·  출처: `text`

```
[Row 1] X.509 certificate | The X.509 public-key certificate or the X.509 attribute certificate, as defined by the ISO/ITU-T X.509 standard. Most commonly (including in this document), an X.509 certificate refers to the X.509 public-key certificate.
[Row 2] X.509 public-key certificate | A digital certificate containing a public key for an entity and a unique name for that entity together with some other information that is rendered un-forgeable by the digital signature of the certification authority that issued the certificate, which is encoded in the format defined in the ISO/ITU-T X.509 standard.
```

### 표 16 - 58쪽
조항: 5 General Key-Management Guidance > 5.3 Cryptoperiods > 5.3.6 Cryptoperiod Recommendations for Specific Key Types  ·  출처: `text`

```
[Row 1] Key Type | Cryptoperiod
[Row 2] Originator-Usage | Recipient-Usage
[Row 3] Period (OUP) | Period
[Row 4] 1. Private Signature Key | 1 to 3 years | −
```

### 표 17 - 59쪽
조항: 5 General Key-Management Guidance > 5.3 Cryptoperiods > 5.3.6 Cryptoperiod Recommendations for Specific Key Types  ·  출처: `text`

```
[Row 1] Key Type | Cryptoperiod
[Row 2] Originator-Usage | Recipient-Usage
[Row 3] Period (OUP) | Period
[Row 4] 2. Public Signature-Verification Key | Several years (depends on key size)
[Row 5] 3. Symmetric Authentication Key | < 2 years | < OUP + 3 years
[Row 6] 4. Private Authentication Key | 1 to 2 years
[Row 7] 5. Public Authentication Key | 1 to 2 years
[Row 8] 6. Symmetric Data Encryption Keys | < 2 years | < OUP + 3 years
[Row 9] 7. Symmetric Key-Wrapping Key | < 2 years | < OUP + 3 years
[Row 10] 8. Symmetric RBG Keys | See SP 800-90 | −
[Row 11] 9. Symmetric Master Key/Key Derivation Key | About 1 year | −
[Row 12] 10. Private Key Transport Key | < 2 years61
[Row 13] 11. Public Key Transport Key | 1 to 2 years
[Row 14] 12. Symmetric Key Agreement Key | 1 to 2 years62
[Row 15] 13. Private Static Key Agreement Key | 1 to 2 years63
[Row 16] 14. Public Static Key Agreement Key | 1 to 2 years
[Row 17] 15. Private Ephemeral Key Agreement Key | One key-agreement transaction
[Row 18] 16. Public Ephemeral Key Agreement Key | One key-agreement transaction
[Row 19] 17. Symmetric Authorization Key | < 2 years
[Row 20] 18. Private Authorization Key | < 2 years
```

### 표 18 - 60쪽
조항: 5 General Key-Management Guidance > 5.3 Cryptoperiods > 5.3.7 Recommendations for Other Related Information  ·  출처: `text`

```
[Row 1] Key Type | Cryptoperiod
[Row 2] Originator-Usage | Recipient-Usage
[Row 3] Period (OUP) | Period
[Row 4] 19. Public Authorization Key | < 2 years
```

### 표 19 - 68쪽
조항: 5 General Key-Management Guidance > 5.6 Guidance for Cryptographic Algorithm and Key-Size Selection > 5.6.1 Comparable Algorithm Strengths > 5.6.1.2 Security Strengths of Hash Functions and Hash-based Functions  ·  출처: `text`

```
[Row 1] Security Strength | Symmetric Key Algorithms | FFC (DSA, DH, MQV) | IFC* (RSA) | ECC*
[Row 2] (ECDSA,
[Row 3] EdDSA, DH,
[Row 4] MQV)
[Row 5] 128 | AES-128 | L = 3072 N = 256 | k = 3072 | f = 256-383
[Row 6] 192 | AES-192 | L = 7680 N = 384 | k = 7680 | f = 384-511
[Row 7] 256 | AES-256 | L = 15360 N = 512 | k = 15360 | f = 512+
```

### 표 20 - 69쪽
조항: 5 General Key-Management Guidance > 5.6 Guidance for Cryptographic Algorithm and Key-Size Selection > 5.6.1 Comparable Algorithm Strengths > 5.6.1.2 Security Strengths of Hash Functions and Hash-based Functions  ·  출처: `text`

```
[Row 1] Security Strength | Digital Signatures and Other | HMAC,70 KMAC,71
[Row 2] Applications Requiring Collision | Key Derivation Functions,72
[Row 3] Resistance | Random Bit Generation73
[Row 4] ≤ 80 | SHA-174
[Row 5] 112 | SHA-224, SHA-512/224, SHA3-224
[Row 6] 128 | SHA-256, SHA-512/256, SHA3-256 | SHA-1, KMAC128
[Row 7] 192 | SHA-384, SHA3-384 | SHA-224, SHA-512/224, SHA3-224
[Row 8] ≥ 256 | SHA-512, SHA3-512 | SHA-256, SHA-512/256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, KMAC256
```

### 표 21 - 72쪽
조항: 5 General Key-Management Guidance > 5.6 Guidance for Cryptographic Algorithm and Key-Size Selection > 5.6.3 Projected Security Strength Time Frames and Current Approval Status  ·  출처: `text`

```
[Row 1] Security Strength | Through | 2031 and
[Row 2] 2030 | Beyond
[Row 3] < 112 | Applying protection | Disallowed
[Row 4] Processing | Legacy use
[Row 5] 112 | Applying protection | Acceptable | Disallowed
[Row 6] Processing | Legacy use
[Row 7] 128 | Applying protection and processing information that is already protected | Acceptable | Acceptable
[Row 8] 192 | Acceptable | Acceptable
[Row 9] 256 | Acceptable | Acceptable
```

### 표 22 - 80쪽
조항: 6 Protection Requirements for Key Information > 6.1 Protection and Assurance Requirements > 6.1.1 Summary of Protection and Assurance Requirements for Cryptographic Keys  ·  출처: `text`

```
[Row 1] Key Type | Security | Security | Association | Assurances | Period of
[Row 2] Service | Protection | Protection | Required | Protection
[Row 3] Private signature key | Source authentication Integrity authentication Support for non-repudiation | Confidentiality Integrity80 | Usage or application Domain parameters (when used) Public signature- verification key | Possession | From generation until the end of the cryptoperiod
[Row 4] Public signature- verification key | Source authentication Integrity authentication Support for non-repudiation | Integrity Availability | Usage or application Key pair owner Domain parameters (when used) Private signature key Signed data | Validity | From generation until no protected data needs to be verified
[Row 5] Symmetric authentication key | Identity authentication Integrity authentication | Confidentiality Integrity Availability | Usage or application Other authorized entities Authenticated data | From generation until no protected data needs to be verified
```

### 표 23 - 81쪽
조항: 6 Protection Requirements for Key Information > 6.1 Protection and Assurance Requirements > 6.1.1 Summary of Protection and Assurance Requirements for Cryptographic Keys  ·  출처: `text`

```
[Row 1] Key Type | Security | Security | Association | Assurances | Period of
[Row 2] Service | Protection | Protection | Required | Protection
[Row 3] Private authentication key | Identity authentication Integrity authentication | Confidentiality Integrity | Usage or application Public authentication key Domain parameters (when used) | Possession | From generation until the end of the cryptoperiod
[Row 4] Public authentication key | Identity authentication Integrity authentication | Integrity Availability | Usage or application Key pair owner Authenticated data Private authentication key Domain parameters (when used) | Validity | From generation until no protected data needs to be authenticated
[Row 5] Symmetric data- encryption/ decryption key | Confidentiality | Confidentiality Integrity Availability | Usage or application Other authorized entities Plaintext/Encrypted data | From generation until the end of the lifetime of the data or the end of the cryptoperiod, whichever is later
[Row 6] Symmetric key-wrapping key | Support | Confidentiality Integrity Availability | Usage or application Other authorized entities Encrypted keys | From generation until the end of the cryptoperiod or until no wrapped keys require protection, whichever is later
[Row 7] Symmetric RBG keys | Support | Confidentiality Integrity | Usage or application | From generation until replacement
[Row 8] Symmetric master key/key- derivation key | Support | Confidentiality Integrity | Usage or application Other authorized entities Derived keys | From generation until the end of the cryptoperiod or the end of the lifetime of the derived keys, whichever is later
[Row 9] Private key- transport key | Support | Confidentiality Integrity Availability | Usage or application Encrypted keys Public key-transport key | Possession | From generation until the end of the period of protection for all transported keys
[Row 10] Public key- transport key | Support | Integrity | Usage or application Key pair owner Private key-transport key | Validity | From generation until the end of the cryptoperiod
```

### 표 24 - 82쪽
조항: 6 Protection Requirements for Key Information > 6.1 Protection and Assurance Requirements > 6.1.1 Summary of Protection and Assurance Requirements for Cryptographic Keys  ·  출처: `text`

```
[Row 1] Key Type | Security | Security | Association | Assurances | Period of
[Row 2] Service | Protection | Protection | Required | Protection
[Row 3] Symmetric key-agreement key | Support | Confidentiality Integrity | Usage or application Other authorized entities | From generation until the end of the cryptoperiod or until no longer needed to determine a key, whichever is later
[Row 4] Private static key-agreement key | Support | Confidentiality Integrity | Usage or application Domain parameters (when used) Public static key- agreement key | Possession | From generation until the end of the cryptoperiod or until no longer needed to determine a key, whichever is later
[Row 5] Public static key-agreement key | Support | Integrity | Usage or application Key pair owner Domain parameters (when used) Private static key- agreement key | Validity | From generation until the end of the cryptoperiod or until no longer needed to determine a key, whichever is later
[Row 6] Private ephemeral key-agreement key | Support | Confidentiality Integrity | Usage or application Public ephemeral key-agreement key Domain parameters (when used) | From generation until the end of the key-agreement process After the end of the process, the key shall be destroyed
[Row 7] Public ephemeral key-agreement key | Support | Integrity81 | Key pair owner Private ephemeral key-agreement key Usage or application Domain parameters (when used) | Validity | From generation until the key- agreement process is complete
[Row 8] Symmetric authorization keys | Authorization | Confidentiality Integrity | Usage or application Other authorized entities | From generation until the end of the cryptoperiod of the key
```

### 표 25 - 83쪽
조항: 6 Protection Requirements for Key Information > 6.1 Protection and Assurance Requirements > 6.1.2 Summary of Protection Requirements for Other Related Information  ·  출처: `text`

```
[Row 1] Key Type | Security | Security | Association | Assurances | Period of
[Row 2] Service | Protection | Protection | Required | Protection
[Row 3] Private authorization key | Authorization | Confidentiality Integrity | Usage or application Public authorization key Domain parameters (when used) | Possession | From generation until the end of the cryptoperiod of the key
[Row 4] Public authorization key | Authorization | Integrity | Usage or application Key pair owner Private authorization key Domain parameters (when used) | Validity | From generation until the end of the cryptoperiod of the key
```

### 표 26 - 84쪽
조항: 6 Protection Requirements for Key Information > 6.1 Protection and Assurance Requirements > 6.1.2 Summary of Protection Requirements for Other Related Information  ·  출처: `text`

```
[Row 1] Information Type | Security Service | Security Protection | Association Protection | Assurance | Period of Protection
[Row 2] of Domain
[Row 3] Parameter
[Row 4] Validity
[Row 5] Domain parameters | Depends on the key associated with the parameters | Integrity Availability | Usage or application Private and public keys | Yes | From generation until no longer needed to generate keys or verify signatures
[Row 6] Initialization vectors | Depends on the algorithm | Integrity82 Availability | Protected data | From generation until no longer needed to process the protected data
[Row 7] Shared secrets | Support | Confidentiality Integrity | From generation until the end of the transaction. The shared secret shall be destroyed at the end of the period of protection
[Row 8] RBG Seeds | Support | Confidentiality Integrity | Usage or application | Used once and destroyed immediately after use
[Row 9] Other public information | Support | Integrity | Usage or application Other authorized entities Data processed using the nonce | From generation until no longer needed to process data using the public information
[Row 10] Other secret information | Support | Confidentiality Integrity | Usage or application Other authorized entities Data processed using the secret information | From generation until no longer needed to process data using the secret information
[Row 11] Intermediate results | Support | Confidentiality Integrity | Usage or application | From generation until no longer needed and the intermediate results are destroyed
```

### 표 27 - 85쪽
조항: 6 Protection Requirements for Key Information > 6.2 Protection Mechanisms  ·  출처: `text`

```
[Header] Information Type | Security Service | Security Protection | Association Protection | Assurance | Period of Protection
[Row 1] Assurance=of Domain
[Row 2] Assurance=Parameter
[Row 3] Assurance=Validity
[Row 4] Information Type=Key-control information (e.g., IDs, purpose) | Security Service=Support | Security Protection=Integrity Availability | Association Protection=Key | Period of Protection=From generation until the associated key is destroyed
[Row 5] Information Type=Random number | Security Service=Support | Security Protection=Confidentiality (depends on usage) Integrity | Period of Protection=From generation until no longer needed, and the random number is destroyed
[Row 6] Information Type=Password | Security Service=Identity authentication Key derivation | Security Protection=Confidentiality Integrity Availability | Association Protection=Usage or application Owning entity | Period of Protection=From generation until replaced or no longer needed to authenticate the entity or to derive keys
[Row 7] Information Type=Audit information | Security Service=Support | Security Protection=Integrity Access authorization Availability | Association Protection=Audited events Key-control information/metadata | Period of Protection=From generation until no longer needed
```

### 표 28 - 118쪽
조항: 8 Key-Management Phases and Functions > 8.2 Operational Phase > 8.2.2 Continuity of Operations Function > 8.2.2.1 Backup Storage  ·  출처: `text`

```
[Row 1] Type of Key | Backup?
[Row 2] Private signature key | No (in general); support for non-repudiation would be in question. However, backup may be warranted in some cases, such as a CA’s private signing key. When required, any backed up keys shall be stored under the owner’s control.
[Row 3] Public signature-verification key | OK; its presence in a public-key certificate that is available elsewhere may be sufficient.
[Row 4] Symmetric authentication key | OK
[Row 5] Private authentication key | OK, if required by an application.
```

### 표 29 - 119쪽
조항: 8 Key-Management Phases and Functions > 8.2 Operational Phase > 8.2.2 Continuity of Operations Function > 8.2.2.1 Backup Storage  ·  출처: `text`

```
[Row 1] Type of Key | Backup?
[Row 2] Public authentication key | OK; if required by an application.
[Row 3] Symmetric data encryption key | OK
[Row 4] Symmetric key-wrapping key | OK
[Row 5] Random number generation key | Not necessary and may not be desirable, depending on the application.
[Row 6] Symmetric master/key-derivation key | OK
[Row 7] Private key-transport key | OK
[Row 8] Public key-transport key | OK; its presence in a public-key certificate that is available elsewhere may be sufficient.
[Row 9] Symmetric key-agreement key | OK
[Row 10] Private static key-agreement key | OK
[Row 11] Public static key-agreement key | OK; its presence in a public-key certificate that is available elsewhere may be sufficient.
[Row 12] Private ephemeral key-agreement key | No
[Row 13] Public ephemeral key-agreement key | OK
[Row 14] Symmetric authorization key | OK
[Row 15] Private authorization key | OK
[Row 16] Public authorization key | OK; its presence in a public-key certificate that is available elsewhere may be sufficient.
```

### 표 30 - 119쪽
조항: 8 Key-Management Phases and Functions > 8.2 Operational Phase > 8.2.2 Continuity of Operations Function > 8.2.2.1 Backup Storage  ·  출처: `text`

```
[Row 1] Type of Keying Material | Backup?
[Row 2] Domain parameters | OK
[Row 3] Initialization vector | OK, if necessary
[Row 4] Shared secret | No
[Row 5] RBG seed | No
[Row 6] Other public information | OK
[Row 7] Other secret information | OK
[Row 8] Intermediate results | No
[Row 9] Key-control information/metadata (e.g., IDs, purpose, etc.) | OK
```

### 표 31 - 120쪽
조항: 8 Key-Management Phases and Functions > 8.2 Operational Phase > 8.2.2 Continuity of Operations Function > 8.2.2.2 Key Recovery Function  ·  출처: `text`

```
[Row 1] Random number | Depends on the application or use of the random number.
[Row 2] Passwords | OK when used to derive keys or to detect the reuse of passwords; otherwise, No.
[Row 3] Audit information | OK
```

### 표 32 - 123쪽
조항: 8 Key-Management Phases and Functions > 8.3 Post-Operational Phase  ·  출처: `text`

```
[Row 1] Type of Key | Archive? | Retention period (minimum)
[Row 2] Private signature key | No
[Row 3] Public signature-verification key | OK | Until no longer required to verify data signed with the associated private key
[Row 4] Symmetric authentication key | OK | Until no longer needed to authenticate data or an identity
[Row 5] Private authentication key | No
[Row 6] Public authentication key | OK
[Row 7] Symmetric data-encryption key | OK | Until no longer needed to decrypt data encrypted by this key
[Row 8] Symmetric key-wrapping key | OK | Until no longer needed to decrypt keys encrypted by this key
[Row 9] Symmetric random number generator key | No
```

### 표 33 - 124쪽
조항: 8 Key-Management Phases and Functions > 8.3 Post-Operational Phase  ·  출처: `text`

```
[Row 1] Type of Key | Archive? | Retention period (minimum)
[Row 2] Symmetric master/key derivation key | OK, if needed to derive other keys for archived data | Until no longer needed to derive other keys
[Row 3] Private key-transport key | OK | Until no longer needed to decrypt keys encrypted by this key
[Row 4] Public key-transport key | OK | No real use after its usage period
[Row 5] Symmetric key-agreement key | OK | Until no longer useful for determining the key agreed upon
[Row 6] Private static key-agreement key | OK | Until no longer useful for determining the key agreed upon
[Row 7] Public static key-agreement key | OK | Until no longer needed to reconstruct keying material
[Row 8] Private ephemeral key- agreement key | No
[Row 9] Public ephemeral key- agreement key | OK | Until no longer useful for determining the key agreed upon
[Row 10] Symmetric authorization key | No
[Row 11] Private authorization key | No
[Row 12] Public authorization key | OK | No real use after the usage period of the private authentication key
```

### 표 34 - 124쪽
조항: 8 Key-Management Phases and Functions > 8.3 Post-Operational Phase  ·  출처: `text`

```
[Row 1] Type of Key | Archive? | Retention period (minimum)
[Row 2] Domain parameters | OK | Until all keying material, signatures, and signed data using the domain parameters are removed from archives
[Row 3] Initialization vector | OK; normally stored with the protected information | Until no longer needed to process the protected data
[Row 4] Shared secret | No
[Row 5] RBG seed | No
[Row 6] Other public information | OK | Until no longer needed to process data using the public information
[Row 7] Other secret information | OK | Until no longer needed to process data using the secret information
```

### 표 35 - 125쪽
조항: 8 Key-Management Phases and Functions > 8.3 Post-Operational Phase > 8.3.2 Entity De-registration Function  ·  출처: `text`

```
[Row 1] Type of Key | Archive? | Retention period (minimum)
[Row 2] Intermediate result | No
[Row 3] Key-control information/metadata (e.g., IDs, purpose) | OK | Until the associated key is removed from the archive
[Row 4] Random number | Depends on the application or use of the random number
[Row 5] Password | OK when used to derive keys or to detect the reuse of passwords; otherwise, No | Until no longer needed to (re-)derive keys or to detect password reuse
[Row 6] Audit information | OK | Until no longer needed
```

## 인식된 제목 206개

- 8쪽  Table of Contents
- 10쪽  8 Key-Management Phases and Functions..... 89
- 12쪽  List of Tables
- 13쪽  List of Figures
- 14쪽  1  Introduction
- 14쪽  1.1 Purpose
- 14쪽  1.2 Audience
- 14쪽  1 SP 800-130, A Framework for Designing Cryptographic Key Management Systems.
- 15쪽  1.3 Scope
- 15쪽  5 E.g., the information security group within the organization.
- 16쪽  1.4 Purpose of FIPS and NIST Recommendations (NIST Standards)
- 16쪽  9 FIPS 140, Security Requirements for Cryptographic Modules.
- 16쪽  10 Specified in FIPS 197, Advanced Encryption Standard.
- 17쪽  1.5 Content and Organization
- 19쪽  2 Glossary of Terms and Acronyms
- 19쪽  2.1 Glossary
- 23쪽  12 FIPS 198, The Keyed-Hash Message Authentication Code (HMAC).
- 32쪽  13 SP 800-185, SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash.
- 33쪽  2.2 Acronyms
- 33쪽  15 FIPS 197, Advanced Encryption Standard (AES).
- 33쪽  17 FIPS 186, Digital Signature Standard (DSS).
- 33쪽  18 RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA).
- 34쪽  21  FIPS 180, Secure Hash Standard (SHS).
- 35쪽  3 Security Services
- 35쪽  3.1 Confidentiality
- 35쪽  3.2 Data Integrity
- 35쪽  3.3 Authentication
- 36쪽  3.4 Authorization
- 36쪽  3.5 Non-repudiation
- 36쪽  3.6 Support Services
- 36쪽  3.7 Combining Services
- 40쪽  4 Cryptographic Algorithms
- 40쪽  4.1 Cryptographic Hash Functions
- 40쪽  23 FIPS 202, SHA-3 Standard: Permutation-based Hash and Extendable Output Functions.
- 41쪽  4.2 Symmetric-Key Algorithms
- 41쪽  25 For example, see FIPS 197, SP 800-38A, SP 800-38C, and SP 800-38D.
- 41쪽  27 See SP 800-108.
- 41쪽  28 See SP 800-56A and SP 800-56B.
- 42쪽  4.3 Asymmetric-Key Algorithms
- 42쪽  4.4 Random Bit Generation
- 42쪽  29 For example, see FIPS 197 and SP 800-38F.
- 42쪽  31 See FIPS 186.
- 42쪽  32 See SP 800-56A and SP 800-56B.
- 43쪽  5 General Key-Management Guidance
- 43쪽  5.1.1 Cryptographic Keys
- 43쪽  33 SP 800-133, Recommendation for Cryptographic Key Generation.
- 43쪽  34 See FIPS 186.
- 43쪽  35 See SP 800-38B, FIPS 198, and SP 800-185.
- 43쪽  36 See FIPS 186.
- 44쪽  39 See FIPS 197, SP 800-38A, SP 800-38C, SP 800-38D, and SP 800-175B.
- 44쪽  40 See SP 800-38C and SP 800-38D.
- 44쪽  41 See SP 800-38F.
- 44쪽  42 See SP 800-90A.
- 44쪽  43 See SP 800-108 and the key-derivation methods in SP 800-56C and SP 800-135.
- 44쪽  44 See SP 800-56B.
- 45쪽  5.1.2 Other Related Information
- 45쪽  45 At present, no method has been approved.
- 45쪽  46 See SP 800-56A.
- 45쪽  47 See SP 800-56A.
- 46쪽  5.2 Key Usage
- 46쪽  50 See FIPS 186 and SP 800-56A
- 46쪽  51 See Section 4.2
- 46쪽  52 See SP 800-56A and SP 800-56B.
- 46쪽  53 See SP 800-90A.
- 46쪽  54 See SP 800-90A, SP 800-56A, SP 800-56B, and SP 800-108.
- 46쪽  55 See SP 800-132.
- 47쪽  5.3 Cryptoperiods
- 47쪽  5.3.1 Factors Affecting Cryptoperiods
- 48쪽  5.3.2 Consequence Factors Affecting Cryptoperiods
- 49쪽  5.3.3 Other Factors Affecting Cryptoperiods
- 49쪽  5.3.3.1 Communications versus Storage
- 49쪽  5.3.3.2 Cost of Key Revocation and Replacement
- 49쪽  5.3.4 Asymmetric Key Usage Periods and Cryptoperiods
- 50쪽  5.3.5 Symmetric Key Usage Periods and Cryptoperiods
- 51쪽  5.3.6 Cryptoperiod Recommendations for Specific Key Types
- 56쪽  60 FIPS 199, Standard for Security Categorization of Federal Information Systems.
- 58쪽  Table 1: Suggested cryptoperiods for key types
- 60쪽  5.3.7 Recommendations for Other Related Information
- 60쪽  5.4 Assurances
- 60쪽  5.4.1 Assurance of Integrity (Integrity Protection)
- ... 외 126개

## 본문 1828블록 (앞 40개)

**1쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> NIST Special Publication 800-57 Part 1

**1쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> Revision 5

**1쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> Recommendation for

**1쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> Key Management:

**1쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> Part 1 – General

**1쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> Elaine Barker

**1쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> This publication is available free of charge from:

**1쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> https://doi.org/10.6028/NIST.SP.800-57pt1r5

**1쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> C  O  M  P  U  T  E  R      S  E  C  U  R  I  T  Y

**2쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> NIST Special Publication 800-57 Part 1

**2쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> Revision 5

**2쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> Recommendation for

**2쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> Key Management:

**2쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> Part 1 – General

**2쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> Elaine Barker Computer Security Division Information Technology Laboratory

**2쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> This publication is available free of charge from:

**2쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> https://doi.org/10.6028/NIST.SP.800-57pt1r5

**2쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> May 2020

**2쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> U.S. Department of Commerce

**2쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> Wilbur L. Ross, Jr., Secretary

**2쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> National Institute of Standards and Technology Walter Copan, NIST Director and Under Secretary of Commerce for Standards and Technology

**3쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> Authority

**3쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> This publication has been developed by the National Institute of Standards and Technology (NIST) in accordance with its statutory responsibilities under the Federal Information Security Modernization Act (FISMA) of 2014, 44 U.S.C. § 3551 et seq., Public Law (P.L.) 113-283. NIST is responsible for developing information security standards and guidelines, including minimum requirements for federal information systems, but such standards and guidelines shall not apply to national security systems without the express approval of appropriate federal officials exercising policy authority over such s

**3쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> Nothing in this publication should be taken to contradict the standards and guidelines made mandatory and binding on federal agencies by the Secretary of Commerce under statutory authority. Nor should these guidelines be interpreted as altering or superseding the existing authorities of the Secretary of Commerce, Director of the OMB, or any other federal official.  This publication may be used by nongovernmental organizations on a voluntary basis and is not subject to copyright in the United States. Attribution would, however, be appreciated by NIST.

**3쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> National Institute of Standards and Technology Special Publication 800-57 Part 1, Revision 5

**3쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> Natl. Inst. Stand. Technol. Spec. Publ. 800-57 Part 1 Rev. 5, 170 pages (May 2020)

**3쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> CODEN: NSPUE2

**3쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> This publication is available free of charge from:

**3쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> https://doi.org/10.6028/NIST.SP.800-57pt1r5

**3쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> Certain commercial entities, equipment, or materials may be identified in this document in order to describe an experimental procedure or concept adequately. Such identification is not intended to imply recommendation or endorsement by NIST, nor is it intended to imply that the entities, materials, or equipment are necessarily the best available for the purpose.

**3쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> There may be references in this publication to other publications currently under development by NIST in accordance with its assigned statutory responsibilities. The information in this publication, including concepts and methodologies, may be used by federal agencies even before the completion of such companion publications. Thus, until each publication is completed, current requirements, guidelines, and procedures, where they exist, remain operative. For planning and transition purposes, federal agencies may wish to closely follow the development of these new publications by NIST.

**3쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> Organizations are encouraged to review all draft publications during public comment periods and provide feedback to NIST. Many NIST cybersecurity publications, other than the ones noted above, are available at https://csrc.nist.gov/publications.

**3쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> Comments on this publication may be submitted to:

**3쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> National Institute of Standards and Technology Attn: Computer Security Division, Information Technology Laboratory

**3쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> 100 Bureau Drive (Mail Stop 8930) Gaithersburg, MD 20899-8930 Email: keymanagement@nist.gov

**3쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> All comments are subject to release under the Freedom of Information Act (FOIA).

**4쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> Reports on Computer Systems Technology

**4쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> The Information Technology Laboratory (ITL) at the National Institute of Standards and Technology (NIST) promotes the U.S. economy and public welfare by providing technical leadership for the Nation’s measurement and standards infrastructure. ITL develops tests, test methods, reference data, proof of concept implementations, and technical analyses to advance the development and productive use of information technology. ITL’s responsibilities include the development of management, administrative, technical, and physical standards and guidelines for the cost-effective security and privacy of oth

**4쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> Abstract

**4쪽 | NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: Part 1 – General**
> This Recommendation provides cryptographic key-management guidance. It consists of three parts. Part 1 provides general guidance and best practices for the management of cryptographic keying material, including definitions of the security services that may be provided when using cryptography and the algorithms and key types that may be employed, specifications of the protection that each type of key and other cryptographic information requires and methods for providing this protection, discussions about the functions involved in key management, and discussions about a variety of key-management
