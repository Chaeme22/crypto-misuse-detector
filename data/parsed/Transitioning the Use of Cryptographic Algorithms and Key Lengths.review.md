# 파싱 검수 - Transitioning the Use of Cryptographic Algorithms and Key Lengths.pdf

- 언어 판정: `en`
- OCR 상태: `not_needed`
- 블록: {'paragraph': 348, 'heading': 38, 'table': 12}
- 조항 경로가 붙은 블록: 351/398
- 텍스트 품질: 정상

## 표 12개

표 안의 숫자와 알고리즘명이 규칙표의 임계값이 된다. 원문과 한 칸씩 대조할 것.

### 표 1 - 9쪽
조항: 1 Introduction > 1.2 Useful Terms for Understanding this Recommendation > 1.2.2 General Definitions and Abbreviations  ·  출처: `text`

```
[Row 1] Apply cryptographic protection | Depending on the algorithm, to encrypt or sign data, generate a hash function or Message Authentication Code (MAC), or establish keys (including wrapping and deriving keys).
[Row 2] Approval status | Used to designate usage by the U.S. Federal Government.
[Row 3] Approved | FIPS-approved or NIST-Recommended. An algorithm or technique that is either 1) specified in a FIPS or NIST Recommendation, or 2) adopted in a FIPS or NIST Recommendation and specified either (a) in an appendix to the FIPS or NIST Recommendation, or (b) in a document referenced by the FIPS or NIST Recommendation.
[Row 4] len(x) | The bit length of x.
[Row 5] Shall | A requirement for Federal Government use. Note that shall may be coupled with not to become shall not.
```

### 표 2 - 10쪽
조항: 1 Introduction > 1.2 Useful Terms for Understanding this Recommendation > 1.2.2 General Definitions and Abbreviations  ·  출처: `text`

```
[Row 1] AES | Advanced Encryption Standard specified in FIPS 197.16
[Row 2] CCM | Counter with Cipher-block-chaining Message authentication code, _ specified in SP 800-38C.17
[Row 3] CMAC | Message Authentication Code mode specified in SP 800-38B.18
[Row 4] CTR DRBG _ | A DRBG specified in SP 800-90A19 based on a block cipher algorithm.
[Row 5] DH | Diffie-Hellman algorithm specified in SP 800-56A.
[Row 6] DRBG | Deterministic Random Bit Generator.
[Row 7] DSA | Digital Signature Algorithm specified in FIPS 186.
[Row 8] Dual EC DRBG _ _ | A DRBG originally specified in SP 800-90A that has been withdrawn.
[Row 9] ECDSA | Elliptic Curve Digital Signature Algorithm specified in FIPS 186.
[Row 10] EdDSA | Edwards Curve Digital Signature Algorithm specified in FIPS 186.
[Row 11] FIPS | Federal Information Processing Standard.
[Row 12] GCM | Galois Counter Mode specified in SP 800-38D.20
[Row 13] GMAC | Galois Message Authentication Mode specified in SP 800-38D.
[Row 14] Hash DRBG _ | A DRBG specified in SP 800-90A based on a hash funcrion.
[Row 15] HMAC | Keyed Hash Message Authentication Code specified in FIPS 198.21
[Row 16] HMAC DRBG _ | A DRBG specified in SP 800-90A based on HMAC.
[Row 17] KMAC | Keccak Message Authentication Code specified in SP 800-185.
```

### 표 3 - 11쪽
조항: 1 Introduction > 1.2 Useful Terms for Understanding this Recommendation > 1.2.3 Definition of Status Approval Terms  ·  출처: `text`

```
[Header] KW | Key Wrap mode specified in SP 800-38F.22
[Row 1] KW=KWP | Key Wrap mode specified in SP 800-38F.22=Key Wrap with Padding mode specified in SP 800-38F.
[Row 2] KW=MAC | Key Wrap mode specified in SP 800-38F.22=Message Authentication Code.
[Row 3] KW=MQV | Key Wrap mode specified in SP 800-38F.22=Menezes-Qu-Vanstone algorithm.
[Row 4] KW=NIST | Key Wrap mode specified in SP 800-38F.22=National Institute of Standards and Technology.
[Row 5] KW=PKCS1 | Key Wrap mode specified in SP 800-38F.22=Public Key Cryptography Standard 1.
[Row 6] KW=RNG | Key Wrap mode specified in SP 800-38F.22=Random Number Generator.
[Row 7] KW=RSA | Key Wrap mode specified in SP 800-38F.22=Rivest-Shamir-Adelman algorithm.
[Row 8] KW=SHA | Key Wrap mode specified in SP 800-38F.22=Secure Hash Algoriithm specified in FIPS 18023 and FIPS 202.24
[Row 9] KW=SP | Key Wrap mode specified in SP 800-38F.22=Special Publication.
[Row 10] KW=TDEA | Key Wrap mode specified in SP 800-38F.22=Triple Data Encryption Algorithm specified in SP 800-67.25
[Row 11] KW=TKW | Key Wrap mode specified in SP 800-38F.22=Triple Data Encryption Algorithm Wrapping as specified in SP 800- 38F.
```

### 표 4 - 13쪽
조항: 2 Encryption and Decryption Using Block Cipher Algorithms  ·  출처: `text`

```
[Header] Algorithm | Status
[Row 1] Algorithm=Two-key TDEA Encryption | Status=Disallowed
[Row 2] Algorithm=Two-key TDEA Decryption | Status=Legacy use
[Row 3] Algorithm=Three-key TDEA Encryption | Status=Deprecated through 2023 Disallowed after 2023
[Row 4] Algorithm=Three-key TDEA Decryption | Status=Legacy use
[Row 5] Algorithm=SKIPJACK Encryption | Status=Disallowed
[Row 6] Algorithm=SKIPJACK Decryption | Status=Legacy use
[Row 7] Algorithm=AES-128 Encryption and Decryption | Status=Acceptable
[Row 8] Algorithm=AES-192 Encryption and Decryption | Status=Acceptable
[Row 9] Algorithm=AES-256 Encryption and Decryption | Status=Acceptable
```

### 표 5 - 15쪽
조항: 3 Digital Signatures  ·  출처: `text`

```
[Row 1] Digital Signature Process | Domain Parameters | Status
[Row 2] Digital Signature Generation | < 112 bits of security strength: DSA: (L, N) ≠ (2048, 224), (2048, 256) or (3072, 256) ECDSA: len(n) < 224 RSA: len(n) < 2048 | Disallowed
[Row 3] ≥ 112 bits of security strength: DSA: (L, N) = (2048, 224), (2048, 256) or (3072, 256) ECDSA or EdDSA: len(n) ≥ 224 RSA: len(n) ≥ 2048 | Acceptable
[Row 4] Digital Signature Verification | < 112 bits of security strength: DSA32: ((512 ≤ L < 2048) or (160 ≤ N < 224)) ECDSA: 160 ≤ len(n) < 224 RSA: 1024 ≤ len(n) < 2048 | Legacy use
[Row 5] ≥ 112 bits of security strength: DSA: (L, N) = (2048, 224), (2048, 256) or (3072, 256) ECDSA and EdDSA: len(n) ≥ 224 RSA: len(n) ≥ 2048 | Acceptable
```

### 표 6 - 17쪽
조항: 4 Random Bit Generation  ·  출처: `text`

```
[Row 1] Algorithm | Status
[Row 2] Hash DRBG and HMAC DRBG _ _ | Acceptable
[Row 3] CTR DRBG with three-key TDEA _ | Deprecated through 2023 Disallowed after 2023
[Row 4] CTR DRBG with AES-128, AES-192 _ and AES-256AES-256 | Acceptable
[Row 5] DUAL EC DRBG _ _ | Disallowed
[Row 6] RNGs in FIPS 186-242, ANS X9.3143 and ANS X9.62-1998 | Disallowed
```

### 표 7 - 19쪽
조항: 4 Random Bit Generation  ·  출처: `text`

```
[Row 1] Scheme | Domain Parameters | Status
[Row 2] SP 800-56A DH and MQV schemes using finite fields | < 112 bits of security strength: (len(p), len(q)) = (1024, 160) | Disallowed
[Row 3] ≥ 112 bits of security strength: Using listed safe-prime groups OR FIPS 186-type domain parameters (112-bit security strength only): (len(p), len(q)) = (2048, 224) or (2048, 256) | Acceptable
[Row 4] Non-compliant DH and MQV schemes using finite fields | < 112 bits of security strength: len(p) < 2048 OR len(q) < 224 | Disallowed
[Row 5] Non-conformance to SP 800-56A | Disallowed after 2020
[Row 6] SP 800-56A DH and MQV schemes using elliptic curves | < 112 bits of security strength: len(n) < 224 | Disallowed
[Row 7] ≥ 112 bits of security strength: (Using specified curves) | Acceptable
[Row 8] Non-compliant DH and MQV schemes using elliptic curves | < 112 bits of security strength: len(n) < 224 | Disallowed
[Row 9] ≥ 112 bits of security strength: Non-conformance to SP 800-56A or IG A.2 | Disallowed after 2020
```

### 표 8 - 21쪽
조항: 7 Key Wrapping  ·  출처: `text`

```
[Header] Scheme | Implementation Details | Status
[Row 1] Scheme=SP 800-56B Key Agreement and Key Transport schemes | Implementation Details=len(n) < 2048 | Status=Disallowed
[Row 2] Implementation Details=len(n) ≥ 2048 | Status=Acceptable
[Row 3] Scheme=Non-SP 800-56B- compliant Key Agreement and Key Transport schemes | Implementation Details=len(n) < 2048 | Status=Disallowed
[Row 4] Implementation Details=PKCS1-v1 5 padding _ | Status=Deprecated through 2023 Disallowed after 2023
[Row 5] Implementation Details=Other non-compliance with SP 800-56B | Status=Deprecated through 2020 Disallowed after 2020
```

### 표 9 - 22쪽
조항: 8 Deriving Additional Keys from a Cryptographic Key  ·  출처: `text`

```
[Row 1] Algorithm | Status
[Row 2] Key wrapping using two-key TDEA | Disallowed
[Row 3] Key unwrapping using two-key TDEA | Legacy use
[Row 4] Key wrapping using three-key TDEA and any approved key-wrapping method | Deprecated through 2023 Disallowed after 2023
[Row 5] Key unwrapping using three-key TDEA and any approved key-unwrapping method | Legacy use
[Row 6] Key wrapping and unwrapping using AES-128, AES- 192 or AES-256 and any method for key wrapping that is specified or otherwise approved in SP 800-38F | Acceptable
```

### 표 10 - 23쪽
조항: 9 Hash Functions  ·  출처: `text`

```
[Row 1] KDF Type | Algorithm | Status
[Row 2] HMAC-based KDF | HMAC using any approved hash function | Acceptable
[Row 3] CMAC-based KDF | CMAC using two-key TDEA | Disallowed
[Row 4] CMAC using three-key TDEA | Deprecated through 2023 Disallowed after 2023
[Row 5] CMAC using AES | Acceptable
```

### 표 11 - 24쪽
조항: 9 Hash Functions  ·  출처: `text`

```
[Row 1] Hash Function | Use | Status
[Row 2] SHA-1 | Digital signature generation | Disallowed, except where specifically allowed by NIST protocol-specific guidance.
[Row 3] Digital signature verification | Legacy use
[Row 4] Non-digital-signature applications | Acceptable
[Row 5] SHA-2 family (SHA- 224, SHA-256, SHA-384, SHA-512, SHA-512/224 and SHA-512/256) | Acceptable for all hash function applications
[Row 6] SHA-3 family (SHA3-224, SHA3- | Acceptable for all hash function applications
```

### 표 12 - 26쪽
조항: 10 Message Authentication Codes (MACs)  ·  출처: `text`

```
[Row 1] MAC Algorithm | Implementation Details | Status
[Row 2] HMAC Generation | Key lengths < 112 bits | Disallowed
[Row 3] Key lengths ≥ 112 bits | Acceptable
[Row 4] HMAC Verification | Key lengths < 112 bits | Legacy use
[Row 5] Key lengths ≥ 112 bits | Acceptable
[Row 6] CMAC Generation | Two-key TDEA | Disallowed
[Row 7] Three-key TDEA | Deprecated through 2023 Disallowed after 2023
[Row 8] AES | Acceptable
[Row 9] CMAC Verification | Two-key TDEA | Legacy use
[Row 10] Three-key TDEA | Legacy use
[Row 11] AES | Acceptable
[Row 12] GMAC Generation and Verification | AES | Acceptable
[Row 13] KMAC Generation and Verification | Key lengths < 112 bits | Disallowed
[Row 14] Key lengths ≥ 112 bits | Acceptable
```

## 인식된 제목 38개

- 7쪽  1 SP 800-57, Part 1: Recommendation for Key Management: General.
- 7쪽  2 DH: Diffie-Hellman algorithm.
- 7쪽  3 MQV: Menezes-Qu-Vanstone algorithm.
- 7쪽  4 RSA: Rivest-Shamir-Adelman algorithm.
- 8쪽  1.2 Useful Terms for Understanding this Recommendation
- 8쪽  7 The term “key size” is commonly used in other documents.
- 9쪽  1.2.2 General Definitions and Abbreviations
- 9쪽  10 FIPS 186, Digital Signature Standard (DSS).
- 9쪽  14 FIPS 140, Security Requirements for Cryptographic Modules.
- 10쪽  16 FIPS 197, Advanced Encryption Standard.
- 10쪽  21 FIPS 198, Keyed-Hash Message Authentication Code (HMAC).
- 11쪽  23 FIPS 180, Secure Hash Standard (SHS).
- 11쪽  24 FIPS 202, Permutation-Based Hash and Extendable-Output Functions.
- 12쪽  27 A TDEA key bundle consists of three keys.
- 12쪽  28 FIPS 185, Escrowed Encryption Standard.
- 12쪽  29 SP 800-38 series: Recommendation for Block Cipher Modes of Operation.
- 13쪽  Table 1: Approval Status of Symmetric Algorithms Used for
- 14쪽  30 EdDSA will be specified in FIPS 186-5 for public comment.
- 15쪽  Table 2: Approval Status of Algorithms Used for Digital Signature
- 16쪽  34 IG A.2, Use of Non-NIST Recommended Asymmetric Key Sizes and Elliptic Curves.
- 16쪽  35 IG 7.5, Strength of Key Establishment Methods.
- 16쪽  36 FIPS 186-2 includes the 512 and 1024-bit key lengths.
- 16쪽  37 FIPS 186-4 includes the 1024-bit key length.
- 16쪽  40 FIPS 186-4 includes approval for the 1024-bit modulus length.
- 17쪽  Table 3: Approval Status of Algorithms Used for Random Bit Generation
- 17쪽  42 FIPS 186-2, Digital Signature Standard (DSS).
- 19쪽  Table 4: Approval Status for SP 800-56A Key Agreement (DH and
- 21쪽  Table 5 (below) provides the approval status the choice of n.
- 21쪽  Table 5: Approval Status for the RSA-based Key Agreement and Key
- 22쪽  Table 6: Approval Status of Block Cipher Algorithms Used for Key
- 23쪽  Table 7 provides the approval status of the PRFs for key derivation.
- 23쪽  Table 7: Approval Status of the Algorithms Used for a Key Derivation
- 24쪽  Table 8 provides the approval status of the hash functions.
- 24쪽  Table 8: Approval Status of Hash Functions
- 24쪽  45 SP 800-107, Recommendation for Applications Using Approved Hash Algorithms.
- 24쪽  46 The approved uses of XOFs may be addressed in future publications.
- 24쪽  47 SP 800-185, SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash and ParallelHash.
- 26쪽  Table 9: Approval Status of MAC Algorithms

## 본문 348블록 (앞 40개)

**1쪽 | (조항 없음)**
> NIST Special Publication 800-131A

**1쪽 | (조항 없음)**
> Revision 2

**1쪽 | (조항 없음)**
> Transitioning the Use of Cryptographic Algorithms and

**1쪽 | (조항 없음)**
> Key Lengths

**1쪽 | (조항 없음)**
> Elaine Barker Allen Roginsky

**1쪽 | (조항 없음)**
> This publication is available free of charge from:

**1쪽 | (조항 없음)**
> https://doi.org/10.6028/NIST.SP.800-131Ar2

**1쪽 | (조항 없음)**
> C  O  M  P  U  T  E  R      S  E  C  U  R  I  T  Y

**2쪽 | (조항 없음)**
> NIST Special Publication 800-131A

**2쪽 | (조항 없음)**
> Revision 2

**2쪽 | (조항 없음)**
> Transitioning the Use of Cryptographic Algorithms and

**2쪽 | (조항 없음)**
> Key Lengths

**2쪽 | (조항 없음)**
> Elaine Barker Allen Roginsky Computer Security Division Information Technology Laboratory

**2쪽 | (조항 없음)**
> This publication is available free of charge from:

**2쪽 | (조항 없음)**
> https://doi.org/10.6028/NIST.SP.800-131Ar2

**2쪽 | (조항 없음)**
> March 2019

**2쪽 | (조항 없음)**
> U.S. Department of Commerce

**2쪽 | (조항 없음)**
> Wilbur L. Ross, Jr., Secretary

**2쪽 | (조항 없음)**
> National Institute of Standards and Technology Walter Copan, NIST Director and Under Secretary of Commerce for Standards and Technology

**3쪽 | (조항 없음)**
> Authority

**3쪽 | (조항 없음)**
> This publication has been developed by NIST in accordance with its statutory responsibilities under the Federal Information Security Modernization Act (FISMA) of 2014, 44 U.S.C. § 3551 et seq., Public Law (P.L.) 113-283. NIST is responsible for developing information security standards and guidelines, including minimum requirements for federal information systems, but such standards and guidelines shall not apply to national security systems without the express approval of appropriate federal officials exercising policy authority over such systems. This guideline is consistent with the require

**3쪽 | (조항 없음)**
> Nothing in this publication should be taken to contradict the standards and guidelines made mandatory and binding on federal agencies by the Secretary of Commerce under statutory authority. Nor should these guidelines be interpreted as altering or superseding the existing authorities of the Secretary of Commerce, Director of the OMB, or any other federal official.  This publication may be used by nongovernmental organizations on a voluntary basis and is not subject to copyright in the United States. Attribution would, however, be appreciated by NIST.

**3쪽 | (조항 없음)**
> National Institute of Standards and Technology Special Publication 800-131A Revision 2

**3쪽 | (조항 없음)**
> Natl. Inst. Stand. Technol. Spec. Publ. 800-131A Rev. 2, 33 pages (March 2019)

**3쪽 | (조항 없음)**
> CODEN: NSPUE2

**3쪽 | (조항 없음)**
> This publication is available free of charge from:

**3쪽 | (조항 없음)**
> https://doi.org/10.6028/NIST.SP.800-131Ar2

**3쪽 | (조항 없음)**
> Certain commercial entities, equipment, or materials may be identified in this document in order to describe an experimental procedure or concept adequately. Such identification is not intended to imply recommendation or endorsement by NIST, nor is it intended to imply that the entities, materials, or equipment are necessarily the best available for the purpose.

**3쪽 | (조항 없음)**
> There may be references in this publication to other publications currently under development by NIST in accordance with its assigned statutory responsibilities. The information in this publication, including concepts and methodologies, may be used by federal agencies even before the completion of such companion publications. Thus, until each publication is completed, current requirements, guidelines, and procedures, where they exist, remain operative. For planning and transition purposes, federal agencies may wish to closely follow the development of these new publications by NIST.

**3쪽 | (조항 없음)**
> Public comment period: Month Day, YYYY through Month Day, YYYY

**3쪽 | (조항 없음)**
> Organizations are encouraged to review all draft publications during public comment periods and provide feedback to NIST. All NIST Computer Security Division publications, other than the ones noted above, are available at https://csrc.nist.gov/publications.

**3쪽 | (조항 없음)**
> Comments on this publication may be submitted to:

**3쪽 | (조항 없음)**
> National Institute of Standards and Technology Attn: Computer Security Division, Information Technology Laboratory

**3쪽 | (조항 없음)**
> 100 Bureau Drive (Mail Stop 8930) Gaithersburg, MD 20899-8930 Email: CryptoTransitions@nist.gov

**3쪽 | (조항 없음)**
> All comments are subject to release under the Freedom of Information Act (FOIA)

**4쪽 | (조항 없음)**
> Reports on Computer Systems Technology

**4쪽 | (조항 없음)**
> The Information Technology Laboratory (ITL) at the National Institute of Standards and Technology (NIST) promotes the U.S. economy and public welfare by providing technical leadership for the Nation’s measurement and standards infrastructure. ITL develops tests, test methods, reference data, proof of concept implementations, and technical analyses to advance the development and productive use of information technology. ITL’s responsibilities include the development of management, administrative, technical, and physical standards and guidelines for the cost-effective security and privacy of oth

**4쪽 | (조항 없음)**
> Abstract

**4쪽 | (조항 없음)**
> The National Institute of Standards and Technology (NIST) provides cryptographic key management guidance for defining and implementing appropriate key management procedures, using algorithms that adequately protect sensitive information, and planning ahead for possible changes in the use of cryptography because of algorithm breaks or the availability of more powerful computing techniques. NIST Special Publication (SP) 800- 57, Part 1, Recommendation for Key Management: General, includes a general approach for transitioning from one algorithm or key length to another. This Recommendation (SP 80

**4쪽 | (조항 없음)**
> Keywords
