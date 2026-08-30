# 파싱 검수 - Recommendation for Block Cipher Modes of Operation.pdf

- 언어 판정: `en`
- OCR 상태: `partial` (텍스트 없는 페이지 1개)
- 블록: {'paragraph': 577, 'heading': 19, 'table': 3}
- 조항 경로가 붙은 블록: 572/599
- 텍스트 품질: 정상

## 표 3개

표 안의 숫자와 알고리즘명이 규칙표의 임계값이 된다. 원문과 한 칸씩 대조할 것.

### 표 1 - 10쪽
조항: 3 Introduction  ·  출처: `text`

```
[Header] Bit | A binary digit: 0 or 1.
[Row 1] Bit=Bit Error | A binary digit: 0 or 1.=The substitution of a ‘0’ bit for a ‘1’ bit, or vice versa.
[Row 2] Bit=Bit String | A binary digit: 0 or 1.=An ordered sequence of 0’s and 1’s.
[Row 3] Bit=Block Cipher | A binary digit: 0 or 1.=A family of functions and their inverse functions that is parameterized by cryptographic keys; the functions map bit strings of a fixed length to bit strings of the same length.
[Row 4] Bit=Block Size | A binary digit: 0 or 1.=The number of bits in an input (or output) block of the block cipher.
[Row 5] Bit=CBC | A binary digit: 0 or 1.=Cipher Block Chaining.
[Row 6] Bit=CFB | A binary digit: 0 or 1.=Cipher Feedback.
[Row 7] Bit=Ciphertext | A binary digit: 0 or 1.=Encrypted data.
[Row 8] Bit=Confidentiality Mode | A binary digit: 0 or 1.=A mode that is used to encipher plaintext and decipher ciphertext. The confidentiality modes in this recommendation are the ECB, CBC, CFB, OFB, and CTR modes.
[Row 9] Bit=CTR | A binary digit: 0 or 1.=Counter.
[Row 10] Bit=Cryptographic Key | A binary digit: 0 or 1.=A parameter used in the block cipher algorithm that determines the forward cipher operation and the inverse cipher operation.
[Row 11] Bit=Data Block (Block) | A binary digit: 0 or 1.=A sequence of bits whose length is the block size of the block cipher.
[Row 12] Bit=Data Segment (Segment) | A binary digit: 0 or 1.=In the CFB mode, a sequence of bits whose length is a parameter that does not exceed the block size.
[Row 13] Bit=Decryption (Deciphering) | A binary digit: 0 or 1.=The process of a confidentiality mode that transforms encrypted data into the original usable data.
[Row 14] Bit=ECB | A binary digit: 0 or 1.=Electronic Codebook.
[Row 15] Bit=Encryption (Enciphering) | A binary digit: 0 or 1.=The process of a confidentiality mode that transforms usable data into an unreadable form.
```

### 표 2 - 11쪽
조항: 4 Definitions, Abbreviations, and Symbols > 4.1 Definitions and Abbreviations  ·  출처: `text`

```
[Row 1] Exclusive-OR | The bitwise addition, modulo 2, of two bit strings of equal length.
[Row 2] FIPS | Federal Information Processing Standard.
[Row 3] Forward Cipher Function (Forward Cipher Operation) | One of the two functions of the block cipher algorithm that is selected by the cryptographic key.
[Row 4] Initialization Vector (IV) | A data block that some modes of operation require as an additional initial input.
[Row 5] Input Block | A data block that is an input to either the forward cipher function or the inverse cipher function of the block cipher algorithm.
[Row 6] Inverse Cipher Function (Inverse Cipher Operation) | The function that reverses the transformation of the forward cipher function when the same cryptographic key is used.
[Row 7] Least Significant Bit(s) | The right-most bit(s) of a bit string.
[Row 8] Mode of Operation (Mode) | An algorithm for the cryptographic transformation of data that features a symmetric key block cipher algorithm.
[Row 9] Most Significant Bit(s) | The left-most bit(s) of a bit string.
[Row 10] Nonce | A value that is used only once.
[Row 11] Octet | A group of eight binary digits.
[Row 12] OFB | Output Feedback.
[Row 13] Output Block | A data block that is an output of either the forward cipher function or the inverse cipher function of the block cipher algorithm.
[Row 14] Plaintext | Usable data that is formatted as input to a mode.
```

### 표 3 - 29쪽
조항: 6 Block Cipher Modes of Operation > 6.5 The Counter Mode  ·  출처: `text`

```
[Header] Mode | Effect of Bit Errors in C j | Effect of Bit Errors in the IV
[Row 1] Mode=ECB | Effect of Bit Errors in C j=RBE in the decryption of C j | Effect of Bit Errors in the IV=Not applicable
[Row 2] Mode=CBC | Effect of Bit Errors in C j=RBE in the decryption of C j SBE in the decryption of C j+1 | Effect of Bit Errors in the IV=SBE in the decryption of C 1
[Row 3] Mode=CFB | Effect of Bit Errors in C j=SBE in the decryption of C j RBE in the decryption of C ,…,C j+1 j+b/s | Effect of Bit Errors in the IV=RBE in the decryption of C, C, …, C 1 2 j for some j between 1 and b/s
[Row 4] Mode=OFB | Effect of Bit Errors in C j=SBE in the decryption of C j | Effect of Bit Errors in the IV=RBE in the decryption of C, C, …, C 1 2 n
[Row 5] Mode=CTR | Effect of Bit Errors in C j=SBE in the decryption of C j | Effect of Bit Errors in the IV=Not applicable *
```

## 인식된 제목 19개

- 8쪽  1 Purpose
- 8쪽  2 Authority
- 8쪽  3 Introduction
- 10쪽  4 Definitions, Abbreviations, and Symbols
- 10쪽  4.1 Definitions and Abbreviations
- 12쪽  4.2 Symbols
- 12쪽  4.2.1 Variables
- 12쪽  4.2.2 Operations and Functions
- 14쪽  5 Preliminaries
- 14쪽  5.1 Underlying Block Cipher Algorithm
- 14쪽  5.2 Representation of the Plaintext and the Ciphertext
- 15쪽  5.3 Initialization Vectors
- 15쪽  5.4 Examples of Operations and Functions
- 16쪽  6 Block Cipher Modes of Operation
- 16쪽  6.1 The Electronic Codebook Mode
- 17쪽  6.2 The Cipher Block Chaining Mode
- 18쪽  6.3 The Cipher Feedback Mode
- 20쪽  6.4 The Output Feedback Mode
- 22쪽  6.5 The Counter Mode

## 본문 577블록 (앞 40개)

**1쪽 | (조항 없음)**
> NIST Special Publication 800-38A Recommendation for Block 2001 Edition Cipher Modes of Operation

**1쪽 | (조항 없음)**
> Methods and Techniques

**1쪽 | (조항 없음)**
> Morris Dworkin

**1쪽 | (조항 없음)**
> C  O  M  P  U  T  E  R S  E  C  U  R  I  T  Y

**3쪽 | (조항 없음)**
> C  O  M  P  U  T  E  R S  E  C  U  R  I  T  Y

**3쪽 | (조항 없음)**
> Computer Security Division Information Technology Laboratory National Institute of Standards and Technology Gaithersburg, MD 20899-8930

**3쪽 | (조항 없음)**
> December 2001

**3쪽 | (조항 없음)**
> U.S. Department of Commerce Donald L. Evans, Secretary

**3쪽 | (조항 없음)**
> Technology Administration Phillip J. Bond, Under Secretary of Commerce for Technology

**3쪽 | (조항 없음)**
> National Institute of Standards and Technology Arden L. Bement, Jr., Director

**3쪽 | (조항 없음)**
> iii

**4쪽 | (조항 없음)**
> Reports on Information Security Technology

**4쪽 | (조항 없음)**
> The Information Technology Laboratory (ITL) at the National Institute of Standards and Technology (NIST) promotes the U.S. economy and public welfare by providing technical leadership for the Nation’s measurement and standards infrastructure. ITL develops tests, test methods, reference data, proof of concept implementations, and technical analyses to advance the development and productive use of information technology. ITL’s responsibilities include the development of technical, physical, administrative, and management standards and guidelines for the cost-effective security and privacy of sen

**4쪽 | (조항 없음)**
> Certain commercial entities, equipment, or materials may be identified in this document in order to describe an experimental procedure or concept adequately. Such identification is not intended to imply recommendation or endorsement by the National Institute of Standards and Technology, nor is it intended to imply that the entities, materials, or equipment are necessarily the best available for the purpose.

**4쪽 | (조항 없음)**
> National Institute of Standards and Technology Special Publication 800-38A 2001 ED

**4쪽 | (조항 없음)**
> Natl. Inst. Stand. Technol. Spec. Publ. 800-38A 2001 ED, 66 pages (December 2001)

**4쪽 | (조항 없음)**
> CODEN: NSPUE2

**4쪽 | (조항 없음)**
> U.S. GOVERNMENT PRINTING OFFICE

**4쪽 | (조항 없음)**
> WASHINGTON: 2001

**4쪽 | (조항 없음)**
> For sale by the Superintendent of Documents, U.S. Government Printing Office

**4쪽 | (조항 없음)**
> Internet: bookstore.gpo.gov — Phone: (202) 512-1800 — Fax: (202) 512-2250

**4쪽 | (조항 없음)**
> Mail: Stop SSOP, Washington, DC 20402-0001

**4쪽 | (조항 없음)**
> iv

**5쪽 | (조항 없음)**
> Abstract

**5쪽 | (조항 없음)**
> This recommendation defines five confidentiality modes of operation for use with an underlying symmetric key block cipher algorithm: Electronic Codebook (ECB), Cipher Block Chaining (CBC), Cipher Feedback (CFB), Output Feedback (OFB), and Counter (CTR).  Used with an underlying block cipher algorithm that is approved in a Federal Information Processing Standard (FIPS), these modes can provide cryptographic protection for sensitive, but unclassified, computer data.

**5쪽 | (조항 없음)**
> KEY WORDS: Computer security; cryptography; data security; block cipher; encryption; Federal Information Processing Standard; mode of operation.

**5쪽 | (조항 없음)**
> v

**8쪽 | 1 Purpose**
> This publication provides recommendations regarding modes of operation to be used with symmetric key block cipher algorithms.

**8쪽 | 2 Authority**
> This document has been developed by the National Institute of Standards and Technology (NIST) in furtherance of its statutory responsibilities under the Computer Security Act of 1987 (Public Law 100-235) and the Information Technology Management Reform Act of 1996, specifically 15 U.S.C. 278 g-3(a)(5). This is not a guideline within the meaning of 15 U.S.C. 278 g-3 (a)(5).

**8쪽 | 2 Authority**
> This recommendation is neither a standard nor a guideline, and as such, is neither mandatory nor binding on Federal agencies. Federal agencies and non-government organizations may use this recommendation on a voluntary basis. It is not subject to copyright.

**8쪽 | 2 Authority**
> Nothing in this recommendation should be taken to contradict standards and guidelines that have been made mandatory and binding upon Federal agencies by the Secretary of Commerce under his statutory authority. Nor should this recommendation be interpreted as altering or superseding the existing authorities of the Secretary of Commerce, the Director of the Office of Management and Budget, or any other Federal official.

**8쪽 | 2 Authority**
> Conformance testing for implementations of the modes of operation that are specified in this recommendation will be conducted within the framework of the Cryptographic Module Validation Program (CMVP), a joint effort of the NIST and the Communications Security Establishment of the Government of Canada. An implementation of a mode of operation must adhere to the requirements in this recommendation in order to be validated under the CMVP.

**8쪽 | 3 Introduction**
> This recommendation specifies five confidentiality modes of operation for symmetric key block cipher algorithms, such as the algorithm specified in FIPS Pub. 197, the Advanced Encryption Standard (AES) [2]. The modes may be used in conjunction with any symmetric key block cipher algorithm that is approved by a Federal Information Processing Standard (FIPS).  The five modes—the Electronic Codebook (ECB), Cipher Block Chaining (CBC), Cipher Feedback (CFB), Output Feedback (OFB), and Counter (CTR) modes—can provide data confidentiality.

**8쪽 | 3 Introduction**
> Two FIPS publications already approve confidentiality modes of operation for two particular block cipher algorithms.  FIPS Pub. 81 [4] specifies the ECB, CBC, CFB, and OFB modes of the Data Encryption Standard (DES). FIPS Pub. 46-3 [3] approves the seven modes that are specified in ANSI X9.52 [1].  Four of these modes are equivalent to the ECB, CBC, CFB, and OFB modes with the Triple DES algorithm (TDEA) as the underlying block cipher; the other

**9쪽 | 3 Introduction**
> three modes in ANSI X9.52 are variants of the CBC, CFB, and OFB modes of Triple DES that use interleaving or pipelining.

**9쪽 | 3 Introduction**
> Thus, there are three new elements in this recommendation:  1) the extension of the four confidentiality modes in FIPS Pub 81 for use with any FIPS-approved block cipher; 2) the revision of the requirements for these modes; and 3) the specification of an additional confidentiality mode, the CTR mode, for use with any FIPS-approved block cipher.

**12쪽 | 4 Definitions, Abbreviations, and Symbols > 4.2 Symbols > 4.2.1 Variables**
> b The block size, in bits.

**12쪽 | 4 Definitions, Abbreviations, and Symbols > 4.2 Symbols > 4.2.1 Variables**
> j The index to a sequence of data blocks or data segments ordered from left to right.

**12쪽 | 4 Definitions, Abbreviations, and Symbols > 4.2 Symbols > 4.2.1 Variables**
> n The number of data blocks or data segments in the plaintext.

**12쪽 | 4 Definitions, Abbreviations, and Symbols > 4.2 Symbols > 4.2.1 Variables**
> s The number of bits in a data segment.
