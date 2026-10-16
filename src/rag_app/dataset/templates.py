"""
정답을 알고 만드는 Java 합성 코드.

학습 라벨은 사람이 검토하기 전까지 믿을 수 없다. 그래도 합성 코드는 만들 때 정답을 정해
두므로 검토가 쉽다. 오용 유형마다 값을 정하고, 그 값이 코드 어디에 놓이는지(그 자리,
지역 변수, 필드, 같은 파일의 호출자, 밖에서 오는 인자)를 바꿔 같은 문제를 여러 모양으로 만든다.
값이 놓인 자리가 다르면 판정에 필요한 문맥의 깊이도 달라진다.

판정 기준은 dataset/misuse_taxonomy.json의 조건을 따른다. 여기서 정하는 것은 코드와
"이 코드를 다 보면 무엇이 정답인가"뿐이다. 문맥을 줄였을 때의 정답은 build.py가 탐지기를
다시 돌려 정한다.

값 하나가 lineage 하나다. 같은 값의 변형(자리·이름·경로)은 학습·검증·평가 중 한 곳에만
들어가야 외운 값을 맞힌 것으로 세지 않는다. 그래서 유형마다 값을 다섯 개 둔다(학습 3,
검증 1, 평가 1).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import product

# 대상 줄 표시. 코드를 쓰기 전에 지운다.
MARK = "// <<"


@dataclass(frozen=True)
class Value:
    """값 하나와 그 값을 다 보았을 때의 정답."""
    expr: str                 # Java 식
    decision: str             # violation | clean | undetermined
    role: str = "crypto_operation"
    note: str = ""            # 왜 그 정답인지. 사람 검토와 정답 근거 문장에 쓴다


@dataclass(frozen=True)
class Family:
    """오용 유형 하나의 코드 틀."""
    rule_id: str
    misuse_id: str
    imports: tuple[str, ...]
    java_type: str            # 값의 타입. 지역 변수·필드·인자 선언에 쓴다
    sink: str                 # `{v}` 자리에 값이 들어가는 문장. 대상 줄이다
    values: tuple[Value, ...]
    setup: tuple[str, ...] = ()   # 대상 줄 앞에 필요한 문장
    after: tuple[str, ...] = ()   # 대상 줄 뒤 문장. 값이 무엇에 쓰이는지 보인다
    placements: tuple[str, ...] = ("inline", "local", "field", "caller", "parameter")


@dataclass(frozen=True)
class Sample:
    """합성 샘플 하나. 코드와 대상 줄과 전체 문맥에서의 정답."""
    template_id: str
    lineage_group: str
    family: Family
    value: Value
    placement: str
    path: str
    code: str
    target_line: int
    decision: str
    role: str
    names: dict = field(default_factory=dict)


def _v(expr: str, note: str) -> Value:
    return Value(expr, "violation", note=note)


FAMILIES: tuple[Family, ...] = (
    Family("CRYPTO-HASH-WEAK", "MISUSE-HASH-WEAK", ("java.security.MessageDigest",),
           "String", "MessageDigest md = MessageDigest.getInstance({v});",
           (_v('"MD5"', "MD5는 기준표에 없다"),
            _v('"SHA-1"', "SHA-1은 서명용 기준표에 없다"),
            _v('"MD2"', "MD2는 기준표에 없다"),
            _v('"SHA1"', "SHA-1은 서명용 기준표에 없다"),
            _v('"MD4"', "MD4는 기준표에 없다")),
           after=("byte[] digest = md.digest(password.getBytes());",),
           setup=('String password = System.getProperty("user.password", "");',)),
    Family("CRYPTO-MODE-ECB", "MISUSE-MODE-ECB", ("javax.crypto.Cipher",),
           "String", "Cipher cipher = Cipher.getInstance({v});",
           (_v('"AES/ECB/PKCS5Padding"', "ECB 운영모드는 같은 평문 블록이 같은 암호문이 된다"),
            _v('"ARIA/ECB/NoPadding"', "국산 블록암호라도 ECB 운영모드면 위반"),
            _v('"SEED/ECB/PKCS5Padding"', "ECB 운영모드"),
            _v('"AES/ECB/NoPadding"', "ECB 운영모드"),
            _v('"LEA/ECB/PKCS5Padding"', "ECB 운영모드"))),
    Family("CRYPTO-CIPHER-OBSOLETE", "MISUSE-CIPHER-OBSOLETE", ("javax.crypto.Cipher",),
           "String", "Cipher cipher = Cipher.getInstance({v});",
           (_v('"DES/CBC/PKCS5Padding"', "DES는 기준표에 없다"),
            _v('"RC4"', "RC4는 기준표에 없다"),
            _v('"Blowfish/CBC/PKCS5Padding"', "Blowfish는 기준표에 없다"),
            _v('"RC2/CBC/PKCS5Padding"', "RC2는 기준표에 없다"),
            _v('"DES"', "DES는 기준표에 없다"))),
    Family("CRYPTO-KEYSIZE-SHORT", "MISUSE-KEYSIZE-SHORT", ("java.security.KeyPairGenerator",),
           "int", "generator.initialize({v});",
           (_v("1024", "RSA 1024비트는 기준표의 최소 길이에 못 미친다"),
            _v("512", "RSA 512비트는 기준표의 최소 길이에 못 미친다"),
            _v("768", "RSA 768비트는 기준표의 최소 길이에 못 미친다"),
            _v("1536", "RSA 1536비트는 기준표의 최소 길이에 못 미친다"),
            _v("2047", "RSA 2047비트는 기준표의 최소 길이에 못 미친다")),
           setup=('KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");',)),
    Family("CRYPTO-RNG-INSECURE", "MISUSE-RNG-INSECURE", ("java.util.Random",),
           "Random", "Random rnd = {v};",
           (_v("new Random()", "java.util.Random 출력을 키 바이트로 쓴다"),
            _v("new Random(System.currentTimeMillis())", "java.util.Random 출력을 키 바이트로 쓴다"),
            _v("new Random(42L)", "java.util.Random 출력을 키 바이트로 쓴다"),
            _v("new java.util.Random()", "java.util.Random 출력을 키 바이트로 쓴다"),
            _v("new Random(7)", "java.util.Random 출력을 키 바이트로 쓴다")),
           after=("byte[] key = new byte[16];", "rnd.nextBytes(key);"),
           placements=("inline",)),
    Family("CRYPTO-SEED-PREDICTABLE", "MISUSE-SEED-PREDICTABLE", ("java.security.SecureRandom",),
           "long", "random.setSeed({v});",
           (_v("42L", "시드가 상수다"),
            _v("System.currentTimeMillis()", "현재 시각 시드는 예측할 수 있다"),
            _v("System.nanoTime()", "현재 시각 시드는 예측할 수 있다"),
            _v("12345L", "시드가 상수다"),
            _v("0L", "시드가 상수다")),
           setup=("SecureRandom random = new SecureRandom();",)),
    Family("CRYPTO-KEY-HARDCODED", "MISUSE-KEY-HARDCODED", ("javax.crypto.spec.SecretKeySpec",),
           "byte[]", 'SecretKeySpec key = new SecretKeySpec({v}, "AES");',
           (_v('"0123456789abcdef".getBytes()', "키가 문자열 상수다"),
            _v("new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}", "키가 상수 배열이다"),
            _v('"my-very-secret-key-1234".getBytes("UTF-8")', "키가 문자열 상수다"),
            _v("new byte[16]", "키가 0으로 채운 배열이다"),
            _v('"k3y-material-0000".getBytes()', "키가 문자열 상수다"))),
    Family("CRYPTO-IV-STATIC", "MISUSE-IV-STATIC", ("javax.crypto.spec.IvParameterSpec",),
           "byte[]", "IvParameterSpec iv = new IvParameterSpec({v});",
           (_v("new byte[16]", "채우지 않은 0 IV다"),
            _v('"fedcba9876543210".getBytes()', "IV가 문자열 상수다"),
            _v("new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}", "IV가 상수 배열이다"),
            _v('"1234567812345678".getBytes("UTF-8")', "IV가 문자열 상수다"),
            _v("new byte[12]", "채우지 않은 0 IV다"))),
    Family("CRYPTO-PASSWORD-HARDCODED", "MISUSE-PASSWORD-HARDCODED", ("javax.crypto.spec.PBEKeySpec",),
           "char[]", "PBEKeySpec spec = new PBEKeySpec({v});",
           (_v('"changeit".toCharArray()', "비밀번호가 상수다"),
            _v('"s3cr3t-P@ss".toCharArray()', "비밀번호가 상수다"),
            _v("new char[]{'p', 'a', 's', 's'}", "비밀번호가 상수 배열이다"),
            _v('"admin".toCharArray()', "비밀번호가 상수다"),
            _v('"password123".toCharArray()', "비밀번호가 상수다"))),
    Family("CRYPTO-SALT-STATIC", "MISUSE-SALT-STATIC", ("javax.crypto.spec.PBEParameterSpec",),
           "byte[]", "PBEParameterSpec params = new PBEParameterSpec({v}, 10000);",
           (_v("new byte[]{(byte) 0xa2, (byte) 0x15, (byte) 0x7c, (byte) 0x01}", "솔트가 상수 배열이다"),
            _v('"saltsalt".getBytes()', "솔트가 문자열 상수다"),
            _v("new byte[8]", "0으로 채운 솔트다"),
            _v('"0000000000000000".getBytes("UTF-8")', "솔트가 문자열 상수다"),
            _v("new byte[]{1, 2, 3, 4, 5, 6, 7, 8}", "솔트가 상수 배열이다"))),
    Family("CRYPTO-KDF-WEAK", "MISUSE-KDF-WEAK",
           ("java.security.SecureRandom", "javax.crypto.spec.PBEParameterSpec"),
           "int", "PBEParameterSpec params = new PBEParameterSpec(salt, {v});",
           (_v("100", "반복 횟수 100회가 최소 1,000회에 못 미친다"),
            _v("20", "반복 횟수 20회가 최소 1,000회에 못 미친다"),
            _v("1", "반복 횟수 1회가 최소 1,000회에 못 미친다"),
            _v("500", "반복 횟수 500회가 최소 1,000회에 못 미친다"),
            _v("999", "반복 횟수 999회가 최소 1,000회에 못 미친다")),
           setup=("byte[] salt = new byte[16];", "new SecureRandom().nextBytes(salt);")),
    # --- v3 (2026-10-08): 추출기 4·7차에 더한 모양. 시험 세트(국산 시험용 코퍼스)의 값은 쓰지 않는다 ---
    Family("CRYPTO-HASH-WEAK", "MISUSE-HASH-WEAK", ("java.security.Signature",),
           "String", "Signature signer = Signature.getInstance({v});",
           (_v('"SHA1withRSA"', "서명 해시 SHA-1은 서명용 기준표에 없다"),
            _v('"MD5withRSA"', "서명 해시 MD5는 기준표에 없다"),
            _v('"SHA1withECDSA"', "서명 해시 SHA-1은 서명용 기준표에 없다"),
            _v('"MD2withRSA"', "서명 해시 MD2는 기준표에 없다"),
            _v('"SHA1withDSA"', "서명 해시 SHA-1은 서명용 기준표에 없다")),
           after=("signer.initSign(privateKey);", "signer.update(document);",
                  "byte[] signature = signer.sign();")),
    Family("CRYPTO-KEY-HARDCODED", "MISUSE-KEY-HARDCODED", (),
           "byte[]", "byte[] sealed = KISA_SEED_CBC.SEED_CBC_Encrypt({v}, iv, data, 0, data.length);",
           (_v('"seedKeyForOrders".getBytes()', "KISA SEED 키가 문자열 상수다"),
            _v("new byte[]{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x08, 0x19, 0x2a, 0x3b, 0x4c, "
               "0x5d, 0x6e, 0x7f, 0x01}", "KISA SEED 키가 상수 배열이다"),
            _v('"k1s4-s33d-k3y-01".getBytes(StandardCharsets.UTF_8)', "KISA SEED 키가 문자열 상수다"),
            _v("new byte[16]", "KISA SEED 키가 0으로 채운 배열이다"),
            _v('"partnerSeedKey!!".getBytes()', "KISA SEED 키가 문자열 상수다")),
           setup=("byte[] iv = new byte[16];", "new java.security.SecureRandom().nextBytes(iv);",
                  "byte[] data = message.getBytes();")),
    Family("CRYPTO-IV-STATIC", "MISUSE-IV-STATIC", (),
           "byte[]", "byte[] sealed = KISA_SEED_CBC.SEED_CBC_Encrypt(key, {v}, data, 0, data.length);",
           (_v('"abcdefghabcdefgh".getBytes()', "KISA SEED IV가 문자열 상수다"),
            _v("new byte[16]", "채우지 않은 0 IV다"),
            _v("new byte[]{0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, "
               "0x03, 0x02, 0x01, 0x00}", "KISA SEED IV가 상수 배열이다"),
            _v('"0000000000000000".getBytes()', "KISA SEED IV가 문자열 상수다"),
            _v('"ivForSeedCipher!".getBytes(StandardCharsets.UTF_8)', "KISA SEED IV가 문자열 상수다")),
           setup=('byte[] key = System.getenv("SEED_KEY").getBytes();',
                  "byte[] data = message.getBytes();")),
)

# 이름 목록에 알고리즘 이름이 있을 뿐 쓰지 않는 코드. 규칙이 걸리지만 정답은 정상이다.
NAME_LIST_SNIPPETS: tuple[tuple[str, str, str], ...] = (
    ("CRYPTO-HASH-WEAK", "MISUSE-HASH-WEAK",
     'boolean weak = java.util.Arrays.asList("MD5", "SHA-1").contains(name);'),
    ("CRYPTO-HASH-WEAK", "MISUSE-HASH-WEAK",
     'if (name.equals("MD5")) { throw new IllegalArgumentException("weak hash"); }'),
    ("CRYPTO-CIPHER-OBSOLETE", "MISUSE-CIPHER-OBSOLETE",
     'boolean banned = java.util.Set.of("DES", "RC4").contains(name);'),
    ("CRYPTO-HASH-WEAK", "MISUSE-HASH-WEAK",
     'boolean legacy = "SHA1".equalsIgnoreCase(name);'),
    ("CRYPTO-CIPHER-OBSOLETE", "MISUSE-CIPHER-OBSOLETE",
     'java.util.List<String> deny = java.util.List.of("RC4", "Blowfish");'),
)

# 같은 API를 다른 목적으로 쓰는 대조 쌍. 호출만 보면 똑같고, 결과가 어디에 쓰이는지가 판정을 가른다.
# 실제 코드(ApacheCryptoAPI-Bench)에서 파일럿 모델이 이 구분을 못 해 정적 판정을 그대로 따라 했다.
# (규칙, 오용, import, 문장들 — `<<`가 대상 줄, 정답, 역할, 설명). 문장 순번이 lineage다.
_RNG = ("CRYPTO-RNG-INSECURE", "MISUSE-RNG-INSECURE", ("java.util.Random",))
_MD5 = ("CRYPTO-HASH-WEAK", "MISUSE-HASH-WEAK", ("java.security.MessageDigest",))
_DIGEST = ("CRYPTO-HASH-WEAK", "MISUSE-HASH-WEAK", ("org.apache.commons.codec.digest.DigestUtils",))
CONTEXT_SNIPPETS: tuple[tuple, ...] = (
    # --- 난수: 보안 용도 → 위반
    (*_RNG, ["Random rnd = new Random(); <<", "StringBuilder token = new StringBuilder();",
             "for (int i = 0; i < 32; i++) { token.append(Integer.toHexString(rnd.nextInt(16))); }",
             "session.setAttribute(\"csrfToken\", token.toString());"],
     "violation", "crypto_operation", "java.util.Random 출력을 CSRF 토큰으로 쓴다"),
    (*_RNG, ["Random random = new Random(); <<",
             "int code = 100000 + random.nextInt(900000);",
             "mailer.send(user.getEmail(), \"password reset code: \" + code);",
             "resetCodes.put(user.getId(), code);"],
     "violation", "crypto_operation", "java.util.Random 출력을 비밀번호 재설정 코드로 쓴다"),
    (*_RNG, ["Random r = new Random(); <<", "byte[] apiKey = new byte[24];", "r.nextBytes(apiKey);",
             "store.saveApiKey(clientId, java.util.Base64.getEncoder().encodeToString(apiKey));"],
     "violation", "crypto_operation", "java.util.Random 출력을 API 키로 쓴다"),
    (*_RNG, ["Random otp = new Random(System.nanoTime()); <<",
             "String pin = String.format(\"%06d\", otp.nextInt(1000000));",
             "sms.send(phone, pin);", "pending.put(phone, pin);"],
     "violation", "crypto_operation", "java.util.Random 출력을 일회용 인증 번호로 쓴다"),
    (*_RNG, ["Random saltSource = new Random(); <<", "byte[] salt = new byte[16];",
             "saltSource.nextBytes(salt);", "user.setPasswordSalt(salt);",
             "user.setPasswordHash(hasher.hash(password, salt));"],
     "violation", "crypto_operation", "java.util.Random 출력을 비밀번호 솔트로 쓴다"),
    # --- 난수: 보안과 무관 → 정상
    (*_RNG, ["Random rnd = new Random(); <<", "java.util.List<String> order = new java.util.ArrayList<>(items);",
             "java.util.Collections.shuffle(order, rnd);", "view.render(order);"],
     "clean", "non_security", "화면에 보여 줄 목록 순서를 섞는 데"),
    (*_RNG, ["Random jitter = new Random(); <<", "long delay = baseDelayMs + jitter.nextInt(250);",
             "LOG.debug(\"retrying in {} ms\", delay);", "Thread.sleep(delay);"],
     "clean", "non_security", "재시도 간격에 흔들림을 주는 데"),
    (*_RNG, ["Random sampler = new Random(seed); <<",
             "for (Record rec : records) { if (sampler.nextDouble() < 0.01) { sample.add(rec); } }",
             "metrics.report(sample);"],
     "clean", "non_security", "통계용 표본을 뽑는 데"),
    (*_RNG, ["Random random = new Random(); <<",
             "java.awt.Color color = new java.awt.Color(random.nextInt(256), random.nextInt(256), random.nextInt(256));",
             "chart.setSeriesColor(series, color);"],
     "clean", "non_security", "차트 색상을 고르는 데"),
    (*_RNG, ["Random pick = new Random(); <<",
             "int index = pick.nextInt(backends.size());",
             "Backend target = backends.get(index);", "return target.forward(request);"],
     "clean", "non_security", "부하 분산할 서버를 고르는 데"),
    # --- 해시: 보안 용도 → 위반
    (*_MD5, ["MessageDigest md = MessageDigest.getInstance(\"MD5\"); <<",
             "byte[] hashed = md.digest(password.getBytes(\"UTF-8\"));",
             "user.setPasswordHash(java.util.Base64.getEncoder().encodeToString(hashed));",
             "repository.save(user);"],
     "violation", "crypto_operation", "MD5로 비밀번호를 저장한다"),
    (*_MD5, ["MessageDigest sha = MessageDigest.getInstance(\"SHA-1\"); <<",
             "byte[] sig = sha.digest((payload + SHARED_SECRET).getBytes(\"UTF-8\"));",
             "response.setHeader(\"X-Signature\", hex(sig));"],
     "violation", "crypto_operation", "SHA-1로 요청 서명을 만든다"),
    (*_MD5, ["MessageDigest md = MessageDigest.getInstance(\"MD5\"); <<",
             "String expected = hex(md.digest((user + \":\" + password).getBytes()));",
             "if (!expected.equals(storedHash)) { throw new SecurityException(\"login failed\"); }"],
     "violation", "crypto_operation", "MD5로 로그인 비밀번호를 검증한다"),
    (*_MD5, ["MessageDigest digest = MessageDigest.getInstance(\"SHA1\"); <<",
             "digest.update(secretKey);", "digest.update(message);",
             "byte[] tag = digest.digest();", "if (!java.security.MessageDigest.isEqual(tag, received)) { reject(); }"],
     "violation", "crypto_operation", "SHA-1로 메시지 인증값을 만든다"),
    (*_MD5, ["MessageDigest md5 = MessageDigest.getInstance(\"MD5\"); <<",
             "String token = hex(md5.digest((userId + System.currentTimeMillis()).getBytes()));",
             "sessions.put(token, userId);", "return token;"],
     "violation", "crypto_operation", "MD5로 세션 토큰을 만든다"),
    # --- 해시: 보안과 무관 → 정상
    (*_MD5, ["MessageDigest md = MessageDigest.getInstance(\"MD5\"); <<",
             "String cacheKey = hex(md.digest(query.getBytes(\"UTF-8\")));",
             "Object hit = cache.get(cacheKey);", "if (hit != null) { return hit; }"],
     "clean", "non_security", "쿼리 결과 캐시 키를 만드는 데"),
    (*_MD5, ["MessageDigest md = MessageDigest.getInstance(\"MD5\"); <<",
             "String fingerprint = hex(md.digest(java.nio.file.Files.readAllBytes(path)));",
             "if (!seen.add(fingerprint)) { LOG.info(\"duplicate file skipped: {}\", path); }"],
     "clean", "non_security", "중복 파일을 걸러 내는 데"),
    (*_MD5, ["MessageDigest sha = MessageDigest.getInstance(\"SHA-1\"); <<",
             "String etag = '\"' + hex(sha.digest(body)) + '\"';",
             "response.setHeader(\"ETag\", etag);"],
     "clean", "non_security", "HTTP ETag를 만드는 데"),
    (*_MD5, ["MessageDigest md = MessageDigest.getInstance(\"MD5\"); <<",
             "byte[] h = md.digest(key.getBytes());",
             "int shard = (h[0] & 0xff) % shardCount;", "return shards.get(shard);"],
     "clean", "non_security", "데이터를 샤드에 나누는 데"),
    (*_MD5, ["MessageDigest md = MessageDigest.getInstance(\"MD5\"); <<",
             "String correlationId = hex(md.digest((host + threadName).getBytes())).substring(0, 8);",
             "org.slf4j.MDC.put(\"cid\", correlationId);"],
     "clean", "non_security", "로그 상관 ID를 만드는 데"),
    # --- v3: 메서드 이름이 알고리즘인 래퍼(DigestUtils). 실제 코드에서 보안과 무관한 쓰임이 특히 많다 ---
    # 보안 용도 → 위반
    (*_DIGEST, ["String hashed = DigestUtils.md5Hex(rawPassword); <<",
                "member.setPassword(hashed);", "memberRepository.save(member);"],
     "violation", "crypto_operation", "MD5로 회원 비밀번호를 저장한다"),
    (*_DIGEST, ["String sign = DigestUtils.sha1Hex(sortedParams + \"&key=\" + appSecret); <<",
                "request.addHeader(\"sign\", sign);", "return client.execute(request);"],
     "violation", "crypto_operation", "SHA-1로 결제 API 요청 서명을 만든다"),
    (*_DIGEST, ["String expected = DigestUtils.md5Hex(token + serverSalt); <<",
                "if (!expected.equals(presented)) { throw new SecurityException(\"invalid token\"); }"],
     "violation", "crypto_operation", "MD5로 인증 토큰을 검증한다"),
    # 보안과 무관 → 정상
    (*_DIGEST, ["String cacheKey = DigestUtils.md5Hex(sql + java.util.Arrays.toString(args)); <<",
                "Object cached = queryCache.get(cacheKey);", "if (cached != null) { return cached; }"],
     "clean", "non_security", "SQL 결과 캐시 키를 만드는 데"),
    (*_DIGEST, ["String checksum = DigestUtils.md5Hex(uploaded.getInputStream()); <<",
                "if (fileRepository.existsByChecksum(checksum)) { return fileRepository.findByChecksum(checksum); }"],
     "clean", "non_security", "같은 업로드 파일을 다시 저장하지 않으려고"),
    (*_DIGEST, ["String version = DigestUtils.sha1Hex(content).substring(0, 10); <<",
                "response.setHeader(\"ETag\", version);", "return ResponseEntity.ok(content);"],
     "clean", "non_security", "정적 자원의 ETag를 만드는 데"),
)

NAMES = (
    {"cls": "CryptoService", "method": "protect", "var": "value", "field": "DEFAULT_VALUE",
     "helper": "apply", "param": "input"},
    {"cls": "TokenUtil", "method": "seal", "var": "material", "field": "SECRET",
     "helper": "build", "param": "given"},
)

PATHS = (
    ("main", "src/main/java/com/example/{cls}.java"),
    ("test", "src/test/java/com/example/{cls}Test.java"),
)


def _class(imports, names, fields, methods, test: bool) -> str:
    head = "".join(f"import {imp};\n" for imp in sorted(set(imports)))
    cls = names["cls"] + ("Test" if test else "")
    body = "".join(f"    {line}\n" for line in fields)
    if fields:
        body += "\n"
    body += "\n".join(methods)
    return f"package com.example;\n\n{head}\npublic class {cls} {{\n{body}}}\n"


def _method(name: str, params: str, statements: list[str]) -> str:
    lines = "".join(f"        {s}\n" for s in statements)
    return f"    public void {name}({params}) throws Exception {{\n{lines}    }}\n"


def _render(family: Family, value: Value, placement: str, names: dict,
            test: bool) -> tuple[str, str, str]:
    """(코드, 정답 판정, 정답 역할)."""
    setup, after = list(family.setup), list(family.after)
    fields: list[str] = []
    methods: list[str] = []
    decision, role = value.decision, value.role

    def target(v: str) -> list[str]:
        return [family.sink.format(v=v) + f" {MARK}"] + after

    if placement == "inline":
        methods.append(_method(names["method"], "", setup + target(value.expr)))
    elif placement == "local":
        methods.append(_method(names["method"], "", setup + [
            f"{family.java_type} {names['var']} = {value.expr};"] + target(names["var"])))
    elif placement == "field":
        fields.append(f"private static final {family.java_type} {names['field']} = {value.expr};")
        methods.append(_method(names["method"], "", setup + target(names["field"])))
    elif placement == "caller":
        methods.append(_method(names["method"], "", [f"{names['helper']}({value.expr});"]))
        methods.append(_method(names["helper"], f"{family.java_type} {names['param']}",
                               setup + target(names["param"])))
    elif placement == "parameter":
        # 값이 이 파일 밖에서 온다. 무엇이 들어오는지 이 코드로는 알 수 없다.
        methods.append(_method(names["helper"], f"{family.java_type} {names['param']}",
                               setup + target(names["param"])))
        decision = "undetermined"
    else:
        raise ValueError(placement)

    if test:
        # 테스트 소스의 고정값은 운영 취약점이 아니다.
        role = "test_fixture"
        decision = "clean" if decision == "violation" else decision
    return _class(family.imports, names, fields, methods, test), decision, role


def _locate(code: str) -> tuple[str, int]:
    lines = code.splitlines()
    for number, line in enumerate(lines, 1):
        if MARK in line:
            lines[number - 1] = line.replace(f" {MARK}", "")
            return "\n".join(lines) + "\n", number
    raise ValueError("대상 줄 표시가 없다")


def generate() -> list[Sample]:
    """모든 합성 샘플. 순서와 내용이 늘 같다."""
    samples: list[Sample] = []
    for family in FAMILIES:
        for vi, value in enumerate(family.values):
            for placement, (ni, names), (kind, path) in product(
                    family.placements, enumerate(NAMES), PATHS):
                test = kind == "test"
                if test and placement != "inline":
                    continue  # 테스트 경로는 한 가지 모양이면 충분하다
                code, decision, role = _render(family, value, placement, names, test)
                code, line = _locate(code)
                samples.append(Sample(
                    template_id=f"{family.rule_id}-V{vi}-{placement}-N{ni}-{kind}",
                    lineage_group=f"LG-{family.misuse_id.removeprefix('MISUSE-')}-V{vi}",
                    family=family, value=value, placement=placement,
                    path=path.format(cls=names["cls"]), code=code, target_line=line,
                    decision=decision, role=role, names=names))

    counters: dict[tuple[str, str], int] = {}
    for rule_id, misuse_id, imports, statements, decision, role, note in CONTEXT_SNIPPETS:
        group = (rule_id, decision)
        vi = counters.get(group, 0)
        counters[group] = vi + 1
        kind = "SEC" if decision == "violation" else "NONSEC"
        short = rule_id.removeprefix("CRYPTO-")
        for ni, names in enumerate(NAMES):
            family = Family(rule_id, misuse_id, imports, "", "", ())
            value = Value("", decision, role=role, note=note)
            body = [s.replace(" <<", f" {MARK}") for s in statements]
            code = _class(imports, names, [], [_method(names["method"], "", body)], False)
            code, line = _locate(code)
            samples.append(Sample(
                template_id=f"{rule_id}-CTX{kind}{vi}-N{ni}-main",
                lineage_group=f"LG-CTX-{short}-{kind}-V{vi}", family=family, value=value,
                placement="context", path=f"src/main/java/com/example/{names['cls']}.java",
                code=code, target_line=line, decision=decision, role=role, names=names))

    for si, (rule_id, misuse_id, statement) in enumerate(NAME_LIST_SNIPPETS):
        for ni, names in enumerate(NAMES):
            family = Family(rule_id, misuse_id, (), "String", statement, ())
            value = Value("", "clean", role="name_list", note="이름만 비교할 뿐 쓰지 않는다")
            code = _class((), names, [], [_method(
                "isWeak" if ni == 0 else "check", "String name",
                [statement + f" {MARK}"])], False)
            code, line = _locate(code)
            samples.append(Sample(
                template_id=f"{rule_id}-NAMES{si}-N{ni}-main",
                lineage_group=f"LG-NAMELIST-V{si}", family=family, value=value,
                placement="name_list", path=f"src/main/java/com/example/{names['cls']}.java",
                code=code, target_line=line, decision="clean", role="name_list",
                names=names))
    return samples
