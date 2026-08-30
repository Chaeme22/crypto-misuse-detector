// 추출기 검증용 표본. 각 줄의 정답을 주석으로 적어 둔다.
// 위반으로 잡혀야 하는 줄과 잡히면 안 되는 줄을 함께 둔다.
package fixtures;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoSamples {

    // 기대: CRYPTO-HASH-WEAK (MD5 리터럴)
    byte[] weakDigest(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }

    // 기대: 잡히지 않음 (SHA-256은 권고 목록에 있다)
    byte[] strongDigest(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }

    // 기대: CRYPTO-MODE-ECB (변환 스펙에 ECB)
    Cipher ecbCipher() throws Exception {
        return Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    // 기대: 잡히지 않음 (GCM은 권고 운영모드)
    Cipher gcmCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    // 기대: CRYPTO-CIPHER-OBSOLETE (DESede)
    Cipher tripleDes() throws Exception {
        return Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }

    // 기대: 인자가 변수라 미결. provenance slice 대상으로 표시되어야 한다.
    Cipher fromConfig(String transformation) throws Exception {
        return Cipher.getInstance(transformation);
    }

    // 기대: CRYPTO-RNG-INSECURE (java.util.Random)
    byte[] weakKey() {
        Random rng = new Random();
        byte[] key = new byte[16];
        rng.nextBytes(key);
        return key;
    }

    // 기대: 잡히지 않음 (SecureRandom)
    byte[] strongKey() {
        SecureRandom rng = new SecureRandom();
        byte[] key = new byte[16];
        rng.nextBytes(key);
        return key;
    }

    // 기대: CRYPTO-KEY-HARDCODED (소스에 박힌 키)
    SecretKeySpec hardcodedKey() {
        byte[] raw = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
        return new SecretKeySpec(raw, "AES");
    }

    // 기대: CRYPTO-KEY-HARDCODED (고정 IV)
    IvParameterSpec fixedIv() {
        return new IvParameterSpec(new byte[16]);
    }

    // 기대: CRYPTO-KEYSIZE-SHORT (RSA 1024). 키 길이가 호출과 다른 줄에 있다.
    KeyPairGenerator shortRsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        return generator;
    }

    // 기대: 잡히지 않음 (RSA 2048)
    KeyPairGenerator okRsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator;
    }

    // 기대: CRYPTO-MODE-ECB. 값이 지역 변수에 있어 따라가면 찾을 수 있다.
    Cipher ecbViaLocal() throws Exception {
        String transformation = "AES/ECB/NoPadding";
        return Cipher.getInstance(transformation);
    }

    // 기대: 잡히지 않음. 따라간 값이 안전한 운영모드다.
    Cipher gcmViaLocal() throws Exception {
        String transformation = "AES/GCM/NoPadding";
        return Cipher.getInstance(transformation);
    }

    // 기대: CRYPTO-MODE-ECB. 같은 파일에서 부르는 자리가 넘긴 값을 따라간다.
    Cipher callerSupplied() throws Exception {
        return fromConfig("AES/ECB/PKCS5Padding");
    }

    // 기대: 잡히지 않음. 알고리즘 이름 목록일 뿐이다.
    static final String[] KNOWN = {"MD5", "SHA-1", "DESede", "AES", "SEED", "ARIA"};

    // 표 기준을 만족하는 공개키. 표 대조로 닫혀야 하고 보고서에 나오지 않아야 한다.
    public KeyPair strongRsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(4096);
        return generator.generateKeyPair();
    }
}
