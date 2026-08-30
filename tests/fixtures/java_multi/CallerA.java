// 다른 파일에서 래퍼를 부른다. 여기 있는 값이 위 파일의 판정 근거다.
package fixtures;

public class CallerA {

    public void run() throws Exception {
        CryptoWrapper.build("AES/ECB/PKCS5Padding");
    }
}
