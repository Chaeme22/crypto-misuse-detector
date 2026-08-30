// 래퍼만 있는 파일. 값이 이 파일에 없으므로 여기만 보면 판정할 수 없다.
package fixtures;

import javax.crypto.Cipher;

public class CryptoWrapper {

    // 기대: 호출 지점 색인이 있으면 CallerA가 넘긴 값으로 판정된다.
    public static Cipher build(String transformation) throws Exception {
        return Cipher.getInstance(transformation);
    }

    // 기대: 아무도 부르지 않으므로 값을 못 찾는다. 확인 필요로 남아야 한다.
    public static Cipher buildUnused(String transformation) throws Exception {
        return Cipher.getInstance(transformation);
    }
}
