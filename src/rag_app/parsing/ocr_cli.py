"""
Tesseract CLI 호출기.

pytesseract는 같은 OS에 tesseract 바이너리가 있어야 하는데, 이 프로젝트 환경은
Windows 파이썬 + WSL tesseract 조합이라 바이너리를 직접 부를 수 없다. 그래서 CLI를
서브프로세스로 호출하고, 필요하면 `wsl --` 같은 실행 앞머리를 붙일 수 있게 한다.

실험으로 확인한 설정(벡터 아웃라인 PDF, 400 DPI 렌더링 기준):
  - psm 11(sparse text)이 표 셀에서 가장 정확했다. psm 7은 짧은 한글 라벨에서 실패했다.
  - `kor+eng`는 라틴 문자를, `kor`는 한글을 각각 더 정확히 읽는다. 서로 보완적이므로
    두 번 읽고 결과가 다르면 사람 검수 대상으로 표시한다. 임의로 한쪽을 고르지 않는다.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from ..observability.logging import get_logger
from .ocr_engine import OCRText

logger = get_logger(__name__)

DEFAULT_PSM = 11
DEFAULT_DPI = 400


def _to_wsl_path(path: Path) -> str:
    """C:\\a\\b -> /mnt/c/a/b"""
    s = str(path.resolve()).replace(os.sep, "/")
    if len(s) > 2 and s[1] == ":":
        return "/mnt/" + s[0].lower() + s[2:]
    return s


class TesseractCLI:
    """tesseract 실행 파일을 서브프로세스로 호출한다."""

    name = "tesseract"

    def __init__(self, command: list[str] | None = None, timeout: int = 60):
        # 기본: 로컬에 tesseract가 있으면 직접, 없으면 WSL 경유.
        if command:
            self.command = list(command)
        elif shutil.which("tesseract"):
            self.command = ["tesseract"]
        else:
            self.command = ["wsl", "--", "tesseract"]
        self.timeout = timeout
        self._via_wsl = self.command[:1] == ["wsl"]

    def available(self) -> bool:
        try:
            r = subprocess.run(self.command + ["--version"], capture_output=True,
                               text=True, timeout=10)
            return r.returncode == 0
        except Exception:
            return False

    def languages(self) -> set[str]:
        try:
            r = subprocess.run(self.command + ["--list-langs"], capture_output=True,
                               text=True, timeout=10)
            return {ln.strip() for ln in (r.stdout or "").splitlines()[1:] if ln.strip()}
        except Exception:
            return set()

    def _run(self, image: Path, lang: str, psm: int) -> str:
        arg = _to_wsl_path(image) if self._via_wsl else str(image)
        try:
            r = subprocess.run(
                self.command + [arg, "stdout", "-l", lang, "--psm", str(psm)],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            logger.warning("ocr_timeout", f"tesseract timed out on {image.name}")
            return ""
        return " ".join((r.stdout or "").split())

    def read_lines(self, image: Path, psm: int = 3, lang: str = "kor+eng") -> list[str]:
        """
        줄 구조를 유지한 채 읽는다.

        스캔본은 벡터 좌표가 없어 문단 경계를 미리 알 수 없다. 그래서 페이지를 통째로
        읽고 빈 줄을 문단 경계로 삼아야 하므로 줄바꿈을 보존한다.
        """
        arg = _to_wsl_path(image) if self._via_wsl else str(image)
        try:
            r = subprocess.run(
                self.command + [arg, "stdout", "-l", lang, "--psm", str(psm)],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            logger.warning("ocr_timeout", f"tesseract timed out on {image.name}")
            return []
        return [ln.rstrip() for ln in (r.stdout or "").splitlines()]

    def read(self, image: Path, psm: int = DEFAULT_PSM, dual_pass: bool = True) -> OCRText:
        """
        이미지를 읽는다.

        dual_pass가 참이면 `kor+eng`와 `eng`로 두 번 읽고 합친다. 한국어 모델을 넣으면
        라틴 글자를 한글 자모로 억지로 맞추려 해서 알고리즘명이 깨지고, 영어 모델만 쓰면
        한글이 통째로 깨진다. 실제 문서에서 `(SEED, HIGHT)`가 전자에서는 `(6660, 11611)`로,
        후자에서는 정확히 읽혔다.

        합치는 범위는 아는 암호 식별자로 제한한다. 위치를 맞춰 바꿔치기하되, 두 번째 판독이
        내놓은 토큰이 우리가 아는 이름일 때만 받아들인다. 모르는 토큰까지 손대면 읽지 않은
        내용을 지어내는 셈이 된다.
        """
        primary = self._run(image, "kor+eng", psm)
        if not dual_pass:
            return OCRText(text=primary)

        secondary = self._run(image, "eng", psm)
        if _normalized(primary) == _normalized(secondary):
            return OCRText(text=primary)

        merged, repaired = merge_latin_tokens(primary, secondary)
        return OCRText(
            text=merged,
            alternate=secondary,
            # 고친 자리도, 못 고치고 남은 차이도 사람이 확인해야 한다.
            needs_review=True,
            )


def _normalized(s: str) -> str:
    return "".join(s.split()).lower()


# 두 번째 판독에서 받아들일 암호 식별자. 이 목록에 있는 토큰만 바꿔치기한다.
CRYPTO_IDENTIFIERS = {
    "AES", "DES", "3DES", "TDEA", "3TDEA", "SEED", "ARIA", "LEA", "HIGHT",
    "SHA", "SHA1", "SHA2", "SHA3", "HAS", "HAS160", "MD5", "HMAC", "CMAC",
    "RSA", "DSA", "ECDSA", "KCDSA", "ECKCDSA", "DH", "ECDH", "MQV", "ECMQV",
    "ECC", "ECIES", "PSEC", "KEM", "OAEP", "PKCS", "PSS", "RNG", "RBG", "DRBG",
    "KS", "ISO", "IEC",
    "PRNG", "CTR", "CBC", "ECB", "CFB", "OFB", "GCM", "CCM", "CMVP", "KCMVP",
    "NIST", "KISA", "FIPS", "CRYPTREC", "ECRYPT", "TLS", "SSL", "IPSEC",
    "HTML5", "API", "URL", "HTTP", "HTTPS", "JSON", "XML", "SVG", "IV",
    "Camellia", "Serpent", "SKIPJACK", "EdDSA", "XMSS",
}
_IDENT_KEY = {re.sub(r"[^A-Za-z0-9]", "", name).upper(): name for name in CRYPTO_IDENTIFIERS}

# 라틴 식별자 모양: 영문으로 시작하고 영숫자와 하이픈/슬래시로 이어진다. AES-128, SHA-512/224.
_LATIN_IDENT = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:[-/][A-Za-z0-9]+)*$")
_LATIN_RUNS = re.compile(r"[A-Za-z][A-Za-z0-9]*(?:[-/][A-Za-z0-9]+)*")


def _is_known_identifier(token: str) -> bool:
    """토큰이 우리가 아는 암호 식별자인지. `AES-128`처럼 뒤에 숫자가 붙은 형태도 받는다."""
    core = token.strip(" ,.;:()[]{}")
    if not _LATIN_IDENT.match(core):
        return False
    head = re.split(r"[-/]", core)[0]
    return re.sub(r"[^A-Za-z0-9]", "", head).upper() in _IDENT_KEY


# 라틴 글자가 한글 모델에 눌려 깨진 자리. 숫자나 자모, 전각 문자가 뭉친 덩어리로 나타난다.
# 예: SEED -> 6660, HIGHT -> 11611, RNG -> 68ㅇ, HTML5 -> "11"/Ｌ5
_GARBLED_RUN = re.compile(r"[0-9A-Za-zＡ-Ｚａ-ｚ０-９ㄱ-ㆎ\"'`/‘’“”]{2,}")


def _is_garbled_run(s: str) -> bool:
    """한글 낱말도 아니고 멀쩡한 라틴 식별자도 아닌, 깨진 흔적으로 보이는 덩어리인지."""
    if re.search(r"[가-힣]", s):
        return False
    if _is_known_identifier(s):
        return False
    # 숫자나 자모가 섞여 있어야 깨진 것으로 본다. 순수 영단어는 건드리지 않는다.
    return bool(re.search(r"[0-9ㄱ-ㆎＡ-Ｚａ-ｚ０-９]", s))


def _is_latin_garble(token: str) -> bool:
    """
    한글 자리에 들어앉은 라틴 덩어리로 보이는지.

    관찰된 실패는 전부 대문자 덩어리다(`무결성을` → `PASS`, `방법들` → `SHS`). 그래서
    대문자만, 짧은 것만 본다. 아는 암호 식별자는 tesseract 쪽이 정확하므로 제외한다.
    """
    core = token.strip(" ,.;:()[]{}'\"")
    if not (2 <= len(core) <= 8):
        return False
    if not re.fullmatch(r"[A-Z]+", core):
        return False
    return not _is_known_identifier(core)


def merge_hangul_tokens(primary: str, secondary: str) -> tuple[str, int]:
    """
    한글 낱말이 라틴 대문자로 깨진 자리를 다른 엔진의 판독으로 갈아끼운다.

    tesseract 한국어 모델은 한글 낱말을 통째로 라틴 대문자로 바꿔 놓는 실패를 한다. 실제
    문서에서 `무결성을`이 `PASS`로, `방법들`이 `SHS`로 나왔다. 뜻이 뒤바뀌므로 그대로 둘
    수 없다.

    두 판독이 일치한 자리는 건드리지 않는다. `KS X ISO IEC`처럼 두 엔진이 똑같이 읽은
    영문 약어가 한글로 바뀌는 사고를 막는 장치다. 고친 줄은 사람이 확인해야 한다.

    Returns:
        (합친 문자열, 고친 자리 수)
    """
    from difflib import SequenceMatcher

    a, b = primary.split(), secondary.split()
    if not a or not b:
        return primary, 0

    repaired = 0
    out: list[str] = []
    for tag, i1, i2, j1, j2 in SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes():
        segment = a[i1:i2]
        if tag == "equal":
            out.extend(segment)
            continue

        hangul = [t for t in b[j1:j2] if re.search(r"[가-힣]", t)]
        for token in segment:
            if hangul and _is_latin_garble(token):
                out.append(hangul.pop(0))
                repaired += 1
            else:
                out.append(token)

    return " ".join(out), repaired


def merge_latin_tokens(primary: str, secondary: str,
                       allow_digits: bool = True) -> tuple[str, int]:
    """
    한국어 판독을 바탕으로 두되, 영어 판독이 살려낸 암호 식별자로 깨진 자리만 갈아끼운다.

    두 판독은 같은 이미지를 같은 순서로 읽으므로 순서가 대체로 맞물린다. 그래서 영어 쪽이
    내놓은 아는 식별자를 순서대로 꺼내, 한국어 쪽에서 깨진 것으로 보이는 덩어리에 차례로
    끼워 넣는다. 한글은 건드리지 않는다.

    바꿔치기는 아는 식별자에만 한다. 모르는 토큰까지 손대면 읽지 않은 내용을 지어내는 셈이
    되기 때문이다.

    Returns:
        (합친 문자열, 고친 자리 수)
    """
    from difflib import SequenceMatcher

    a = primary.split()
    b = secondary.split()
    if not a or not b:
        return primary, 0

    # 한국어 판독에 이미 살아 있는 식별자는 고칠 필요가 없다.
    already = {re.sub(r"[^A-Za-z0-9]", "", t).upper()
               for t in a if _is_known_identifier(t)}

    repaired = 0
    out: list[str] = []
    for tag, i1, i2, j1, j2 in SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes():
        segment = a[i1:i2]
        if tag == "equal":
            # 두 판독이 일치한 자리는 건드리지 않는다. `112 비트`의 112처럼 실제 숫자가
            # 알고리즘명으로 바뀌는 사고를 막는 핵심 장치다.
            out.extend(segment)
            continue

        # 토큰 안쪽까지 본다. 검출기 쪽 판독은 `난수발생기(RBG의`처럼 이름이 한글에 붙어
        # 나오므로 토큰 단위로만 보면 후보를 하나도 못 찾는다.
        pending = [name for t in b[j1:j2] for name in _LATIN_RUNS.findall(t)
                   if _is_known_identifier(name)]
        if not allow_digits:
            # 숫자를 못 믿는 판독(검출기 쪽 인식기는 1을 7로 읽는다)에서 온 후보는 이름만
            # 받는다. AES-792가 깨진 자리에 들어앉으면 키 길이가 조용히 바뀐다.
            pending = [t for t in pending if not re.search(r"\d", t)]
        pending = [t for t in pending
                   if re.sub(r"[^A-Za-z0-9]", "", t).upper() not in already]
        if not pending:
            out.extend(segment)
            continue

        # 상대 판독이 이 자리에 숫자를 갖고 있으면, 여기 있는 숫자는 값으로 본다. 실제로
        # `KS X ISO IEC 18031`의 18031이 DRBG로, `SP 800-90`의 800이 RBG로 바뀌었다.
        # 숫자가 이름으로 깨지는 경우(`SEED` → `6660`)는 상대 쪽에 숫자가 없다.
        counterpart_has_digits = bool(re.search(r"\d", " ".join(b[j1:j2])))

        def _swap(match: "re.Match") -> str:
            nonlocal repaired
            run = match.group(0)
            if not pending or not _is_garbled_run(run):
                return run
            if counterpart_has_digits and re.fullmatch(r"\d+", run):
                return run
            # 깨진 덩어리가 대체할 이름의 일부이면 손대지 않는다. `싸5-128`의 128을 보고
            # AES-128의 AES로 바꾸면 키 길이 숫자가 사라진다. 못 고치더라도 망가뜨리지 않는다.
            if run.upper() in pending[0].upper():
                return run
            repaired += 1
            return pending.pop(0)

        out.extend(_GARBLED_RUN.sub(_swap, token) for token in segment)

    return " ".join(out), repaired
