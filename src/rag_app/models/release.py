"""
배포용 판정 모델 — 자동 감지와 설치(`setup`).

도구는 `analyze` 하나로 쓴다. AI 판정은 코드 문맥을 봐야 하는 자리에만 쓰이고(분기는 파이프라인이 한다), 여기서는
**AI 판정 단계를 켤 수 있는지**만 정한다.

- 이 PC의 Ollama에 배포 모델(`RELEASE_MODEL`)이 있으면 켠다.
- 없으면 정적 판정으로 돌리고, 한 번만 `setup`을 실행하면 된다고 알려 준다.

배포 모델은 공개 기본 모델(`RELEASE_BASE`, Ollama 4비트판) 위에 우리가 학습한 LoRA 어댑터를 얹은 것이다. 기본 모델은
수 GB라 저장소에 넣지 못하고 `ollama pull`로 받는다. 어댑터는 GGUF로 변환해 저장소의 `adapters/`에 둔다(약 19MB).
변환 도구(llama.cpp)는 개발자 쪽에서만 필요하다(`tools/export_adapter.py`).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

RELEASE_MODEL = "crypto-verdict:qwen7b-v2"
RELEASE_BASE = "qwen2.5-coder:7b"
PROJECT_ROOT = Path(__file__).resolve().parents[3]
RELEASE_ADAPTER = PROJECT_ROOT / "adapters" / "qwen7b-v2"


@dataclass(frozen=True)
class VerdictMode:
    """이번 검사에서 판정을 어떻게 할지."""
    use_llm: bool
    backend: str = ""
    model: str = ""
    notice: str = ""          # 사용자에게 한 번 보여 줄 안내


def installed_models(host: str, timeout: float = 3.0) -> list[str] | None:
    """Ollama에 설치된 모델 이름. 서버에 닿지 않으면 None."""
    import requests
    try:
        response = requests.get(f"{host}/api/tags", timeout=timeout)
        response.raise_for_status()
        return [m["name"] for m in response.json().get("models", [])]
    except Exception:
        return None


def _has(installed: list[str], name: str) -> bool:
    return name in installed or f"{name}:latest" in installed


def resolve_mode(force_llm: bool, force_static: bool, installed: list[str] | None,
                 backend: str | None = None, model: str | None = None) -> VerdictMode:
    """
    판정 방식을 정한다. 순수 함수라 네트워크 없이 시험할 수 있다.

    - `--no-llm`: 정적 판정
    - `--llm`: AI 판정 강제. 백엔드·모델을 주지 않으면 배포 모델(Ollama)
    - 아무것도 안 주면: 배포 모델이 Ollama에 있으면 AI 판정, 없으면 정적 판정 + 안내
    """
    if force_static:
        return VerdictMode(False, notice="정적 판정만 쓴다(--no-llm).")
    if force_llm:
        chosen_backend = backend or "ollama"
        chosen_model = model or (RELEASE_MODEL if chosen_backend == "ollama" else "")
        return VerdictMode(True, chosen_backend, chosen_model)
    if installed is None:
        return VerdictMode(False, notice=(
            "Ollama에 연결하지 못해 정적 판정으로 검사한다. AI 판정을 쓰려면 Ollama를 설치·실행하고 "
            "`python -m rag_app.cli setup`을 한 번 실행한다."))
    if _has(installed, model or RELEASE_MODEL):
        return VerdictMode(True, "ollama", model or RELEASE_MODEL)
    return VerdictMode(False, notice=(
        f"판정 모델 {model or RELEASE_MODEL}이(가) 설치돼 있지 않아 정적 판정으로 검사한다. "
        "AI 판정을 쓰려면 `python -m rag_app.cli setup`을 한 번 실행한다."))


def ollama_exe() -> str:
    found = shutil.which("ollama")
    if found:
        return found
    windows = Path.home() / "AppData" / "Local" / "Programs" / "Ollama" / "ollama.exe"
    return str(windows) if windows.exists() else "ollama"


def modelfile_text(base: str, adapter_file: str) -> str:
    # 판정은 결정적이어야 한다. 운영 코드도 온도 0·시드 0으로 부르지만 모델 기본값도 맞춘다.
    return (f"FROM {base}\n"
            f"ADAPTER {adapter_file}\n"
            "PARAMETER temperature 0\n"
            "PARAMETER seed 0\n"
            # 도구 밖에서 `ollama run`으로 써도 같은 문맥 길이가 되게
            "PARAMETER num_ctx 4096\n")


def setup(host: str, adapter_dir: Path = RELEASE_ADAPTER, name: str = RELEASE_MODEL,
          base: str = RELEASE_BASE) -> int:
    """기본 모델을 받고 어댑터를 얹어 배포 모델을 등록한다. 이미 있으면 아무것도 하지 않는다."""
    installed = installed_models(host)
    if installed is None:
        print(f"Ollama 서버({host})에 연결하지 못했다. Ollama를 설치하고 실행한 뒤 다시 시도한다: "
              "https://ollama.com/download")
        return 1
    if _has(installed, name):
        print(f"이미 설치돼 있다: {name}")
        return 0
    adapter = adapter_dir / "adapter-f16.gguf"
    if not adapter.exists():
        print(f"어댑터 파일이 없다: {adapter}")
        return 1
    exe = ollama_exe()
    if not _has(installed, base):
        print(f"기본 모델 {base}를 받는다(약 4.7GB, 한 번만).")
        subprocess.run([exe, "pull", base], check=True)
    (adapter_dir / "Modelfile").write_text(modelfile_text(base, adapter.name), encoding="utf-8")
    print(f"{name}을(를) 등록한다.")
    subprocess.run([exe, "create", name, "-f", "Modelfile"], check=True, cwd=str(adapter_dir))
    if not _has(installed_models(host) or [], name):
        print(f"{name}이(가) 목록에 없다. `ollama create` 출력을 확인한다.")
        return 1
    meta = adapter_dir / "export_meta.json"
    if meta.exists():
        info = json.loads(meta.read_text(encoding="utf-8"))
        print(f"기본 모델 {info.get('base_model', base)} + 어댑터 {adapter.name}")
    print(f"설치 완료. 이제 `python -m rag_app.cli analyze <경로>`가 AI 판정을 함께 쓴다.")
    return 0
