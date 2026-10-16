"""
학습한 LoRA 어댑터를 이 PC의 Ollama 판정 모델로 등록한다.

Colab·Kaggle에서 받은 어댑터 폴더(adapter_config.json, adapter_model.safetensors,
training_meta.json)를 넣으면:

  1. llama.cpp의 convert_lora_to_gguf.py로 어댑터를 GGUF로 바꾼다 (기본 모델은 설정만 필요)
  2. Modelfile을 쓴다: 같은 기본 모델(Ollama 태그) 위에 어댑터를 얹고 온도 0
  3. `ollama create`로 등록하고 목록에 올라왔는지 확인한다

기본 모델을 병합하거나 7B GGUF를 새로 만들지 않는다. 어댑터는 수십 MB라 CPU PC에서도 빠르다.
운영 판정은 `--llm-backend ollama --llm-model <등록 이름>`으로 쓴다.

    python tools/export_adapter.py adapters/qwen7b-v1 --name crypto-verdict:qwen7b-v1

기본 모델 대응: HF 이름 → Ollama 태그. Ollama의 qwen2.5-coder 태그는 같은 Instruct 모델의
4비트 양자화본이고 chat template(ChatML)도 학습 때와 같다.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
LLAMA_CPP = Path.home() / ".cache" / "crypto-misuse" / "llama.cpp"
OLLAMA_BASE = {
    "Qwen/Qwen2.5-Coder-7B-Instruct": "qwen2.5-coder:7b",
    "Qwen/Qwen2.5-Coder-1.5B-Instruct": "qwen2.5-coder:1.5b",
    "Qwen/Qwen2.5-Coder-0.5B-Instruct": "qwen2.5-coder:0.5b",
}


def _ollama_exe() -> str:
    candidate = Path.home() / "AppData" / "Local" / "Programs" / "Ollama" / "ollama.exe"
    return str(candidate) if candidate.exists() else "ollama"


def _ensure_llama_cpp(path: Path) -> Path:
    script = path / "convert_lora_to_gguf.py"
    if script.exists():
        return script
    print(f"llama.cpp를 {path}에 받는다 (변환 스크립트만 쓴다)")
    path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "clone", "--depth", "1", "https://github.com/ggml-org/llama.cpp.git",
                    str(path)], check=True)
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-e", str(path / "gguf-py")],
                   check=True)
    return script


def _installed(host: str) -> list[str]:
    return [m["name"] for m in requests.get(f"{host}/api/tags", timeout=10).json()["models"]]


def main() -> int:
    ap = argparse.ArgumentParser(description="LoRA 어댑터를 Ollama 판정 모델로 등록한다")
    ap.add_argument("adapter", type=Path, help="PEFT 어댑터 폴더")
    ap.add_argument("--name", required=True, help="Ollama 모델 이름. 예: crypto-verdict:qwen7b-v1")
    ap.add_argument("--base-model-id", help="생략하면 training_meta.json의 base_model")
    ap.add_argument("--ollama-base", help="생략하면 기본 모델 이름으로 대응표에서 고른다")
    ap.add_argument("--llama-cpp", type=Path, default=LLAMA_CPP)
    ap.add_argument("--host", default="http://localhost:11434")
    args = ap.parse_args()

    adapter = args.adapter.resolve()
    meta_path = adapter / "training_meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    base_id = args.base_model_id or meta.get("base_model")
    if not base_id:
        raise SystemExit("기본 모델을 모른다. --base-model-id를 준다")
    ollama_base = args.ollama_base or OLLAMA_BASE.get(base_id)
    if not ollama_base:
        raise SystemExit(f"{base_id}에 대응하는 Ollama 태그를 모른다. --ollama-base를 준다")

    installed = _installed(args.host)
    if ollama_base not in installed:
        raise SystemExit(f"기본 모델 {ollama_base}가 Ollama에 없다. `ollama pull {ollama_base}`")

    script = _ensure_llama_cpp(args.llama_cpp)
    gguf = adapter / "adapter-f16.gguf"
    subprocess.run([sys.executable, str(script), str(adapter), "--outfile", str(gguf),
                    "--outtype", "f16", "--base-model-id", base_id], check=True)

    modelfile = adapter / "Modelfile"
    modelfile.write_text(
        f"FROM {ollama_base}\n"
        f"ADAPTER {gguf.name}\n"
        # 판정은 결정적이어야 한다. 운영 코드도 온도 0·시드 0으로 부르지만 모델 기본값도 맞춘다.
        "PARAMETER temperature 0\n"
        "PARAMETER seed 0\n", encoding="utf-8")
    subprocess.run([_ollama_exe(), "create", args.name, "-f", str(modelfile)], check=True,
                   cwd=str(adapter))

    if args.name not in _installed(args.host) and f"{args.name}:latest" not in _installed(args.host):
        raise SystemExit(f"{args.name}가 Ollama 목록에 없다. `ollama create` 출력을 확인한다")
    export = {"ollama_model": args.name, "ollama_base": ollama_base, "base_model": base_id,
              "adapter_gguf": gguf.name,
              "adapter_gguf_sha256": "sha256:" + hashlib.sha256(gguf.read_bytes()).hexdigest(),
              "llama_cpp_commit": subprocess.run(
                  ["git", "-C", str(args.llama_cpp), "rev-parse", "HEAD"], capture_output=True,
                  text=True).stdout.strip(),
              "training_meta": meta}
    (adapter / "export_meta.json").write_text(json.dumps(export, ensure_ascii=False, indent=2) + "\n",
                                              encoding="utf-8")
    print(f"등록 완료: {args.name} (기본 {ollama_base} + {gguf.name})")
    print(f"사용: python -m rag_app.cli analyze <경로> --llm --llm-backend ollama --llm-model {args.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
