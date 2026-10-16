"""
CryptoLLM(Baek·Lee·Kim, ESORICS 2024)을 소스 폴더에 바로 돌린다 — 기준선 비교용.

원본 `tool/main.py`는 APK를 jadx로 디컴파일한 뒤 파일마다 `findCryptoLine` → `slicingCode` → `detect_<model>`을 부른다.
우리 시험지는 이미 소스이므로 디컴파일만 건너뛰고 같은 세 함수를 그대로 부른다(판정 로직은 바꾸지 않는다).
원본 결과 형식과 같이 파일마다 `m`(오용) / `b`(정상) / `X`(분석 실패, 암호 줄은 있었으나 슬라이싱 실패)를 낸다.
암호 줄이 없는 파일은 결과에 넣지 않는다(원본도 쓰지 않는다).

원본 저장소의 `tool/` 폴더에서 CryptoLLM 전용 환경(Python 3.8)으로 실행한다.

    cd repos/CryptoLLM/tool
    python <이 파일> --src <소스 루트> --out <결과.json> --p ./CryptoLLM_codet5.bin --m codet5
"""

import argparse
import json
import os
import shutil
import sys
import tempfile

import torch

sys.path.insert(0, os.getcwd())
from slicing import slicingCode  # noqa: E402
from extract_crypto_line import findCryptoLine  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--p", required=True, help="학습된 모델(.bin)")
    ap.add_argument("--m", default="codet5", choices=("codebert", "codegpt", "codet5", "electra"))
    args = ap.parse_args()
    args.device = torch.device("cpu")

    if args.m == "codet5":
        from detect_codet5 import model_setting_codet5 as setting, detect_codet5 as detect
    elif args.m == "codebert":
        from detect_codebert import model_setting_codebert as setting, detect_codebert as detect
    elif args.m == "codegpt":
        from detect_codegpt import model_setting_codegpt as setting, detect_codegpt as detect
    else:
        from detect_electra import model_setting_electra as setting, detect_electra as detect
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    # 공개 가중치는 GPU에서 저장됐고 원본은 map_location 없이 읽는다. CPU로 읽도록만 바꾼다(가중치·판정은 그대로)
    _load = torch.load
    torch.load = lambda f, *a, **k: _load(f, *a, **{**k, "map_location": "cpu"})
    model, tokenizer = setting(args)
    model.eval()

    src = os.path.abspath(args.src)
    results = {}
    files = [os.path.join(r, f) for r, _, fs in os.walk(src) for f in fs if f.endswith(".java")
             and "/.git/" not in r + "/"]
    for n, path in enumerate(sorted(files), 1):
        rel = os.path.relpath(path, src)
        # 원본은 디컴파일 폴더(…/sources/…) 안에서 작업 파일을 만든다. 같은 모양의 임시 폴더를 쓴다.
        work = tempfile.mkdtemp(prefix="cllm_")
        try:
            target = os.path.join(work, "sources", rel)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copyfile(path, target)
            line_dic, pre_path = findCryptoLine(target, work)
            if not line_dic:
                continue
            code_dir = slicingCode(os.path.basename(target), work, pre_path, line_dic, args.device)
            if code_dir is False:
                results[rel] = "X"
                continue
            with torch.no_grad():
                preds = detect(code_dir, model, tokenizer, args)
            results[rel] = "m" if 1 in list(preds) else "b"
        except Exception as error:  # 원본도 예외를 X로 남긴다
            results[rel] = "X"
            print(f"  X {rel}: {str(error)[:80]}", flush=True)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        if n % 50 == 0:
            print(f"  {n}/{len(files)}", flush=True)
    if os.path.exists("./graph"):
        shutil.rmtree("./graph", ignore_errors=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"tool": f"CryptoLLM-{args.m}", "src": src, "files": results}, f, ensure_ascii=False, indent=1)
    print(f"파일 {len(files)}개 중 암호 줄 {len(results)}개 — m {sum(v == 'm' for v in results.values())}, "
          f"b {sum(v == 'b' for v in results.values())}, X {sum(v == 'X' for v in results.values())}")


if __name__ == "__main__":
    main()
