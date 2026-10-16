"""
AI 판정 자동 감지와 배포 설정을 고정한다 (2026-10-09).

도구는 `analyze` 하나로 쓴다. 배포 판정 모델이 Ollama에 있으면 AI 판정을 함께 쓰고, 없으면 정적 판정으로 돌리며 설치
방법을 알려 준다. 보고서에는 어떤 판정 방식이었는지 남는다.
"""

from __future__ import annotations

from rag_app.analysis import sarif
from rag_app.models import release


def test_uses_ai_when_release_model_is_installed():
    mode = release.resolve_mode(False, False, ["qwen2.5-coder:7b", release.RELEASE_MODEL])
    assert mode.use_llm and mode.backend == "ollama" and mode.model == release.RELEASE_MODEL
    assert mode.notice == ""


def test_falls_back_to_static_with_setup_hint_when_model_missing():
    mode = release.resolve_mode(False, False, ["qwen2.5-coder:7b"])
    assert not mode.use_llm
    assert "setup" in mode.notice


def test_falls_back_to_static_when_ollama_is_unreachable():
    mode = release.resolve_mode(False, False, None)
    assert not mode.use_llm
    assert "Ollama" in mode.notice and "setup" in mode.notice


def test_no_llm_forces_static_even_if_model_installed():
    mode = release.resolve_mode(False, True, [release.RELEASE_MODEL])
    assert not mode.use_llm


def test_llm_flag_defaults_to_release_model_on_ollama():
    mode = release.resolve_mode(True, False, None)
    assert mode.use_llm and mode.backend == "ollama" and mode.model == release.RELEASE_MODEL


def test_llm_flag_keeps_explicit_backend_and_model():
    mode = release.resolve_mode(True, False, None, "local", "Qwen/Qwen2.5-Coder-7B-Instruct")
    assert (mode.backend, mode.model) == ("local", "Qwen/Qwen2.5-Coder-7B-Instruct")


def test_latest_tag_counts_as_installed():
    mode = release.resolve_mode(False, False, ["my-model:latest"], model="my-model")
    assert mode.use_llm and mode.model == "my-model"


def test_modelfile_pins_deterministic_decoding():
    text = release.modelfile_text("qwen2.5-coder:7b", "adapter-f16.gguf")
    assert "FROM qwen2.5-coder:7b" in text and "ADAPTER adapter-f16.gguf" in text
    assert "temperature 0" in text and "seed 0" in text


def test_release_adapter_ships_with_the_repository():
    assert (release.RELEASE_ADAPTER / "adapter-f16.gguf").exists()


def test_report_records_how_it_was_judged(tmp_path):
    doc = sarif.build([], root=str(tmp_path),
                      verdict_info={"mode": "llm", "backend": "ollama", "model": release.RELEASE_MODEL})
    assert doc["runs"][0]["properties"]["verdict"]["model"] == release.RELEASE_MODEL
    static = sarif.build([], root=str(tmp_path), verdict_info={"mode": "static"})
    assert static["runs"][0]["properties"]["verdict"] == {"mode": "static"}
