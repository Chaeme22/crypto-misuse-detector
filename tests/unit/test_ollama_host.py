"""Ollama 주소는 표준 환경 변수 `OLLAMA_HOST`를 따른다 (2026-10-09)."""

from __future__ import annotations

from rag_app.config.schema import AppConfig


def test_default_host_without_env(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    assert AppConfig().ollama_host == "http://localhost:11434"


def test_env_host_without_scheme(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "127.0.0.1:11439")
    assert AppConfig().ollama_host == "http://127.0.0.1:11439"


def test_env_host_overrides_config_value(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://gpu-box:11434")
    assert AppConfig(ollama_host="http://localhost:11434").ollama_host == "http://gpu-box:11434"
