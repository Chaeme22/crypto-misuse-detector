"""
Ollama 판정 경로를 고정한다.

GPU가 없는 개발 PC에서 LLM 판정을 돌릴 수 있는 길은 Ollama뿐이다. 그런데 이 경로는 챗봇
시절 코드가 남아 있어 판정 요청을 한 번도 제대로 처리하지 못했다. 판정기는 문서 context
없이 프롬프트만 보내는데, context가 비면 "제공된 문서에서 답변을 찾을 수 없습니다"를 바로
돌려줬다. 그 답은 판정 형식이 아니므로 모든 판정이 보류로 떨어졌다. 온도 0과 고정 시드도
무시하고 top_p 표본추출을 켜서, 같은 코드에 같은 보고서라는 원칙도 깨져 있었다.
"""

from __future__ import annotations

import json

import pytest

from rag_app.config.schema import AppConfig
from rag_app.domain.exceptions import LLMModelError
from rag_app.domain.models import GenerationRequest
from rag_app.models import llm as llm_module


class _Response:
    def __init__(self, payload=None, lines=()):
        self.status_code = 200
        self._payload = payload or {}
        self._lines = lines
        self.text = ""

    def json(self):
        return self._payload

    def iter_lines(self):
        return iter(self._lines)


@pytest.fixture
def ollama(monkeypatch):
    """설치된 모델 목록과 생성 응답을 흉내 낸다. 보낸 요청을 기록한다."""
    sent: dict = {"posts": []}

    def fake_get(url, timeout=None):
        return _Response({"models": [{"name": "qwen2.5:7b"}, {"name": "gemma4:12b"}]})

    def fake_post(url, json=None, timeout=None, stream=None):
        sent["posts"].append((url, json))
        lines = [
            b'{"message": {"content": "role: crypto_operation\\ndecision: violation\\n"}}',
            b'{"message": {"content": "reasoning: x\\nfix: y"}, "done": true, "eval_count": 9}',
        ]
        return _Response(lines=lines)

    monkeypatch.setattr(llm_module.requests, "get", fake_get)
    monkeypatch.setattr(llm_module.requests, "post", fake_post)
    return sent


def _config() -> AppConfig:
    return AppConfig(environment="development")


def test_verdict_request_without_context_reaches_the_model(ollama):
    model = llm_module.OllamaLLM(_config(), model="qwen2.5:7b")
    result = model.generate(GenerationRequest(question="판정하라", temperature=0.0, seed=0,
                                              max_tokens=512))
    assert result.answer.startswith("role: crypto_operation")
    assert len(ollama["posts"]) == 1


def test_verdict_request_is_deterministic(ollama):
    """온도 0·고정 시드로 부르고 표본추출 옵션을 켜지 않는다."""
    model = llm_module.OllamaLLM(_config(), model="qwen2.5:7b")
    model.generate(GenerationRequest(question="판정하라", temperature=0.0, seed=0, max_tokens=512))
    url, payload = ollama["posts"][0]
    options = payload["options"]
    assert options["temperature"] == 0.0
    assert options["seed"] == 0
    assert options["num_predict"] == 512
    assert "top_p" not in options and "repeat_penalty" not in options
    assert payload["model"] == "qwen2.5:7b"


def test_verdict_prompt_is_sent_as_is(ollama):
    """판정 프롬프트에 챗봇 시스템 프롬프트(SOURCE 인용 규칙)를 덧씌우지 않는다."""
    model = llm_module.OllamaLLM(_config(), model="qwen2.5:7b")
    model.generate(GenerationRequest(question="판정하라", temperature=0.0, seed=0))
    _, payload = ollama["posts"][0]
    assert payload["messages"] == [{"role": "user", "content": "판정하라"}]
    assert "SOURCE" not in json.dumps(payload, ensure_ascii=False)


def test_missing_model_fails_loudly_without_downloading(ollama):
    """없는 모델을 몰래 수 GB 내려받지 않는다. 무엇을 받아야 하는지 알려 준다."""
    with pytest.raises(LLMModelError) as caught:
        llm_module.OllamaLLM(_config(), model="qwen2.5-coder:7b")
    assert "ollama pull qwen2.5-coder:7b" in str(caught.value)
    assert not any("/api/pull" in url for url, _ in ollama["posts"])


def test_local_backend_receives_the_adapter(monkeypatch):
    """학습한 어댑터는 local 백엔드에 얹는다. 기본 모델 이름과 함께 그대로 넘어가야 한다."""
    seen = {}

    class FakeLocal:
        def __init__(self, config, model_id, load_in_4bit=False, adapter_path=None):
            seen.update(model_id=model_id, load_in_4bit=load_in_4bit, adapter_path=adapter_path)

    monkeypatch.setattr(llm_module, "LocalTransformersLLM", FakeLocal)
    llm_module.make_verdict_model(_config(), "local", None, True, "runs/qwen7b-pilot-v1")
    assert seen == {"model_id": "Qwen/Qwen2.5-Coder-7B-Instruct", "load_in_4bit": True,
                    "adapter_path": "runs/qwen7b-pilot-v1"}


def test_ollama_backend_rejects_a_separate_adapter(ollama):
    """Ollama는 어댑터를 등록한 모델 이름으로 쓴다. 따로 넘기면 무시하지 않고 막는다."""
    with pytest.raises(ValueError):
        llm_module.make_verdict_model(_config(), "ollama", "qwen2.5:7b", adapter="x")
