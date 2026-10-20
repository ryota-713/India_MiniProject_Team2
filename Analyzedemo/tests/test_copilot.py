from datetime import UTC, datetime
from types import SimpleNamespace

from detection.copilot import COPILOT_ENV, CopilotExplainer
from detection.engine import HybridDetector
from detection.models import AIExplanation, DetectionResult, Event
from detection.serialization import result_from_record, result_to_record


class FakeSession:
    def __init__(self, response=None, error=None):
        self.response = response or SimpleNamespace(
            data=SimpleNamespace(content="入力中の兆候について説明します。")
        )
        self.error = error
        self.options = None
        self.prompt = None
        self.timeout = None
        self.closed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        self.closed = True

    async def send_and_wait(self, prompt, *, timeout):
        self.prompt = prompt
        self.timeout = timeout
        if self.error:
            raise self.error
        return self.response


class FakeClient:
    def __init__(self, session, options):
        self.session = session
        self.options = options
        self.session_options = None
        self.closed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        self.closed = True

    async def create_session(self, **kwargs):
        self.session_options = kwargs
        return self.session


def result_with_sensitive_data() -> DetectionResult:
    event = Event(
        "copilot-test",
        datetime(2026, 1, 1, tzinfo=UTC),
        "source-secret",
        "/login?password=do-not-send&query=%27%20OR%201%3D1",
        method="GET",
        status_code=400,
        user_agent="Bearer should-not-send",
    )
    return HybridDetector().analyze((event,))[0]


def fake_client_factory(session, captured):
    def create_client(**options):
        captured.setdefault("client_options", []).append(options)
        client = FakeClient(session, options)
        captured["client"] = client
        return client

    return create_client


def test_copilot_uses_empty_toolless_session_and_caches_sanitized_success():
    session = FakeSession()
    captured = {}
    explainer = CopilotExplainer(
        model="auto",
        timeout_seconds=13,
        client_factory=fake_client_factory(session, captured),
    )

    first = explainer.explain(result_with_sensitive_data())
    second = explainer.explain(result_with_sensitive_data())

    assert first.status == "generated"
    assert second.cached
    client_options = captured["client_options"][0]
    session_options = captured["client"].session_options
    assert client_options["mode"] == "empty"
    assert client_options["use_logged_in_user"] is True
    assert client_options["env"] == COPILOT_ENV
    assert session.timeout == 13
    assert len(captured["client_options"]) == 1
    assert session.closed
    sent = session.prompt
    assert "do-not-send" not in sent
    assert "source-secret" not in sent
    assert "should-not-send" not in sent
    assert "score_is_probability" in sent
    assert "未信頼データ" in session_options["system_message"]["content"]
    assert client_options["env"]["COPILOT_GITHUB_TELEMETRY_DISABLED"] == "true"


def test_copilot_session_disables_all_tools_and_persistent_context():
    session = FakeSession()
    captured = {}
    explainer = CopilotExplainer(client_factory=fake_client_factory(session, captured))
    explainer.explain(result_with_sensitive_data())
    options = captured["client"].session_options

    assert options["available_tools"] == []
    assert options["tools"] == []
    assert options["enable_session_store"] is False
    assert options["enable_github_cache_store"] is False
    assert options["enable_skills"] is False
    assert options["enable_mcp_apps"] is False
    assert options["enable_file_change_tracking"] is False
    assert options["enable_host_git_operations"] is False
    assert options["enable_session_telemetry"] is False
    assert options["memory"] == {"enabled": False}
    assert options["infinite_sessions"] == {"enabled": False}
    assert options["system_message"]["mode"] == "append"


def test_copilot_timeout_or_auth_failure_is_redacted():
    timed_out = CopilotExplainer(
        client_factory=fake_client_factory(
            FakeSession(error=TimeoutError("private timeout detail")), {}
        )
    ).explain(result_with_sensitive_data())
    assert timed_out.status == "unavailable"
    assert "private timeout detail" not in str(timed_out)

    class AuthenticationError(Exception):
        pass

    unauthenticated = CopilotExplainer(
        client_factory=fake_client_factory(
            FakeSession(error=AuthenticationError("private token detail")), {}
        )
    ).explain(result_with_sensitive_data())
    assert unauthenticated.status == "auth_error"
    assert "private token detail" not in str(unauthenticated)


def test_copilot_handles_empty_response_and_sdk_errors():
    empty = CopilotExplainer(
        client_factory=fake_client_factory(
            FakeSession(response=SimpleNamespace(data=SimpleNamespace(content=None))), {}
        )
    ).explain(result_with_sensitive_data())
    failed = CopilotExplainer(
        client_factory=fake_client_factory(FakeSession(error=RuntimeError("private error")), {})
    ).explain(result_with_sensitive_data())

    assert empty.status == "invalid_response"
    assert failed.status == "error"
    assert "private error" not in str(failed)


def test_copilot_explanation_round_trips_separately_from_detection():
    result = result_with_sensitive_data()
    explanation = AIExplanation(
        status="generated",
        text="これはCopilotが生成した補助的な仮説です。",
        model="auto",
    )
    explained = DetectionResult(
        event=result.event,
        rule_findings=result.rule_findings,
        ai_finding=result.ai_finding,
        disagreement=result.disagreement,
        ai_explanation=explanation,
    )

    restored = result_from_record(result_to_record(explained))

    assert restored == explained
    assert restored.ai_finding == result.ai_finding


def test_copilot_explainer_does_not_need_or_accept_api_keys():
    session = FakeSession()
    captured = {}
    explainer = CopilotExplainer(client_factory=fake_client_factory(session, captured))

    assert explainer.explain(result_with_sensitive_data()).status == "generated"
    assert "api_key" not in captured["client_options"][0]