from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from detection.engine import HybridDetector
from detection.gemini_explain import GeminiError, gemini_configured
from detection.gemini_explain import explain as ai_explain
from detection.live_monitor import (
    ATTACK_LABELS,
    MonitorError,
    attack_labels,
    feed_to_json,
    normalise_base_url,
    poll_events,
)
from detection.models import AIExplanation, DetectionResult
from detection.storage import EventStore
from detection.transfer import ImportDataError, import_json_events

PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env", override=False)

MAX_EXPLANATION_LENGTH = 4000

st.set_page_config(page_title="Request Signal", page_icon="RS", layout="wide")
st.markdown(
    """
    <style>
    :root {
      --ink: #172b2a;
      --muted: #5e716f;
      --paper: #f4f6f2;
      --surface: #ffffff;
      --line: #d8e0da;
      --signal: #087f70;
      --alert: #b84932;
      --amber: #a6650b;
    }
        .stApp {
            background: var(--paper);
            color: var(--ink);
        }
        [data-testid="stSidebar"] {
            background: #e8eeea;
            border-right: 1px solid var(--line);
        }
        [data-testid="stMetric"] {
            background: var(--surface);
            border: 1px solid var(--line);
            padding: 14px 16px;
            border-radius: 6px;
        }
        h1, h2, h3 {
            color: var(--ink);
            font-family: "Aptos Display", "Segoe UI Variable", sans-serif;
            letter-spacing: 0;
        }
        .signal-label {
            color: var(--signal);
            font-size: 0.78rem;
            font-weight: 700;
            text-transform: uppercase;
        }
    .muted { color: var(--muted); }
        div[data-testid="stButton"] button[kind="primary"] {
            background: var(--signal);
            border-color: var(--signal);
        }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_store(database_path: str) -> EventStore:
    return EventStore(database_path)


def _show_rules() -> None:
    st.title("Detection Rules")
    rules = [
        {
            "Rule ID": "SQLI-001",
            "Category": "SQL injection",
            "Severity": "High",
            "Limit": "Detects SQL-like syntax in a request. Does not prove success or intent.",
        },
        {
            "Rule ID": "XSS-001",
            "Category": "Cross-site scripting",
            "Severity": "High",
            "Limit": "HTML/script-handler patterns. Legitimate test strings can also match.",
        },
        {
            "Rule ID": "PATH-001",
            "Category": "Path traversal",
            "Severity": "High",
            "Limit": "Detects parent-directory syntax. Does not judge reach or success.",
        },
        {
            "Rule ID": "AUTH-REPEAT-001",
            "Category": "Authentication anomaly",
            "Severity": "Medium",
            "Limit": "5+ login failures from one source in 5 min. Shared IPs can cause false positives.",
        },
        {
            "Rule ID": "AI-ROBUST-MAD",
            "Category": "Anomalous request shape",
            "Severity": "Score-based",
            "Limit": "Statistical distance from a synthetic baseline. The score is not a "
            "probability and unusual-but-benign paths can match.",
        },
    ]
    st.dataframe(pd.DataFrame(rules), hide_index=True, width="stretch")
    st.warning("This is an educational signature-detection demo, not a certified IDS or breach-decision system.")


def _monitor_state() -> dict:
    return st.session_state.setdefault(
        "live_monitor", {"cursor": 0, "events": {}, "target": ""}
    )


def _poll_into_state(base_url: str) -> int:
    """Pull new events from the shop feed, run detection (rules + local AI), and cache
    them in the session only. Nothing is written to disk.

    The first poll after connecting to a target sets a baseline: the events already in
    the shop log are skipped, so the counters start at 0 on every run and rise only
    with attacks that happen while monitoring. Re-entering the target resets to 0.
    """
    state = _monitor_state()
    if state["target"] != base_url:
        state.update(cursor=0, events={}, target=base_url, baseline_pending=True)
    events, total = poll_events(base_url, state["cursor"])
    if state.get("baseline_pending"):
        state.update(cursor=total, baseline_pending=False)
        return 0
    fresh = [event for event in events if event.get("event_id") not in state["events"]]
    state["cursor"] = total
    if fresh:
        detected = HybridDetector().analyze(import_json_events(feed_to_json(fresh)), ai_enabled=True)
        for result in detected:
            state["events"][result.event.event_id] = result
    return len(fresh)


def _monitor_results() -> tuple[DetectionResult, ...]:
    return tuple(_monitor_state()["events"].values())


CHART_BUCKET = "10min"
WINDOW_HOURS = 24


@st.fragment(run_every="3s")
def _live_feed(store: EventStore) -> None:
    """Auto-refreshing part (every 3s): poll the shop, draw the attack-type metrics and
    the per-attack-type chart, and list the detected attack events. Keeping the table
    inside this fragment means new attacks appear without any manual interaction."""
    target = st.session_state.get("monitor_target", "").strip()
    if target:
        try:
            base_url = normalise_base_url(target)
            _poll_into_state(base_url)
            st.caption(f"Connected to {base_url} · auto-refreshing every 3s")
        except MonitorError as exc:
            st.warning(str(exc))
        except (ImportDataError, OSError, sqlite3.Error) as exc:
            st.warning(f"Could not ingest the feed: {exc}")
    else:
        st.caption("Enter the demo shop target above to start monitoring.")

    results = _monitor_results()
    attacks = [result for result in results if result.rule_findings]

    offset = int(st.session_state.get("day_offset", 0))
    window_end = datetime.now(UTC) - timedelta(hours=WINDOW_HOURS * offset)
    window_start = window_end - timedelta(hours=WINDOW_HOURS)
    in_window = [
        result
        for result in attacks
        if window_start <= result.event.timestamp.astimezone(UTC) <= window_end
    ]

    counts = dict.fromkeys(ATTACK_LABELS, 0)
    for result in in_window:
        for label in attack_labels(result):
            counts[label] += 1
    metric_columns = st.columns(len(ATTACK_LABELS))
    for column, label in zip(metric_columns, ATTACK_LABELS, strict=True):
        column.metric(label, f"{counts[label]:,}")

    nav = st.columns([1.2, 2.6, 1.2])
    if nav[0].button("◀ Earlier 24h", use_container_width=True):
        st.session_state["day_offset"] = offset + 1
        st.rerun(scope="fragment")
    window_label = (
        "Last 24 hours"
        if offset == 0
        else f"{window_start:%Y-%m-%d %H:%M} – {window_end:%Y-%m-%d %H:%M} UTC"
    )
    nav[1].markdown(
        f"<div style='text-align:center;padding-top:6px'>Showing detected access · "
        f"<b>{window_label}</b></div>",
        unsafe_allow_html=True,
    )
    if nav[2].button("Later 24h ▶", use_container_width=True, disabled=offset == 0):
        st.session_state["day_offset"] = max(0, offset - 1)
        st.rerun(scope="fragment")

    records = [
        (result.event.timestamp.astimezone(UTC), label)
        for result in in_window
        for label in attack_labels(result)
    ]
    if records:
        frame = pd.DataFrame(records, columns=["time", "category"])
        pivot = frame.pivot_table(
            index=frame["time"].dt.floor(CHART_BUCKET),
            columns="category",
            aggfunc="size",
            fill_value=0,
        )
        full_index = pd.date_range(
            pd.Timestamp(window_start).floor(CHART_BUCKET),
            pd.Timestamp(window_end).ceil(CHART_BUCKET),
            freq=CHART_BUCKET,
        )
        pivot = pivot.reindex(full_index, fill_value=0)
        for label in ATTACK_LABELS:
            if label not in pivot.columns:
                pivot[label] = 0
        pivot = pivot[list(ATTACK_LABELS)]
        pivot.index.name = "time (UTC)"
        st.line_chart(pivot, height=320)
    else:
        st.caption("No attacks detected in this time window yet.")

    # Detected attack events table (auto-refreshes with this fragment).
    attacks_sorted = sorted(attacks, key=lambda result: result.event.timestamp, reverse=True)
    st.subheader(f"Detected attack events ({len(attacks_sorted)})")
    if not attacks_sorted:
        st.caption("No attacks detected yet. Start the demo shop and run the attack tool.")
        return
    st.caption("Select a row to see the AI explanation and countermeasures.")
    table = pd.DataFrame(
        [
            {
                "Time (UTC)": result.event.timestamp.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S"),
                "Source": result.event.source,
                "Method": result.event.method or "-",
                "Path": result.event.path,
                "Attack": " / ".join(attack_labels(result)) or "Other",
                "Severity": result.display_severity,
            }
            for result in attacks_sorted
        ]
    )
    selection = st.dataframe(
        table,
        hide_index=True,
        width="stretch",
        on_select="rerun",
        selection_mode="single-row",
        key="attack_table",
    )
    rows = selection["selection"]["rows"]
    if rows:
        st.divider()
        _render_attack_explanation(attacks_sorted[rows[0]], store)
    else:
        st.info("↑ Select an attack row to view its AI explanation and countermeasures.")


def _save_explanation(
    result: DetectionResult, text: str, store: EventStore, *, model: str
) -> DetectionResult:
    """Persist an explanation to the store and the live-monitor session cache."""
    updated = replace(
        result,
        ai_explanation=AIExplanation(
            status="generated",
            text=text.strip()[:MAX_EXPLANATION_LENGTH],
            model=model,
        ),
    )
    store.update_result(updated)
    cache = _monitor_state()["events"]
    if result.event.event_id in cache:
        cache[result.event.event_id] = updated
    return updated


def _render_attack_explanation(result: DetectionResult, store: EventStore) -> None:
    """Show detection facts plus an AI-written explanation for one event.

    When the AI backend is configured, the explanation is generated automatically on
    selection (no copy-paste). The program only supplies sanitized facts; the
    explanation text is written by the AI.
    """
    st.markdown("**AI Explanation**")
    st.caption(
        "Detection is done by the program (rules + local statistical AI). The "
        "explanation text is written on the fly by the AI from the sanitized facts "
        "below (method, path, rule evidence, local-AI verdict) — no source, user-agent "
        "or request body is sent, and there is no pre-written text."
    )
    st.markdown(
        f"Attack type: **{' / '.join(attack_labels(result)) or 'Other'}** · Severity: "
        f"**{result.display_severity}**"
    )
    with st.expander("Detection facts (rules + local statistical AI)", expanded=True):
        for finding in result.rule_findings:
            st.write(f"{finding.rule_id} · {finding.name}: {finding.evidence}")
        if result.ai_finding.suspicious is not None:
            st.caption(
                f"Local statistical AI: "
                f"{'flagged' if result.ai_finding.suspicious else 'not flagged'} "
                f"(score {result.ai_finding.score})"
            )

    if not gemini_configured():
        st.info("AI explanation is not configured. Set the AI API key in the .env file to enable it.")
        return

    # Auto-generate on first selection of an attack event.
    already = bool(result.ai_explanation and result.ai_explanation.text)
    if not already and result.rule_findings:
        with st.spinner("Generating explanation with AI…"):
            try:
                result = _save_explanation(result, ai_explain(result), store, model="AI")
                already = True
            except GeminiError as exc:
                st.warning(f"AI explanation failed: {exc}")
                if st.button("Retry", key=f"retry-{result.event.event_id}"):
                    st.rerun()
                return

    if already:
        st.markdown("**Explanation by AI**")
        st.write(result.ai_explanation.text)
        st.caption("An AI-generated hypothesis, not a verified fact.")
        if st.button("Regenerate", key=f"regen-{result.event.event_id}"):
            with st.spinner("Regenerating with AI…"):
                try:
                    _save_explanation(result, ai_explain(result), store, model="AI")
                    st.rerun()
                except GeminiError as exc:
                    st.warning(f"AI explanation failed: {exc}")
    else:
        st.caption("Select an attack event to generate its explanation.")


def _show_live_monitor(store: EventStore) -> None:
    st.markdown(
        '<div class="signal-label">Live defensive monitor / local demo shop</div>',
        unsafe_allow_html=True,
    )
    st.title("Live Attack Monitor")
    st.caption(
        "Point this at your local demo shop to detect SQL injection, brute-force and "
        "other login attacks in real time. Only loopback/private IPs can be monitored."
    )
    state = _monitor_state()
    st.session_state["monitor_target"] = st.text_input(
        "Monitor target IP / URL",
        value=st.session_state.get("monitor_target", state["target"] or "127.0.0.1:8080"),
        help="Your own demo shop address, e.g. 127.0.0.1:8080",
    )

    _live_feed(store)


def main() -> None:
    # In-memory store only: nothing is written to a local database file, so no event
    # data remains on disk or between runs.
    try:
        store = get_store(":memory:")
    except (OSError, sqlite3.Error):
        st.error("Cannot open the in-memory event store.")
        st.stop()

    with st.sidebar:
        st.title("RS / SIGNAL DESK")
        page = st.radio(
            "Workspace",
            ["Live Attack Monitor", "Detection Rules"],
            label_visibility="collapsed",
        )
        st.caption("LOCAL · DEFENSIVE DEMO")

    if page == "Live Attack Monitor":
        _show_live_monitor(store)
    else:
        _show_rules()


if __name__ == "__main__":
    main()
