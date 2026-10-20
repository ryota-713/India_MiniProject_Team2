from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from detection.copilot import (
    MAX_EXPLANATION_LENGTH,
    CopilotExplainer,
    _prompt_for,
    _request_payload,
)
from detection.demo_data import load_synthetic_events
from detection.engine import HybridDetector
from detection.live_monitor import (
    MonitorError,
    feed_to_json,
    normalise_base_url,
    poll_events,
    summarise,
    time_series,
)
from detection.models import AIExplanation, DetectionResult
from detection.storage import EventStore
from detection.transfer import ImportDataError, import_json_events

PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env", override=False)


def _copilot_enabled() -> bool:
    return os.getenv("COPILOT_ENABLED", "").lower() == "true"


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


@st.cache_resource
def get_copilot_explainer(model_name: str) -> CopilotExplainer:
    return CopilotExplainer(model=model_name)


def _severity_order(severity: str) -> int:
    return {"Info": 0, "Low": 1, "Medium": 2, "High": 3}.get(severity, -1)


def _category_text(result: DetectionResult) -> str:
    categories = [finding.category for finding in result.rule_findings]
    if result.ai_finding.suspicious and result.ai_finding.category:
        categories.append(result.ai_finding.category)
    return ", ".join(dict.fromkeys(categories)) or "No indicator"


def _result_row(result: DetectionResult) -> dict[str, object]:
    return {
        "Time (UTC)": result.event.timestamp.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S"),
        "Source": result.event.source,
        "Method": result.event.method or "Not provided",
        "Path": result.event.path,
        "Category": _category_text(result),
        "Severity": result.display_severity,
        "Detected by": ", ".join(result.detection_sources) or "None",
        "AI state": result.ai_finding.status,
        "Event ID": result.event.event_id,
    }


def _load_demo(store: EventStore) -> int:
    results = HybridDetector().analyze(load_synthetic_events())
    return store.save_results(results)


def _show_overview(store: EventStore) -> None:
    st.markdown(
        '<div class="signal-label">Defensive monitoring / local workspace</div>',
        unsafe_allow_html=True,
    )
    st.title("Request Signal")
    st.caption(
        "Webリクエストの兆候をルールとローカル統計AIで照合します。検知結果は侵害の証明ではありません。"
    )
    results = store.list_results()
    suspicious = [result for result in results if result.is_suspicious]
    status_columns = st.columns(3)
    status_columns[0].caption("RULE DETECTION")
    status_columns[0].write("Active · local")
    status_columns[1].caption("LOCAL STATISTICAL AI")
    status_columns[1].write("Active · request-shape baseline")
    copilot_state = (
        "Enabled · local CLI sign-in checked on use"
        if _copilot_enabled()
        else "Disabled"
    )
    status_columns[2].caption("COPILOT SDK EXPLANATION")
    status_columns[2].write(copilot_state)

    metric_columns = st.columns(4)
    metric_columns[0].metric("処理イベント", f"{len(results):,}")
    metric_columns[1].metric("要確認", f"{len(suspicious):,}")
    metric_columns[2].metric(
        "High", sum(result.display_severity == "High" for result in suspicious)
    )
    metric_columns[3].metric("AI不一致", sum(result.disagreement for result in results))
    severity_counts = {
        severity: sum(result.display_severity == severity for result in results)
        for severity in ("High", "Medium", "Low", "Info")
    }
    st.caption(
        "Severity distribution: "
        + " · ".join(f"{severity} {count}" for severity, count in severity_counts.items())
    )

    with st.sidebar:
        st.subheader("絞り込み")
        source_options = sorted({result.event.source for result in results})
        selected_sources = st.multiselect("Source", source_options, default=source_options)
        severity_options = ["High", "Medium", "Low", "Info"]
        selected_severities = st.multiselect("Severity", severity_options, default=severity_options)
        category_options = sorted({_category_text(result) for result in results})
        selected_categories = st.multiselect(
            "Detection category", category_options, default=category_options
        )
        if results:
            days = [result.event.timestamp.astimezone(UTC).date() for result in results]
            selected_dates = st.date_input("Date range (UTC)", value=(min(days), max(days)))
        else:
            selected_dates = ()

    filtered = [
        result
        for result in results
        if result.event.source in selected_sources
        and result.display_severity in selected_severities
        and _category_text(result) in selected_categories
    ]
    if isinstance(selected_dates, tuple) and len(selected_dates) == 2:
        filtered = [
            result
            for result in filtered
            if selected_dates[0]
            <= result.event.timestamp.astimezone(UTC).date()
            <= selected_dates[1]
        ]

    st.subheader("Recent events")
    if not results:
        st.info(
            "イベントはまだありません。合成デモを読み込むか、"
            "Import & Testからファイルを取り込んでください。"
        )
        if st.button("合成デモイベントを読み込む", type="primary"):
            st.success(f"合成イベントを {_load_demo(store)} 件登録しました。")
            st.rerun()
        return
    if not filtered:
        st.info("現在のフィルターに一致するイベントはありません。")
        return

    rows = [_result_row(result) for result in filtered]
    st.dataframe(
        pd.DataFrame(rows).drop(columns=["Event ID"]),
        hide_index=True,
        width="stretch",
    )
    selected_id = st.selectbox(
        "イベント詳細",
        [result.event.event_id for result in filtered],
        format_func=lambda event_id: next(
            f"{event_id} · {_category_text(item)}"
            for item in filtered
            if item.event.event_id == event_id
        ),
    )
    selected = next(result for result in filtered if result.event.event_id == selected_id)
    with st.expander("選択したイベントの根拠と判定", expanded=True):
        left, right = st.columns(2)
        with left:
            st.markdown("**観測された事実**")
            st.json(
                {
                    "event_id": selected.event.event_id,
                    "timestamp": selected.event.timestamp.isoformat(),
                    "source": selected.event.source,
                    "method": selected.event.method,
                    "path": selected.event.path,
                    "status_code": selected.event.status_code,
                    "user_agent": selected.event.user_agent,
                }
            )
        with right:
            st.markdown("**ルール検知**")
            if selected.rule_findings:
                for finding in selected.rule_findings:
                    st.write(f"{finding.rule_id} · {finding.name} · {finding.severity}")
                    st.caption(finding.evidence)
            else:
                st.write("ルール一致なし")
            st.markdown("**AI支援型検知**")
            st.write(f"状態: {selected.ai_finding.status}")
            if selected.ai_finding.suspicious is not None:
                st.write(f"判定: {'要確認' if selected.ai_finding.suspicious else '兆候なし'}")
                st.write(f"正規化スコア: {selected.ai_finding.score}（確率ではありません）")
                st.caption(selected.ai_finding.evidence or "")
            st.caption(selected.ai_finding.limitation or "")
        if selected.disagreement:
            st.warning("ルール検知とAI検知の判定が異なります。両方の結果を個別に確認してください。")
        if selected.ai_explanation:
            st.markdown("**Copilotによる補足仮説**")
            status = selected.ai_explanation.status
            if selected.ai_explanation.cached:
                status += " · cache"
            st.caption(f"状態: {status}")
            if selected.ai_explanation.text:
                st.text(selected.ai_explanation.text)
                st.caption("AI生成の仮説であり、観測事実や検知証拠ではありません。")
            elif selected.ai_explanation.message:
                st.warning(selected.ai_explanation.message)

        st.divider()
        st.markdown("**AI解説（M365 Copilot用）**")
        st.caption(
            "検知はルール／ローカル統計AI（プログラム）が担当します。AIには"
            "“検知結果の解説”だけを任せます。下のプロンプトをコピーして"
            "M365 Copilotに貼り付けると、日本語の解説が得られます。"
            "送信されるのはサニタイズ済みのPath・Method/Status・ルール根拠・"
            "ローカルAI判定だけで、Source・User-Agent・Request bodyは含めません。"
        )
        with st.expander("Copilotへ渡す内容（サニタイズ済み・確認用）"):
            st.json(_request_payload(selected))

        st.markdown("① コピー用プロンプト（右上のアイコンでコピー）")
        st.code(_prompt_for(selected), language="text")

        st.markdown("② M365 Copilotの回答を貼り戻す")
        existing = (
            selected.ai_explanation.text
            if selected.ai_explanation and selected.ai_explanation.text
            else ""
        )
        with st.form(f"m365-explain-{selected.event.event_id}"):
            answer = st.text_area(
                "AIの解説（M365 Copilotの回答を貼り付け）",
                value=existing,
                height=170,
                placeholder="M365 Copilotが返した解説をここに貼り付けてください。",
            )
            saved = st.form_submit_button("解説を保存", type="primary")
        if saved:
            text = answer.strip()
            if not text:
                st.warning("保存する解説テキストを貼り付けてください。")
            else:
                explanation = AIExplanation(
                    status="generated",
                    text=text[:MAX_EXPLANATION_LENGTH],
                    model="M365 Copilot (manual)",
                )
                store.update_result(replace(selected, ai_explanation=explanation))
                st.success("AI解説を保存しました。")
                st.rerun()


def _show_rules() -> None:
    st.title("Detection Rules")
    rules = [
        {
            "Rule ID": "SQLI-001",
            "Category": "SQL injection",
            "Severity": "High",
            "Limit": "SQL構文に似た文字列を検出。成功や悪意は証明しない。",
        },
        {
            "Rule ID": "XSS-001",
            "Category": "Cross-site scripting",
            "Severity": "High",
            "Limit": "HTML/スクリプト関連パターン。正規のテスト文字列も一致し得る。",
        },
        {
            "Rule ID": "PATH-001",
            "Category": "Path traversal",
            "Severity": "High",
            "Limit": "親ディレクトリ移動の表記を検出。対象への到達や成功は判定しない。",
        },
        {
            "Rule ID": "AUTH-REPEAT-001",
            "Category": "Authentication anomaly",
            "Severity": "Medium",
            "Limit": "同一sourceのログイン失敗5件以上/5分。共有IP等で誤検知し得る。",
        },
        {
            "Rule ID": "AI-ROBUST-MAD",
            "Category": "Anomalous request shape",
            "Severity": "Score-based",
            "Limit": "合成ベースラインとの統計距離。スコアは確率ではなく、"
            "変わった正常経路も検出し得る。",
        },
    ]
    st.dataframe(pd.DataFrame(rules), hide_index=True, width="stretch")
    st.warning("これは教育用の兆候検出デモであり、認定IDSや侵害判定システムではありません。")


def _monitor_state() -> dict:
    return st.session_state.setdefault(
        "live_monitor", {"cursor": 0, "events": {}, "target": "", "live": False, "last_error": ""}
    )


def _poll_into_state(store: EventStore, base_url: str) -> int:
    """Pull new events from the shop feed, detect, persist, and cache in session.

    Returns the number of newly ingested events, or -1 when this poll only set a
    fresh baseline (after a reset or when the target first changes): events already
    in the shop log before that point are skipped, so the monitor counts from zero
    and rises only as new attacks arrive.
    """
    state = _monitor_state()
    if state["target"] != base_url:
        state.update(cursor=0, events={}, target=base_url, baseline_pending=True)
    events, total = poll_events(base_url, state["cursor"])
    if state.get("baseline_pending"):
        # Treat everything already logged as the baseline; count only later events.
        state.update(cursor=total, events={}, baseline_pending=False)
        return -1
    fresh = [event for event in events if event.get("event_id") not in state["events"]]
    state["cursor"] = total
    if fresh:
        detected = HybridDetector().analyze(import_json_events(feed_to_json(fresh)), ai_enabled=False)
        store.save_results(detected)
        for result in detected:
            state["events"][result.event.event_id] = result
    return len(fresh)


def _monitor_results(store: EventStore) -> tuple[DetectionResult, ...]:
    return tuple(_monitor_state()["events"].values())


def _show_live_monitor(store: EventStore) -> None:
    st.markdown(
        '<div class="signal-label">Live defensive monitor / local demo shop</div>',
        unsafe_allow_html=True,
    )
    st.title("Live Attack Monitor")
    st.caption(
        "デモ用ECショップのIPを監視対象として指定し、SQLインジェクションとブルートフォースの"
        "ログイン攻撃をリアルタイムに検知します。監視できるのはローカル/プライベートIPだけです。"
    )
    state = _monitor_state()

    controls = st.columns([3, 1, 1, 1])
    target = controls[0].text_input(
        "監視対象 IP / URL", value=state["target"] or "127.0.0.1:8080",
        help="自分のデモ用ショップの宛先。例: 127.0.0.1:8080",
    )
    bucket_seconds = int(controls[1].selectbox("グラフ粒度(秒)", [5, 10, 30, 60], index=1))
    threshold = int(controls[2].number_input("ブルートフォース閾値", min_value=2, max_value=100, value=5))
    window_minutes = int(controls[3].number_input("集計窓(分)", min_value=1, max_value=60, value=5))

    actions = st.columns([1, 1, 1, 3])
    refresh = actions[0].button("更新", type="primary")
    state["live"] = actions[1].toggle("自動更新", value=state["live"])
    interval = int(actions[2].selectbox("更新間隔(秒)", [2, 3, 5, 10], index=1))
    if actions[3].button("監視データをリセット"):
        # Keep the entered target (so it need not be re-typed) and just rebaseline.
        st.session_state["live_monitor"] = {
            "cursor": 0, "events": {}, "target": target.strip(), "live": False,
            "last_error": "", "baseline_pending": True,
        }
        st.rerun()

    if refresh or state["live"]:
        try:
            base_url = normalise_base_url(target)
            added = _poll_into_state(store, base_url)
            state["last_error"] = ""
            if added < 0:
                st.caption(f"接続先 {base_url} ・ 基準点を設定しました。これ以降の攻撃だけを表示します。")
            else:
                st.caption(f"接続先 {base_url} ・ 新規 {added} 件を取り込みました。")
        except MonitorError as exc:
            state["last_error"] = str(exc)
        except (ImportDataError, OSError, sqlite3.Error) as exc:
            state["last_error"] = f"取り込みに失敗しました: {exc}"
    if state["last_error"]:
        st.warning(state["last_error"])

    results = _monitor_results(store)
    summary = summarise(
        results, threshold=threshold, window_seconds=window_minutes * 60,
        now=datetime.now(UTC),
    )

    metrics = st.columns(4)
    metrics[0].metric("監視イベント", f"{summary.total_events:,}")
    metrics[1].metric("SQLiログイン試行", f"{summary.sqli_login_attempts:,}")
    metrics[2].metric("admin' OR 1=1 -- 試行", f"{summary.tautology_attempts:,}")
    metrics[3].metric(f"失敗ログイン(直近{window_minutes}分)", f"{summary.failed_logins:,}")

    if summary.brute_force_active:
        hot = ", ".join(
            f"{s.source} ({s.failed_logins}回)" for s in summary.brute_force_sources if s.over_threshold
        )
        st.error(
            f"ブルートフォース検知: 閾値 {threshold} 回/{window_minutes}分 を超過 — {hot}",
            icon="🚨",
        )
    elif summary.failed_logins:
        st.info(f"失敗ログインを監視中（閾値 {threshold} 回/{window_minutes}分 未満）。")

    st.subheader("時間帯別アクセス")
    buckets = time_series(results, bucket_seconds=bucket_seconds)
    if buckets:
        frame = pd.DataFrame(
            {
                "総リクエスト": [b.total for b in buckets],
                "失敗ログイン": [b.failed_logins for b in buckets],
                "検知した攻撃": [b.attacks for b in buckets],
            },
            index=pd.DatetimeIndex(
                [b.start.astimezone(UTC) for b in buckets], name="time (UTC)"
            ),
        )
        st.line_chart(frame)
    else:
        st.caption("まだデータがありません。『更新』を押すか自動更新を有効にしてください。")

    if summary.brute_force_sources:
        st.subheader("送信元別の失敗ログイン（集計窓内）")
        st.dataframe(
            pd.DataFrame(
                [
                    {"Source": s.source, "失敗回数": s.failed_logins,
                     "状態": "攻撃" if s.over_threshold else "監視中"}
                    for s in summary.brute_force_sources
                ]
            ),
            hide_index=True,
            width="stretch",
        )

    attacks = [result for result in results if result.rule_findings]
    st.subheader(f"検知した攻撃イベント（{len(attacks)}件）")
    if attacks:
        attacks.sort(key=lambda r: r.event.timestamp, reverse=True)
        st.dataframe(
            pd.DataFrame([_result_row(result) for result in attacks]).drop(columns=["Event ID"]),
            hide_index=True,
            width="stretch",
        )
    else:
        st.caption("攻撃は検知されていません。")

    if state["live"]:
        time.sleep(interval)
        st.rerun()


def main() -> None:
    database_path = os.getenv("DATABASE_PATH", str(PROJECT_ROOT / "data" / "events.sqlite3"))
    try:
        store = get_store(database_path)
    except (OSError, sqlite3.Error):
        st.error("ローカルイベントDBを開けません。DATABASE_PATHとファイル権限を確認してください。")
        st.stop()

    with st.sidebar:
        st.title("RS / SIGNAL DESK")
        page = st.radio(
            "Workspace",
            ["Overview", "Live Attack Monitor", "Detection Rules"],
            label_visibility="collapsed",
        )
        st.caption("LOCAL · DEFENSIVE DEMO")

    if page == "Overview":
        _show_overview(store)
    elif page == "Live Attack Monitor":
        _show_live_monitor(store)
    else:
        _show_rules()


if __name__ == "__main__":
    main()
