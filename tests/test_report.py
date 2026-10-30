import json
import re

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from bastion.config import StatePaths
from bastion.errors import BastionError
from bastion.eventlog import EventLog
from bastion.events import Event
from bastion.report import (
    analyze_state,
    assess_health,
    choose_bucket,
    overall_ok,
    render_html,
    render_markdown,
    write_report,
)

NOW = 1_800_000_000.0
XSS = '<script>alert(1)</script>'


def alert_data(rule="entropy_spike", severity="high", ts=NOW - 100, path="a.txt", title="Title"):
    return {"time": "t", "ts": ts, "rule": rule, "severity": severity, "title": title,
            "explanation": "expl", "benign_causes": "benign", "suggestion": "do x", "threshold": 5,
            "observed": 6, "window_seconds": 10, "total_related": 1,
            "events": [Event("modified", path, ts, entropy=7.9).to_dict()], "disclaimer": "d"}


@pytest.fixture
def state(tmp_path):
    return StatePaths(tmp_path / "state")


def build(state, *, alerts=(), events=(), system=()):
    state.ensure()
    log = EventLog(state.log)
    for ts, data in system:
        log.append("system", data, ts=ts)
    for ev in events:
        log.append("event", ev.to_dict(), ts=ev.ts)
    for a in alerts:
        log.append("alert", a, ts=a["ts"])
    return log


def start(ts):
    return ts, {"action": "monitor_start"}


def stop(ts):
    return ts, {"action": "monitor_stop"}


# --- analysis -----------------------------------------------------------------------------

def test_counts_top_dirs_and_timeline(state):
    events = [Event("modified", f"docs/f{i}.txt", NOW + i) for i in range(6)] + \
             [Event("deleted", "other/x.txt", NOW + 70), Event("moved", "a.txt", NOW + 71, dest_path="docs/a.txt")]
    build(state, events=events, alerts=[alert_data(ts=NOW + 72)])
    a = analyze_state(state, now=NOW + 100)
    assert a.event_counts == {"modified": 6, "deleted": 1, "moved": 1}
    assert a.top_dirs[0] == ("docs", 7) and a.total_events == 8
    assert a.severity_counts["high"] == 1 and a.rule_counts == {"entropy_spike": 1}
    assert a.timeline and sum(a.timeline.events) == 8 and sum(a.timeline.alerts) == 1
    assert a.log_check.ok


def test_sessions_and_coverage_gaps(state):
    build(state, system=[start(NOW), stop(NOW + 100),            # clean session
                         start(NOW + 400), start(NOW + 900),     # second one never stopped
                         stop(NOW + 1000)])
    a = analyze_state(state, now=NOW + 2000)
    assert [s.ended_cleanly for s in a.sessions] == [True, False, True]
    assert len(a.gaps) == 2
    assert a.gaps[0].seconds == 300 and a.gaps[0].after_unclean_stop is False
    assert a.gaps[1].after_unclean_stop is True


def test_alerts_are_attributed_to_sessions(state):
    build(state, system=[start(NOW), stop(NOW + 100)], alerts=[alert_data(ts=NOW + 50), alert_data(ts=NOW + 500)])
    assert analyze_state(state, now=NOW + 600).sessions[0].alerts == 1


def test_analyze_never_modifies_state(state):
    build(state, events=[Event("modified", "a.txt", NOW)])
    before = state.log.read_bytes()
    analyze_state(state, now=NOW)
    assert state.log.read_bytes() == before and not state.checkpoints.exists()


def test_missing_log_is_an_empty_analysis(state):
    state.ensure()
    a = analyze_state(state, now=NOW)
    assert a.total_events == 0 and a.timeline is None and a.log_check.ok


@pytest.mark.parametrize("span", [0, 1, 59, 60, 61, 3599, 86400, 10 ** 7])
def test_choose_bucket_keeps_at_most_60_bars_when_possible(span):
    size = choose_bucket(span)
    assert span / size <= 60 or size == 86400


# --- health -----------------------------------------------------------------------------------

def levels(findings):
    return {f.level for f in findings}


def test_broken_chain_is_blocking(state):
    build(state, events=[Event("modified", "a.txt", NOW), Event("modified", "b.txt", NOW + 1)])
    lines = state.log.read_text().splitlines()
    state.log.write_text("\n".join(lines[:1] + ['{"seq": 2}']) + "\n")
    findings = assess_health(analyze_state(state, now=NOW + 5))
    assert not overall_ok(findings) and any("BROKEN" in f.text for f in findings)


def test_recent_high_alert_is_blocking_but_old_one_is_not(state):
    build(state, alerts=[alert_data(ts=NOW - 100)], system=[start(NOW - 200)])
    assert not overall_ok(assess_health(analyze_state(state, now=NOW)))
    findings = assess_health(analyze_state(state, now=NOW + 3 * 86400))
    assert overall_ok(findings)


def test_missing_protections_are_warnings_not_failures(state):
    build(state, events=[Event("modified", "a.txt", NOW)])
    findings = assess_health(analyze_state(state, now=NOW + 10))
    text = " ".join(f.text for f in findings)
    assert overall_ok(findings) and "baseline" in text.lower() and "canary" in text.lower() \
        and "checkpoint" in text.lower() and "never run" in text


def test_unclean_monitor_stop_is_flagged(state):
    build(state, system=[start(NOW), start(NOW + 50), stop(NOW + 60)])
    findings = assess_health(analyze_state(state, now=NOW + 100))
    assert any("without a clean stop" in f.text for f in findings)


# --- rendering -----------------------------------------------------------------------------------

def evil_state(state):
    build(state,
          events=[Event("created", f'{XSS}/"><img src=x onerror=alert(1)>/file.txt', NOW)],
          alerts=[alert_data(title=XSS, path=f"{XSS}.txt")],
          system=[start(NOW - 5)])
    return analyze_state(state, now=NOW + 5)


def test_html_escapes_everything_that_comes_from_the_log(state):
    page = render_html(evil_state(state))
    assert "<script" not in page.lower()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "<img" not in page                      # the injected tag stayed inert text
    assert "&lt;img" in page


def test_html_is_self_contained(state):
    page = render_html(evil_state(state))
    assert "Content-Security-Policy" in page and "default-src 'none'" in page
    assert not re.search(r"<script|<link|<iframe|src=['\"]https?:|href=['\"]https?:", page, re.I)
    assert "http://" not in page and "https://" not in page


def test_html_contains_the_honest_limits(state):
    build(state, events=[Event("modified", "a.txt", NOW)])
    page = render_html(analyze_state(state, now=NOW))
    assert "does not prove malicious activity" in page and "cannot tell you" in page


def test_markdown_escapes_table_breaking_characters(state):
    build(state, events=[Event("created", "a|b`c\nd/x.txt", NOW)])
    md = render_markdown(analyze_state(state, now=NOW))
    row = next(line for line in md.splitlines() if line.startswith("| a"))
    assert row.count("|") - row.count("\\|") == 3 and "`" not in row


def test_report_shows_failed_checkpoint(state):
    build(state, events=[Event("modified", "a.txt", NOW)])
    from bastion.report import CheckpointStatus
    a = analyze_state(state, now=NOW)
    a.checkpoints = [CheckpointStatus("2026-01-01T00:00:00+00:00", 3, "k" * 32, False, "rewritten")]
    page = render_html(a)
    assert "FAILED" in page and "do NOT verify" in page


def test_json_export_is_valid_and_complete(state):
    build(state, events=[Event("modified", "a.txt", NOW)], alerts=[alert_data()])
    data = analyze_state(state, now=NOW + 1).to_dict()
    again = json.loads(json.dumps(data))
    assert again["log"]["ok"] and again["alerts"] and again["event_counts"] == {"modified": 1}


def test_write_report_never_overwrites(tmp_path):
    target = tmp_path / "out" / "r.html"
    write_report(target, "one")
    with pytest.raises(BastionError, match="never overwritten"):
        write_report(target, "two")
    assert target.read_text() == "one"


@settings(max_examples=40, deadline=None)
@given(st.text(max_size=60), st.text(max_size=60))
def test_arbitrary_text_never_becomes_markup(title, path):
    from bastion.eventlog import LogVerification
    from bastion.report import Analysis
    a = Analysis(generated_at=NOW, state_dir=title, log_check=LogVerification(True, 1, "0" * 64))
    a.alerts = [alert_data(title=title, path=path)]
    a.top_dirs = [(path, 1)]
    page = render_html(a)
    body = page.split("</style>", 1)[1]
    assert "<script" not in body.lower()
    assert not re.search(r"<(img|iframe|svg onload|object|embed)", body.replace("<svg viewBox", ""), re.I)
