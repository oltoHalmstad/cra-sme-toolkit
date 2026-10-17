from datetime import datetime, timedelta, timezone

import pytest

from crasme.reporting import (EventType, Inject, ReportingClock, TeamResponse, add_months,
                              score_tabletop)

T0 = datetime(2026, 10, 1, 8, 30, tzinfo=timezone.utc)


def test_vulnerability_deadlines():
    c = ReportingClock(EventType.EXPLOITED_VULNERABILITY, T0, corrective_measure_at=T0 + timedelta(days=5))
    d = c.deadlines()
    assert d["early_warning"] == T0 + timedelta(hours=24)
    assert d["notification"] == T0 + timedelta(hours=72)
    assert d["final_report"] == T0 + timedelta(days=19)


def test_vulnerability_final_waits_for_fix():
    d = ReportingClock(EventType.EXPLOITED_VULNERABILITY, T0).deadlines()
    assert d["final_report"] is None


def test_incident_final_one_month_after_notification():
    sent = T0 + timedelta(hours=60)
    d = ReportingClock(EventType.SEVERE_INCIDENT, T0, notification_submitted_at=sent).deadlines()
    assert d["final_report"] == datetime(2026, 11, 3, 20, 30, tzinfo=timezone.utc)


def test_incident_final_conservative_anchor_when_not_sent():
    d = ReportingClock(EventType.SEVERE_INCIDENT, T0).deadlines()
    assert d["final_report"] == add_months(T0 + timedelta(hours=72), 1)


@pytest.mark.parametrize("start,exp", [((2026, 1, 31), (2026, 2, 28)), ((2028, 1, 31), (2028, 2, 29)),
                                       ((2026, 12, 15), (2027, 1, 15))])
def test_add_months_clamps(start, exp):
    s = datetime(*start, tzinfo=timezone.utc)
    assert add_months(s, 1).date() == datetime(*exp).date()


def test_naive_timestamps_rejected():
    with pytest.raises(ValueError):
        ReportingClock(EventType.SEVERE_INCIDENT, datetime(2026, 10, 1)).deadlines()


def test_timezone_normalisation():
    cest = timezone(timedelta(hours=2))
    local = datetime(2026, 10, 1, 10, 30, tzinfo=cest)  # == 08:30Z
    assert ReportingClock(EventType.SEVERE_INCIDENT, local).deadlines()["early_warning"] == T0 + timedelta(hours=24)


def test_status_flags_late_and_overdue():
    c = ReportingClock(EventType.EXPLOITED_VULNERABILITY, T0)
    st = c.status(T0 + timedelta(hours=80), {"early_warning": T0 + timedelta(hours=25)})
    assert st["early_warning"] == "LATE"
    assert st["notification"] == "OVERDUE"
    assert st["final_report"] == "awaiting corrective measure"


def test_tabletop_scoring():
    inj = [Inject("I1", "exploited RCE", True, EventType.EXPLOITED_VULNERABILITY, T0, T0 + timedelta(days=2)),
           Inject("I2", "researcher PoC, no exploitation", False, None, T0)]
    resp = [TeamResponse("I1", True, T0 + timedelta(hours=3),
                         {"early_warning": T0 + timedelta(hours=20), "notification": T0 + timedelta(hours=75),
                          "final_report": T0 + timedelta(days=10)}, 8, 10),
            TeamResponse("I2", True, T0 + timedelta(hours=1))]
    s = score_tabletop(inj, resp)
    assert s["decision_accuracy"] == 0.5          # I2 over-reported
    assert s["stage_timeliness"] == pytest.approx(2 / 3)  # 72h notification late
    assert s["rows"][0]["completeness"] == 0.8
