"""CRA Article 14 reporting-clock calculator and tabletop scoring (experiment E5).

Encodes the outer limits in Art. 14(2) (actively exploited vulnerabilities)
and Art. 14(4) (severe incidents). "Without undue delay" means a submission
can be late even inside the outer limit; these functions only check outer
limits. Computation of periods in EU law follows Regulation (EEC, Euratom)
No 1182/71; this helper uses simple UTC arithmetic and is a planning aid,
not legal advice.
"""
from __future__ import annotations

import calendar
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum


class EventType(str, Enum):
    EXPLOITED_VULNERABILITY = "actively_exploited_vulnerability"   # Art. 14(1)-(2)
    SEVERE_INCIDENT = "severe_incident"                             # Art. 14(3)-(4)


def _utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware (record awareness time in UTC)")
    return dt.astimezone(timezone.utc)


def add_months(dt: datetime, months: int) -> datetime:
    m = dt.month - 1 + months
    y, m = dt.year + m // 12, m % 12 + 1
    d = min(dt.day, calendar.monthrange(y, m)[1])
    return dt.replace(year=y, month=m, day=d)


@dataclass
class ReportingClock:
    event_type: EventType
    aware_at: datetime
    corrective_measure_at: datetime | None = None       # vulnerabilities: fix/mitigation available
    notification_submitted_at: datetime | None = None   # incidents: the 72h notification actually sent

    def deadlines(self) -> dict[str, datetime | None]:
        a = _utc(self.aware_at)
        out: dict[str, datetime | None] = {
            "early_warning": a + timedelta(hours=24),
            "notification": a + timedelta(hours=72),
        }
        if self.event_type is EventType.EXPLOITED_VULNERABILITY:
            out["final_report"] = (_utc(self.corrective_measure_at) + timedelta(days=14)
                                   if self.corrective_measure_at else None)
        else:
            # one month after the incident notification; if not yet sent, use the
            # 72h outer limit as the conservative anchor
            anchor = _utc(self.notification_submitted_at) if self.notification_submitted_at else out["notification"]
            out["final_report"] = add_months(anchor, 1)
        return out

    def status(self, now: datetime, submitted: dict[str, datetime] | None = None) -> dict[str, str]:
        now = _utc(now)
        submitted = {k: _utc(v) for k, v in (submitted or {}).items()}
        res = {}
        for stage, due in self.deadlines().items():
            if due is None:
                res[stage] = "awaiting corrective measure"
            elif stage in submitted:
                res[stage] = "on time" if submitted[stage] <= due else "LATE"
            elif now > due:
                res[stage] = "OVERDUE"
            else:
                hrs = (due - now).total_seconds() / 3600
                res[stage] = f"due in {hrs:.1f} h"
        return res


# ---------------------------------------------------------------------------
# Tabletop exercise scoring
# ---------------------------------------------------------------------------
@dataclass
class Inject:
    inject_id: str
    description: str
    reportable: bool                     # answer key, agreed by facilitators + legal reviewer
    event_type: EventType | None
    released_at: datetime                # when facts sufficient for awareness were given to the team
    corrective_measure_at: datetime | None = None


@dataclass
class TeamResponse:
    inject_id: str
    decided_reportable: bool
    decision_at: datetime
    submissions: dict[str, datetime] = field(default_factory=dict)
    required_fields_present: int = 0
    required_fields_total: int = 0


def score_tabletop(injects: list[Inject], responses: list[TeamResponse]) -> dict:
    """Decision accuracy, stage timeliness and draft-report completeness."""
    by_id = {r.inject_id: r for r in responses}
    rows, correct, timely, stages = [], 0, 0, 0
    for inj in injects:
        r = by_id.get(inj.inject_id)
        if r is None:
            rows.append({"inject": inj.inject_id, "decision": "missing"})
            continue
        ok = r.decided_reportable == inj.reportable
        correct += ok
        row = {"inject": inj.inject_id, "decision_correct": ok,
               "decision_latency_h": (_utc(r.decision_at) - _utc(inj.released_at)).total_seconds() / 3600}
        if inj.reportable and inj.event_type:
            clock = ReportingClock(inj.event_type, inj.released_at, inj.corrective_measure_at,
                                   r.submissions.get("notification"))
            for stage, due in clock.deadlines().items():
                if due is None:
                    continue
                stages += 1
                sub = r.submissions.get(stage)
                on_time = sub is not None and _utc(sub) <= due
                timely += on_time
                row[f"{stage}_on_time"] = on_time
                row[f"{stage}_margin_h"] = ((due - _utc(sub)).total_seconds() / 3600) if sub else None
        if r.required_fields_total:
            row["completeness"] = r.required_fields_present / r.required_fields_total
        rows.append(row)
    return {"rows": rows,
            "decision_accuracy": correct / len(injects) if injects else 0.0,
            "stage_timeliness": timely / stages if stages else None}
