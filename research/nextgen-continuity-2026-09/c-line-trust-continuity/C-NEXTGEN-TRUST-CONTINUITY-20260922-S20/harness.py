#!/usr/bin/env python3
"""Deterministic local S20 wall-clock/sequence conservative audit harness."""
import hashlib, json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent
CASES = ROOT / "fixtures" / "cases.json"
OUT = ROOT / "outputs" / "results.json"


def canon(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha(obj):
    return hashlib.sha256(canon(obj).encode("utf-8")).hexdigest()


def evaluate(case):
    events = {e["event_id"]: e for e in case["events"]}
    target_id = case["target_event_id"]
    scope_ids = case["evidence_scope"]
    scoped = [events[x] for x in scope_ids if x in events]
    ctx = case["context"]
    reasons = []
    blocks = []
    status = "UNKNOWN"
    # REJECT is deliberately reachable only via an explicitly declared invariant.
    inv = set(ctx.get("invariants", []))
    if "wall_clock_monotonic" in inv:
        walls = [e.get("wall_clock_ms") for e in scoped]
        if all(x is not None for x in walls) and any(b < a for a, b in zip(walls, walls[1:])):
            status = "REJECT"
            reasons.append("显式 wall_clock_monotonic 不变量被记录顺序中的可验证回拨违反")
            blocks.append("wall_clock_monotonic contradiction")
    if status != "REJECT" and "seq_monotonic" in inv:
        seqs = [e.get("seq") for e in scoped]
        if all(x is not None for x in seqs) and any(b <= a for a, b in zip(seqs, seqs[1:])):
            status = "REJECT"
            reasons.append("显式 seq_monotonic 不变量被记录顺序中的可验证逆序违反")
            blocks.append("seq_monotonic contradiction")
    if status != "REJECT":
        target = events.get(target_id)
        if target is None or target_id not in scope_ids:
            reasons.append("目标事件不在证据范围内")
            blocks.append("target event unavailable")
        elif any(a.get("event_id") not in events for a in scoped):
            reasons.append("证据范围含不可解析事件")
            blocks.append("unresolved event")
        elif any(x.get("event_id") in scope_ids for x in ctx.get("negative_assertions", [])):
            reasons.append("显式负断言不是可验证的不存在证明")
            blocks.append("negative assertion unproven")
        elif ctx.get("negative_assertions"):
            reasons.append("存在未被其他证据支持的显式负断言")
            blocks.append("negative assertion unproven")
        elif ctx.get("retry_count", 0) > 0:
            reasons.append("重试不构成新的独立时间/序号证据，保守保持 UNKNOWN")
            blocks.append("retry is non-independent")
        elif ctx.get("clock_source") is None:
            reasons.append("缺少权威时钟源声明，时间证据降权")
            blocks.append("authoritative clock source missing")
        elif target.get("wall_clock_ms") is None:
            reasons.append("目标事件缺失 wall-clock 时间戳")
            blocks.append("wall-clock unavailable")
        elif target.get("seq") is None:
            reasons.append("目标事件缺失逻辑序号")
            blocks.append("logical sequence unavailable")
        else:
            offset = abs(target["wall_clock_ms"] - ctx["reference_wall_clock_ms"])
            if offset > ctx["offset_limit_ms"]:
                reasons.append("目标时间偏移超过允许边界")
                blocks.append("offset exceeds inclusive limit")
            elif len(scoped) > 1:
                walls = [e.get("wall_clock_ms") for e in scoped]
                seqs = [e.get("seq") for e in scoped]
                if any(x is None for x in walls) or any(x is None for x in seqs):
                    reasons.append("双轴证据不完整")
                    blocks.append("incomplete clock_seq evidence")
                elif len(set(walls)) < len(walls) and len(set(seqs)) > 1:
                    reasons.append("同墙钟不同 seq 无法用 wall-clock 区分先后")
                    blocks.append("co-timestamp ordering ambiguity")
                elif any((b > a) != (d > c) for a, b, c, d in zip(walls, walls[1:], seqs, seqs[1:])):
                    reasons.append("wall-clock 与 seq 顺序冲突；不默认任一轴权威")
                    blocks.append("dual-axis ordering conflict")
                elif any(b < a for a, b in zip(walls, walls[1:])):
                    reasons.append("后一记录 wall-clock 早于前一记录；未声明单调不变量")
                    blocks.append("clock rollback without explicit invariant")
                elif any(b <= a for a, b in zip(seqs, seqs[1:])):
                    reasons.append("seq 未严格递增，轴间顺序不可确认")
                    blocks.append("sequence ordering ambiguity")
                elif any(b - a != 1 for a, b in zip(seqs, seqs[1:])):
                    reasons.append("seq 存在空洞，连续墙钟不可补全缺失序号")
                    blocks.append("sequence hole")
                else:
                    status = "RECOVERED"
                    reasons.append("权威时钟源、双轴完整且在含边界内，目标事件证据一致")
            else:
                status = "RECOVERED"
                reasons.append("权威时钟源、双轴完整且在含边界内，目标事件证据一致")
    if not reasons:
        reasons.append("保守规则未形成可判定证据")
        blocks.append("insufficient evidence")
    if status != case["expected_status"]:
        raise AssertionError(f'{case["fixture_id"]}: got {status}, expected {case["expected_status"]}')
    evidence = {
        "target": {"event_id": target_id, "wall_clock_ms": events.get(target_id, {}).get("wall_clock_ms"), "seq": events.get(target_id, {}).get("seq")},
        "scope": [{"event_id": e.get("event_id"), "wall_clock_ms": e.get("wall_clock_ms"), "seq": e.get("seq")} for e in scoped],
        "clock_source": ctx.get("clock_source"),
        "reference_wall_clock_ms": ctx.get("reference_wall_clock_ms"),
        "offset_limit_ms": ctx.get("offset_limit_ms")
    }
    return {
        "fixture_id": case["fixture_id"], "status": status,
        "clock_seq_evidence": evidence, "reason": reasons,
        "blocking_conditions": blocks, "canonical_input_sha256": sha(case)
    }


def main():
    data = json.loads(CASES.read_text(encoding="utf-8"))
    results = [evaluate(c) for c in data["cases"]]
    payload = {
        "schema_version": "s20-results-v1", "synthetic_only": True,
        "production_verified": False, "fixture_count": len(results),
        "status_counts": {s: sum(r["status"] == s for r in results) for s in ("RECOVERED", "UNKNOWN", "REJECT")},
        "results": results
    }
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(f"PASS: harness evaluated {len(results)} fixtures")
    print("PASS: statuses " + ", ".join(f"{s}={payload['status_counts'][s]}" for s in ("RECOVERED", "UNKNOWN", "REJECT")))
    print(f"PASS: wrote {OUT}")

if __name__ == "__main__":
    main()
