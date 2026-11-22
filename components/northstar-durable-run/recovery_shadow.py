#!/usr/bin/env python3
"""northstar 恢复决策的 shadow hook —— 只记录，永不干预执行。

契约（重要）：
  * 默认关闭。仅当 env JEV_SHADOW=1 时才发起任何外部调用。
  * 全部逻辑包在 try/except 内，任何异常都不向外抛；调用在 daemon 线程中进行并带超时，
    因此**不可能**阻塞或改变 northstar 的执行结果。
  * 每个进程最多发起 JEV_SHADOW_MAX 次调用（默认 100），防止失控计费。
  * 落盘是 append-only JSONL，两种行：decision（当时规则怎么判 + 模型怎么判）、outcome（事后结果=标签）。
调用方只需：
    from recovery_shadow import record_recovery
    record_recovery(plan_digest=..., step_id=..., attempt=..., max_attempts=..., reason_code=..., rule_decision="retry_same")
"""
import json, os, sys, threading, time

_LOCK = threading.Lock()
_CALLS = 0
_APPEND_ERRORS = 0
_LOG = os.environ.get("JEV_SHADOW_LOG", "/var/minis/shared/jev-probe/shadow/recovery-shadow.jsonl")
_MAX = int(os.environ.get("JEV_SHADOW_MAX", "100"))
_TIMEOUT = float(os.environ.get("JEV_SHADOW_TIMEOUT", "25"))   # 调用方最多被阻塞的秒数
# v2：判官模块不在 northstar 的 sys.path 上，必须显式定位，否则每条记录都只剩 jev_error
_JUDGE_DIRS = [d for d in os.environ.get(
    "JEV_JUDGE_DIR", "/var/minis/shared/jev-probe").split(os.pathsep) if d]
CRITERIA = {
    "retry_same": "retry the same action on the same backend",
    "reroute": "send to a different backend/agent",
    "abandon": "stop the run and fail the plan",
    "escalate_human": "needs a human before any further attempt",
    "cannot_tell": "state insufficient to decide",
}
INSTR = "A step of this durable agent run just failed. What should the runner do next?"


def _append(obj):
    os.makedirs(os.path.dirname(_LOG), exist_ok=True)
    with open(_LOG, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, ensure_ascii=False) + "\n")


def _default_state(plan_digest, step_id, attempt, max_attempts, reason_code, extra):
    return ("northstar durable run recovery point.\n"
            "plan_digest: %s\nstep_id: %s\nattempt: %s of max_attempts=%s\n"
            "last attempt verdict: failed\nreason_code: %s\n"
            "note: this runner has no fallback backend configured and no human in the loop.\n"
            "%s" % (plan_digest, step_id, attempt, max_attempts, reason_code,
                    ("extra context: " + str(extra)) if extra else ""))


def _work(payload):
    try:
        try:
            from jev_judge import JevJudge, Decision
        except ImportError:
            for _d in _JUDGE_DIRS:                     # v2：显式把判官目录挂上 sys.path 再试一次
                if os.path.isdir(_d) and _d not in sys.path:
                    sys.path.append(_d)
            from jev_judge import JevJudge, Decision
        d = Decision("recovery", INSTR, CRITERIA)
        v = JevJudge().judge(payload["state"], [d])[0]
        payload.update(record_type="decision", jev_choice=v.choice, jev_p=(v.p if v.p is not None else None),
                       jev_confidence=v.confidence, jev_sufficient=v.sufficient,
                       jev_gate=v.gate(), jev_error=v.error, latency_s=round(v.latency, 3) if v.latency else None)
    except Exception as e:                      # 永不外抛
        payload.update(record_type="decision", jev_error="hook: %r" % (e,))
    try:
        _append(payload)
    except Exception as e:          # v2：落盘失败必须留痕，否则「没有记录」与「没有失败」无法区分
        global _APPEND_ERRORS
        _APPEND_ERRORS += 1
        if _APPEND_ERRORS <= 3:
            sys.stderr.write("[recovery_shadow] append failed (%d): %r log=%s\n"
                             % (_APPEND_ERRORS, e, _LOG))


def record_recovery(plan_digest, step_id, attempt, max_attempts, reason_code=None,
                    rule_decision="retry_same", state_text=None, extra=None):
    """记录一次恢复决策。返回 None —— 设计上就不能影响调用方。"""
    global _CALLS
    try:
        if os.environ.get("JEV_SHADOW") != "1":
            return None
        with _LOCK:
            if _CALLS >= _MAX:
                return None
            _CALLS += 1
        payload = {"ts": int(time.time()), "run_id": str(plan_digest), "step_id": str(step_id),
                   "attempt": attempt, "max_attempts": max_attempts,
                   "reason_code": reason_code, "rule_decision": rule_decision,
                   "state": state_text or _default_state(plan_digest, step_id, attempt, max_attempts, reason_code, extra)}
        t = threading.Thread(target=_work, args=(payload,), daemon=True)
        t.start(); t.join(timeout=_TIMEOUT)
    except Exception:
        pass
    return None


def record_outcome(plan_digest, step_id, outcome, detail=None):
    """事后补记结果，作为标签。outcome: recovered_after_retry / exhausted / rerouted / abandoned / human"""
    try:
        if os.environ.get("JEV_SHADOW") != "1":
            return None
        _append({"ts": int(time.time()), "record_type": "outcome", "run_id": str(plan_digest),
                 "step_id": str(step_id), "outcome": outcome, "detail": detail})
    except Exception:
        pass
    return None
