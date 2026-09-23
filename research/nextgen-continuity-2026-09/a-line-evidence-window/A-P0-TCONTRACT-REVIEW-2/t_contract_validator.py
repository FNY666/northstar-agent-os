#!/usr/bin/env python3
"""Tree-external, standard-library-only P0-1 contract/schema rehearsal.
This module is a pure validator: it never calls a service or performs an effect.
"""
from __future__ import annotations
import argparse, datetime as dt, hashlib, hmac, json, math, os, sys, unicodedata
from pathlib import Path
from typing import Any

SCHEMA = "p0-1.execution-contract/t-contract-0"
MAX_INT = 10**18
ALLOWED_VERDICTS = {"verified", "failed", "unknown", "invalid"}
TOP_FIELDS = {"schema_version","run","operation","decision","execution","observation","postconditions","effect","receipt","expected","trusted_binding","dedupe"}
FIELDS = {
 "run": {"task_id","run_id","idempotency_key","operation_fingerprint","artifact_owner","artifact_identity","read_at","attempt"},
 "operation": {"operation_id","kind","target","args"},
 "decision": {"status","policy_id","authority","decided_at"},
 "execution": {"status","operation_id","idempotency_key","started_at","ended_at"},
 "observation": {"status","source","channel","read_at","groundtruth_health","raw_ref"},
 "postcondition": {"name","status","source","channel","read_at","evidence_strength","evidence_id"},
 "effect": {"status","reason","source","read_at"},
 "receipt": {"run_id","operation_id","status","read_at","producer"},
 "trusted_binding": {"run_id","operation_id","operation_fingerprint","operation","decision","owner","identity","read_at","expiry","policy_revision","signature"},
}
EXECUTION_STATUSES = {"not_started","started","succeeded","failed","timeout","cancelled"}
OBSERVATION_STATUSES = {"returned","error","missing","timeout","cancelled"}
POSTCONDITION_STATUSES = {"verified","failed","unknown"}
RECEIPT_STATUSES = {"ok","accepted","started","rejected","business_error","timeout","cancelled","transport_unavailable","internal_error","protocol_error"}
# Deliberately test-only and local. It is not a production trust root.
AUTHORITY_KEY = b"T-CONTRACT-0-PROTOTYPE-only-authority-key"

class DuplicateKey(ValueError): pass
class CanonicalizationError(ValueError): pass


def _pairs(pairs):
    out, nfc = {}, {}
    for key, value in pairs:
        if key in out:
            raise DuplicateKey("duplicate JSON key: " + key)
        nk = unicodedata.normalize("NFC", key)
        if nk in nfc:
            raise CanonicalizationError("NFC key collision: " + nk)
        nfc[nk] = key
        out[key] = value
    return out


def strict_load(text_or_path: Any) -> Any:
    # Accept Path objects and existing relative/absolute paths; otherwise treat
    # the value as JSON text. This keeps the offline CLI and in-process caller
    # semantics aligned without touching any tree or service.
    if isinstance(text_or_path, Path):
        text = text_or_path.read_text(encoding="utf-8")
    elif isinstance(text_or_path, str):
        candidate = Path(text_or_path)
        if candidate.exists() and candidate.is_file():
            text = candidate.read_text(encoding="utf-8")
        else:
            text = text_or_path
    else:
        text = text_or_path
    if not isinstance(text, str):
        raise TypeError("strict_load requires JSON text or a file path")
    return json.loads(text, object_pairs_hook=_pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError("non-finite JSON constant: " + x)))


def _norm(value: Any) -> Any:
    if isinstance(value, str): return unicodedata.normalize("NFC", value)
    if value is None or isinstance(value, bool): return value
    if isinstance(value, int):
        if abs(value) > MAX_INT: raise CanonicalizationError("integer outside finite canonical bound")
        return value
    if isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer() or abs(value) > MAX_INT:
            raise CanonicalizationError("canonical numbers must be finite integers")
        return int(value)
    if isinstance(value, list): return [_norm(x) for x in value]
    if isinstance(value, dict):
        result, seen = {}, set()
        for key, item in value.items():
            nk = unicodedata.normalize("NFC", str(key))
            if nk in seen: raise CanonicalizationError("NFC key collision: " + nk)
            seen.add(nk); result[nk] = _norm(item)
        return {key: result[key] for key in sorted(result)}
    raise CanonicalizationError("unsupported value type")


def canonical(value: Any) -> bytes:
    return json.dumps(_norm(value), ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value: Any) -> str: return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _text(x: Any) -> bool: return isinstance(x, str) and bool(x.strip())


def parse_time(x: Any):
    if not _text(x) or not x.endswith("Z") or len(x) != 20: return None
    try:
        z = dt.datetime.strptime(x, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
        return z if 2000 <= z.year <= 2099 else None
    except (TypeError, ValueError): return None


def _error(errors, msg): errors.append(msg)


def _unknown_fields(obj, allowed, label, errors):
    if not isinstance(obj, dict): _error(errors, label + " object required"); return
    for key in obj:
        if key not in allowed: _error(errors, label + " unknown field " + str(key))


def _required(obj, allowed, label, errors):
    _unknown_fields(obj, allowed, label, errors)
    if isinstance(obj, dict):
        for key in allowed:
            if key not in obj: _error(errors, label + "." + key + " missing")


def _required_present(obj, keys, label, errors):
    if isinstance(obj, dict):
        for key in keys:
            if key not in obj: _error(errors, label + "." + key + " missing")


def _required_text(obj, keys, label, errors):
    if not isinstance(obj, dict): return
    for key in keys:
        if not _text(obj.get(key)): _error(errors, label + "." + key + " must be nonempty string")


def _raw_ref(x):
    prefix = "evidence://sha256/"
    if not _text(x) or ".." in x or "\\" in x or x.startswith("/"): return False
    if not x.startswith(prefix) or len(x) != len(prefix) + 64: return False
    digest = x[len(prefix):]
    return all(c in "0123456789abcdef" for c in digest)


def _binding_payload(obj):
    # Keep this helper total over untrusted/malformed objects.  validate() may
    # call it only after structural checks, but direct callers must not turn a
    # boundary defect into KeyError.
    run = obj.get("run") if isinstance(obj, dict) and isinstance(obj.get("run"), dict) else {}
    op = obj.get("operation") if isinstance(obj, dict) and isinstance(obj.get("operation"), dict) else {}
    dec = obj.get("decision") if isinstance(obj, dict) and isinstance(obj.get("decision"), dict) else {}
    b = obj.get("trusted_binding") if isinstance(obj, dict) and isinstance(obj.get("trusted_binding"), dict) else {}
    return {"run": {k: run.get(k) for k in ("task_id","run_id","idempotency_key","attempt")},
            "operation": op,
            "decision": {k: dec.get(k) for k in ("status","policy_id","authority","decided_at")},
            "owner": run.get("artifact_owner"), "identity": run.get("artifact_identity"),
            "read_at": run.get("read_at"), "expiry": b.get("expiry"), "policy_revision": b.get("policy_revision")}


def binding_signature(obj) -> str:
    return hmac.new(AUTHORITY_KEY, canonical(_binding_payload(obj)), hashlib.sha256).hexdigest()


def operation_fingerprint(operation) -> str: return digest(operation)


def _projection(obj):
    return {"decision": obj.get("decision"), "execution": obj.get("execution"),
            "observation": obj.get("observation"), "postconditions": obj.get("postconditions"),
            "effect": obj.get("effect"), "receipt": obj.get("receipt")}


def validate(obj: Any, trusted_now: str = "2026-09-20T22:00:00Z", registry=None) -> dict:
    """Return structured result; never raises for untrusted input."""
    errors, warnings, trace = [], [], []
    result = {"valid": False, "verdict": "invalid", "expected": None, "match": False,
              "errors": errors, "warnings": warnings, "state_trace": trace,
              "projection": {}, "replay": {"action":"none", "side_effect_replayed":False}}
    try:
        # Programmatic objects are canonicalized here, catching NFC and numeric hazards.
        canonical(obj)
    except Exception as exc:
        errors.append(type(exc).__name__ + ": " + str(exc)); return result
    if not isinstance(obj, dict): errors.append("top-level object required"); return result
    result["expected"] = obj.get("expected")
    result["match"] = obj.get("expected") in ALLOWED_VERDICTS  # updated after verdict
    _unknown_fields(obj, TOP_FIELDS, "top", errors)
    # trusted_binding is optional: its absence is an epistemic gap (unknown),
    # while a present non-object is a structural defect (invalid).
    for field in TOP_FIELDS - {"dedupe", "trusted_binding"}:
        if field not in obj: _error(errors, "top." + field + " missing")
    if "trusted_binding" in obj and not isinstance(obj.get("trusted_binding"), dict):
        _error(errors, "trusted_binding object required")
    if obj.get("schema_version") != SCHEMA: _error(errors, "schema_version mismatch")
    if obj.get("expected") not in ALLOWED_VERDICTS: _error(errors, "expected must be a verdict")
    sections = {k: obj.get(k) if isinstance(obj.get(k), dict) else {} for k in ("run","operation","decision","execution","observation","effect","receipt","trusted_binding")}
    for name, section in sections.items():
        if name == "trusted_binding" and "trusted_binding" not in obj:
            # Missing binding is an epistemic gap: it can never establish verified.
            continue
        if name == "execution":
            _unknown_fields(section, FIELDS[name], name, errors)
            _required_present(section, FIELDS[name] - {"ended_at"}, name, errors)
        elif name == "observation":
            _unknown_fields(section, FIELDS[name], name, errors)
            _required_present(section, FIELDS[name] - {"groundtruth_health", "raw_ref"}, name, errors)
        else:
            _required(section, FIELDS[name], name, errors)
    pcs = obj.get("postconditions")
    if not isinstance(pcs, list): _error(errors, "postconditions list required"); pcs = []
    for i, pc in enumerate(pcs): _required(pc, FIELDS["postcondition"], "postconditions[%d]" % i, errors)
    run, op, dec, ex, ob, effect, rec, bind = (sections[x] for x in ("run","operation","decision","execution","observation","effect","receipt","trusted_binding"))
    _required_text(run, FIELDS["run"] - {"attempt"}, "run", errors)
    _required_text(op, {"operation_id","kind","target"}, "operation", errors)
    _required_text(dec, {"policy_id","authority","decided_at"}, "decision", errors)
    if not isinstance(op.get("args"), dict): _error(errors, "operation.args object required")
    if not isinstance(run.get("attempt"), int) or isinstance(run.get("attempt"), bool) or not 1 <= run.get("attempt", 0) <= 1000000: _error(errors, "run.attempt invalid")
    if dec.get("status") != "accepted": _error(errors, "decision not accepted")
    now, run_time, decision_time = parse_time(trusted_now), parse_time(run.get("read_at")), parse_time(dec.get("decided_at"))
    if now is None: _error(errors, "trusted_now invalid")
    if run_time is None or decision_time is None: _error(errors, "run/decision time invalid")
    if now and (run_time > now or (now-run_time).total_seconds() > 3600): _error(errors, "run outside time window")
    try: actual_fp = operation_fingerprint(op)
    except Exception as exc: actual_fp = None; _error(errors, "canonical operation invalid: " + str(exc))
    if actual_fp != run.get("operation_fingerprint"): _error(errors, "operation fingerprint mismatch")
    # Binding absence/tampering is an epistemic failure, not evidence of a failed effect.
    binding_ok = True
    if not isinstance(bind, dict): binding_ok = False
    else:
        if not hmac.compare_digest(str(bind.get("signature", "")), binding_signature(obj)): binding_ok = False
        if bind.get("operation") != op or bind.get("decision") != dec or bind.get("run_id") != run.get("run_id") or bind.get("operation_id") != op.get("operation_id"): binding_ok = False
        if any(bind.get(a) != run.get(b) for a,b in (("owner","artifact_owner"),("identity","artifact_identity"),("read_at","read_at"))): binding_ok = False
        br, be = parse_time(bind.get("read_at")), parse_time(bind.get("expiry"))
        if br is None or be is None or (now and (be < now or be < br or (be-br).total_seconds() > 3600)): binding_ok = False
    if not binding_ok: warnings.append("trusted binding missing or not authenticated")
    _required_text(ex, {"operation_id","idempotency_key","started_at"}, "execution", errors)
    if ex.get("status") not in EXECUTION_STATUSES: _error(errors, "execution status invalid")
    if ex.get("status") in {"succeeded","failed","timeout","cancelled"} and not _text(ex.get("ended_at")): _error(errors, "execution ended_at missing")
    if ex.get("status") in {"not_started","started"} and ex.get("ended_at") is not None: _error(errors, "execution ended_at forbidden")
    if ex.get("operation_id") != op.get("operation_id") or ex.get("idempotency_key") != run.get("idempotency_key"): _error(errors, "execution identity mismatch")
    _required_text(ob, {"source","channel","read_at"}, "observation", errors)
    if ob.get("status") not in OBSERVATION_STATUSES: _error(errors, "observation status invalid")
    if ob.get("status") == "returned":
        # A returned observation without healthy groundtruth is insufficient
        # evidence (unknown), not malformed input.  A healthy return must carry
        # a syntactically valid opaque content-addressed reference.
        if ob.get("groundtruth_health") == "healthy" and not _raw_ref(ob.get("raw_ref")):
            _error(errors, "observation raw_ref invalid")
    if ob.get("status") != "returned" and ob.get("raw_ref") is not None: _error(errors, "raw_ref forbidden on nonreturned observation")
    if not pcs: warnings.append("empty postconditions: effect cannot be verified")
    names, evidence_ids = set(), set()
    for i, pc in enumerate(pcs):
        if not isinstance(pc, dict): continue
        _required_text(pc, {"name","source","channel","read_at","evidence_id"}, "postconditions[%d]" % i, errors)
        if pc.get("status") not in POSTCONDITION_STATUSES: _error(errors, "postconditions[%d] status invalid" % i)
        if pc.get("name") in names or pc.get("evidence_id") in evidence_ids: _error(errors, "postcondition identity duplicate")
        names.add(pc.get("name")); evidence_ids.add(pc.get("evidence_id"))
    _required_text(effect, {"reason","source","read_at"}, "effect", errors)
    if effect.get("status") not in POSTCONDITION_STATUSES: _error(errors, "effect status invalid")
    _required_text(rec, {"run_id","operation_id","read_at","producer"}, "receipt", errors)
    if rec.get("status") not in RECEIPT_STATUSES: _error(errors, "receipt status invalid")
    if rec.get("run_id") != run.get("run_id") or rec.get("operation_id") != op.get("operation_id"): _error(errors, "receipt identity mismatch")
    # All observations and evidence in this rehearsal have explicit independent channels.
    if ob.get("source") != "observer-A" or ob.get("channel") != "observe-A": warnings.append("observation producer is not the rehearsal trusted channel")
    if effect.get("source") != "effect-A": warnings.append("effect producer is not the rehearsal trusted channel")
    if rec.get("producer") != "receipt-A": warnings.append("receipt producer is not the rehearsal trusted channel")
    for pc in pcs:
        if isinstance(pc, dict) and (pc.get("source") != "pc-A" or pc.get("channel") != "pc-A"): warnings.append("postcondition producer is not the rehearsal trusted channel")
    times = [decision_time, parse_time(ex.get("started_at"))]
    if ex.get("ended_at") is not None:
        times.append(parse_time(ex.get("ended_at")))
    times.append(parse_time(ob.get("read_at")))
    times += [parse_time(p.get("read_at")) for p in pcs if isinstance(p, dict)] + [parse_time(effect.get("read_at")), parse_time(rec.get("read_at"))]
    if any(x is None for x in times): _error(errors, "event time invalid")
    for a,b in zip(times, times[1:]):
        if a and b and a > b: _error(errors, "event order reversed")
    if now and any(x and x > now for x in times): _error(errors, "future event")
    trace += ["decision." + str(dec.get("status")), "execution." + str(ex.get("status")), "observation." + str(ob.get("status")), "postcondition.evaluate"]
    observed = ob.get("status") == "returned" and ob.get("groundtruth_health") == "healthy" and _raw_ref(ob.get("raw_ref"))
    pc_statuses = [p.get("status") for p in pcs if isinstance(p, dict)]
    if ex.get("status") in {"failed","timeout","cancelled"} or effect.get("status") == "failed" or "failed" in pc_statuses or rec.get("status") in {"rejected","business_error","timeout","cancelled"}: computed = "failed"
    elif ex.get("status") in {"not_started","started"}: computed = "unknown"
    elif not observed or not pcs or effect.get("status") != "verified" or rec.get("status") != "ok" or not pc_statuses or any(x != "verified" for x in pc_statuses): computed = "unknown"
    else: computed = "verified"
    trace += ["effect." + computed, "receipt." + str(rec.get("status"))]
    result["projection"] = _projection(obj)
    # Structural/schema errors are invalid. Binding and missing evidence are unknown.
    if errors:
        result["verdict"] = "invalid"
    elif not binding_ok:
        result["verdict"] = "unknown"
    else:
        result["verdict"] = computed
    result["valid"] = result["verdict"] != "invalid"
    result["match"] = result["expected"] == result["verdict"]
    if registry is not None:
        key, fp = run.get("idempotency_key"), run.get("operation_fingerprint")
        old = registry.get(key)
        if old is not None:
            if old != fp:
                result["verdict"] = "invalid"; result["valid"] = False; result["match"] = result["expected"] == "invalid"
                errors.append("idempotency key bound to different operation fingerprint")
                result["replay"] = {"action":"reject", "side_effect_replayed":False}
            else:
                result["replay"] = {"action":"deduplicate", "side_effect_replayed":False}
        elif result["verdict"] in {"verified","failed","unknown"}:
            registry[key] = fp
    return result


def validate_json(text_or_path, **kwargs):
    try: return validate(strict_load(text_or_path), **kwargs)
    except Exception as exc:
        return {"valid":False,"verdict":"invalid","expected":None,"match":False,"errors":[type(exc).__name__+": "+str(exc)],"warnings":[],"state_trace":[],"projection":{},"replay":{"action":"none","side_effect_replayed":False}}


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("fixture"); ap.add_argument("--now", default="2026-09-20T22:00:00Z")
    args = ap.parse_args(argv); out = validate_json(args.fixture, trusted_now=args.now); print(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2)); return 0 if out["match"] else 1
if __name__ == "__main__": raise SystemExit(main())
