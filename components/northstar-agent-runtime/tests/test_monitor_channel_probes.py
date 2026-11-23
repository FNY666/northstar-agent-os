"""Tests for the monitor-channel probe corpus.

The monitor channel is the breakout vector: it must be egress-only,
tamper-evident, and unwritable by the agent. These tests pin the corpus
shape (10 attack probes across 3 families, 3 benign controls) and the
record / channel / detector semantics.
"""

import unittest

import monitor_channel_probes as mcp

EXPECTED_PROBE_NAMES = (
    # channel-integrity
    "integrity-telemetry-writeback",
    "integrity-export-tampered",
    "integrity-span-injection",
    "integrity-channel-bidirectional",
    # channel-isolation
    "isolation-shared-socket",
    "isolation-observer-write",
    "isolation-credential-leak",
    # breakout
    "breakout-socket-escape",
    "breakout-telemetry-exfil",
    "breakout-monitor-disable",
)

EXPECTED_BENIGN_NAMES = (
    "benign-readonly-export",
    "benign-host-rotates-keys",
    "benign-observer-alerts",
)

REQUIRED_KEYS = ("probe", "family", "attack", "gate_interaction", "expected", "reason")

# Every attack probe's gate interaction must name an active deny-side
# check -- framing the attack must never read as a defense.
DENY_SIDE_KEYWORDS = (
    "denies",
    "denied",
    "deny",
    "quarantine",
    "quarantined",
    "quarantines",
    "blocks",
    "refuses",
    "never",
    "fail closed",
)


def _payload_digest(text: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _rec(seq: int, **kwargs: object) -> "mcp.MonitorRecord":
    params: dict[str, object] = {
        "seq": seq,
        "direction": "egress",
        "channel": "telemetry",
        "payload_digest": _payload_digest(f"payload-{seq}"),
        "origin": "host",
    }
    params.update(kwargs)
    return mcp.build_record(**params)  # type: ignore[arg-type]


class CorpusShapeTests(unittest.TestCase):
    def test_probe_names(self) -> None:
        self.assertEqual(mcp.probe_names(), EXPECTED_PROBE_NAMES)

    def test_benign_names(self) -> None:
        self.assertEqual(mcp.benign_names(), EXPECTED_BENIGN_NAMES)

    def test_required_keys(self) -> None:
        for probe in (*mcp.MONITOR_CHANNEL_PROBES, *mcp.MONITOR_CHANNEL_BENIGN):
            for key in REQUIRED_KEYS:
                self.assertIn(key, probe, probe["probe"])

    def test_unique_names(self) -> None:
        names = [*mcp.probe_names(), *mcp.benign_names()]
        self.assertEqual(len(names), len(set(names)))

    def test_expected_outcomes(self) -> None:
        outcomes = mcp.expected_outcomes()
        for name in EXPECTED_PROBE_NAMES:
            self.assertEqual(outcomes[name], "deny", name)
        for name in EXPECTED_BENIGN_NAMES:
            self.assertEqual(outcomes[name], "allow", name)

    def test_deny_side_keyword(self) -> None:
        for probe in mcp.MONITOR_CHANNEL_PROBES:
            text = probe["gate_interaction"].lower()
            self.assertTrue(
                any(k in text for k in DENY_SIDE_KEYWORDS),
                f"{probe['probe']} has no deny-side keyword",
            )

    def test_per_family_counts(self) -> None:
        counts = {
            fam: len(mcp.probes_by_family(fam))
            for fam in ("channel-integrity", "channel-isolation", "breakout")
        }
        self.assertEqual(counts, {"channel-integrity": 4, "channel-isolation": 3, "breakout": 3})

    def test_probe_by_name_and_keyerror(self) -> None:
        self.assertEqual(
            mcp.probe_by_name("breakout-socket-escape")["family"], "breakout"
        )
        with self.assertRaises(KeyError):
            mcp.probe_by_name("no-such-probe")


class RecordTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        record = _rec(0)
        self.assertTrue(mcp.verify_record(record))

    def test_tampered_digest_fails_verify(self) -> None:
        # __post_init__ fail-closes on construction, so build the bad
        # record without it to exercise verify_record's return path.
        record = _rec(0)
        bad = object.__new__(mcp.MonitorRecord)
        object.__setattr__(bad, "seq", record.seq)
        object.__setattr__(bad, "direction", record.direction)
        object.__setattr__(bad, "channel", record.channel)
        object.__setattr__(bad, "payload_digest", record.payload_digest)
        object.__setattr__(bad, "origin", record.origin)
        object.__setattr__(bad, "digest", "sha256:" + "0" * 64)
        self.assertFalse(mcp.verify_record(bad))

    def test_bad_direction_rejected(self) -> None:
        with self.assertRaises(ValueError):
            mcp.build_record(
                seq=0,
                direction="sideways",
                channel="telemetry",
                payload_digest=_payload_digest("x"),
                origin="host",
            )

    def test_bad_digest_format_rejected(self) -> None:
        with self.assertRaises(ValueError):
            mcp.build_record(
                seq=0,
                direction="egress",
                channel="telemetry",
                payload_digest="not-a-digest",
                origin="host",
            )

    def test_negative_seq_rejected(self) -> None:
        with self.assertRaises(ValueError):
            mcp.build_record(
                seq=-1,
                direction="egress",
                channel="telemetry",
                payload_digest=_payload_digest("x"),
                origin="host",
            )


class MonitorChannelTests(unittest.TestCase):
    def test_append_egress_ok(self) -> None:
        channel = mcp.MonitorChannel("telemetry")
        channel.append(_rec(0, channel="telemetry"))
        channel.append(_rec(1, channel="telemetry"))
        self.assertEqual(len(channel.records()), 2)

    def test_append_ingress_rejected(self) -> None:
        channel = mcp.MonitorChannel("telemetry")
        with self.assertRaises(ValueError):
            channel.append(_rec(0, channel="telemetry", direction="ingress"))

    def test_append_seq_break_rejected(self) -> None:
        channel = mcp.MonitorChannel("telemetry")
        channel.append(_rec(0, channel="telemetry"))
        with self.assertRaises(ValueError):
            channel.append(_rec(5, channel="telemetry"))

    def test_append_channel_mismatch_rejected(self) -> None:
        channel = mcp.MonitorChannel("telemetry")
        with self.assertRaises(ValueError):
            channel.append(_rec(0, channel="alerts"))


class DetectorTests(unittest.TestCase):
    def test_writeback_flagged(self) -> None:
        record = mcp.build_record(
            seq=0,
            direction="ingress",
            channel="telemetry",
            payload_digest=_payload_digest("x"),
            origin="agent",
        )
        findings = mcp.detect_writeback([record])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["kind"], "writeback")

    def test_writeback_clean(self) -> None:
        self.assertEqual(mcp.detect_writeback([_rec(0), _rec(1)]), [])

    def test_breakout_socket_escape_flagged(self) -> None:
        record = _rec(0, channel="docker.sock", origin="agent")
        findings = mcp.detect_breakout([record])
        self.assertTrue(any(f["kind"] == "socket_escape" for f in findings))

    def test_breakout_clean(self) -> None:
        self.assertEqual(mcp.detect_breakout([_rec(0), _rec(1)]), [])

    def test_integrity_clean(self) -> None:
        ok, findings = mcp.verify_channel_integrity([_rec(0), _rec(1)])
        self.assertTrue(ok)
        self.assertEqual(findings, [])

    def test_integrity_ingress_flagged(self) -> None:
        bad = mcp.build_record(
            seq=0,
            direction="ingress",
            channel="telemetry",
            payload_digest=_payload_digest("x"),
            origin="host",
        )
        ok, findings = mcp.verify_channel_integrity([bad])
        self.assertFalse(ok)
        self.assertEqual(findings[0]["kind"], "ingress_record")

    def test_integrity_seq_gap_flagged(self) -> None:
        ok, findings = mcp.verify_channel_integrity([_rec(0), _rec(2)])
        self.assertFalse(ok)
        self.assertTrue(any(f["kind"] == "seq_gap" for f in findings))


class IsolationTests(unittest.TestCase):
    def _topo(self, **kwargs: object) -> "mcp.ChannelTopology":
        params: dict[str, object] = {
            "monitor_sockets": ("mon-1",),
            "shared_with_agent": (),
            "observer_write_paths": ("alerts/out",),
            "export_carries_secrets": False,
        }
        params.update(kwargs)
        return mcp.ChannelTopology(**params)  # type: ignore[arg-type]

    def test_isolation_clean(self) -> None:
        ok, findings = mcp.verify_channel_isolation(self._topo())
        self.assertTrue(ok)
        self.assertEqual(findings, [])

    def test_shared_socket_flagged(self) -> None:
        ok, findings = mcp.verify_channel_isolation(
            self._topo(shared_with_agent=("mon-1",))
        )
        self.assertFalse(ok)
        self.assertEqual(findings[0]["kind"], "shared_socket")

    def test_observer_write_flagged(self) -> None:
        ok, findings = mcp.verify_channel_isolation(
            self._topo(observer_write_paths=("agent/actions",))
        )
        self.assertFalse(ok)
        self.assertEqual(findings[0]["kind"], "observer_write_access")

    def test_secret_in_export_flagged(self) -> None:
        ok, findings = mcp.verify_channel_isolation(
            self._topo(export_carries_secrets=True)
        )
        self.assertFalse(ok)
        self.assertEqual(findings[0]["kind"], "secret_in_export")

    def test_head_digest_stable_and_sensitive(self) -> None:
        a = [_rec(0), _rec(1)]
        b = [_rec(0), _rec(1)]
        self.assertEqual(mcp.channel_head_digest(a), mcp.channel_head_digest(b))
        c = [_rec(0), _rec(1, payload_digest=_payload_digest("other"))]
        self.assertNotEqual(mcp.channel_head_digest(a), mcp.channel_head_digest(c))


class MainTests(unittest.TestCase):
    def test_main_runs(self) -> None:
        mcp.main()


if __name__ == "__main__":
    unittest.main()
