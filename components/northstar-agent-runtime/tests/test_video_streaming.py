"""Targeted tests for video_streaming (simulated HLS/DASH bookkeeping)."""

import ast
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import video_streaming as vs
from video_streaming import (
    SCHEMA_PIN,
    VIDEO_STREAMING_VERSION,
    AssetRecord,
    BadDurationError,
    BadFormatError,
    BadTrackError,
    DRMRecord,
    DuplicateAssetError,
    DuplicateDRMError,
    ManifestRecord,
    OutOfRangeError,
    SegmentRecord,
    SeqOrderError,
    UnknownAssetError,
    UnknownCodecError,
    UnknownDRMError,
    UnknownManifestError,
    UnknownSegmentError,
    ValidationError,
    VideoStreaming,
    video_streaming_audit_event,
)


def _tracks():
    return [
        {
            "kind": "video",
            "codec": "h264",
            "bitrate_kbps": 8000,
            "width": 1920,
            "height": 1080,
            "fps": 30.0,
        },
        {
            "kind": "audio",
            "codec": "aac",
            "bitrate_kbps": 128,
            "channels": 2,
            "language": "en",
        },
    ]


def _vs_with_asset(seed=b"test-seed"):
    manager = VideoStreaming(seed=seed)
    manager.register_asset("movie-1", 60_000, 1, tracks=_tracks())
    return manager


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(VIDEO_STREAMING_VERSION, "video-streaming.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.video-streaming.v1")


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_imports_only(self):
        tree = ast.parse(Path(vs.__file__).read_text())
        allowed = {
            "base64",
            "hashlib",
            "json",
            "threading",
            "dataclasses",
            "typing",
            "__future__",
            "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestRegisterAsset(unittest.TestCase):
    def test_roundtrip_and_verify(self):
        manager = _vs_with_asset()
        asset = manager.asset("movie-1")
        self.assertIsInstance(asset, AssetRecord)
        self.assertTrue(asset.verify())
        self.assertEqual(len(asset.tracks), 2)
        self.assertEqual(asset.tracks[0].hls_codec_attr(), "avc1.64001f")
        self.assertEqual(asset.tracks[1].hls_codec_attr(), "mp4a.40.2")

    def test_duplicate_asset_refused(self):
        manager = _vs_with_asset()
        with self.assertRaises(DuplicateAssetError):
            manager.register_asset("movie-1", 60_000, 2, tracks=_tracks())

    def test_bad_duration_refused(self):
        manager = VideoStreaming()
        with self.assertRaises(BadDurationError):
            manager.register_asset("a", 0, 1, tracks=_tracks())
        with self.assertRaises(BadDurationError):
            manager.register_asset("a", True, 2, tracks=_tracks())

    def test_empty_tracks_refused(self):
        manager = VideoStreaming()
        with self.assertRaises(BadTrackError):
            manager.register_asset("a", 60_000, 1, tracks=[])

    def test_unknown_codec_refused(self):
        manager = VideoStreaming()
        bad = [
            {
                "kind": "video",
                "codec": "notacodec",
                "bitrate_kbps": 8000,
                "width": 1920,
                "height": 1080,
            }
        ]
        with self.assertRaises(UnknownCodecError):
            manager.register_asset("a", 60_000, 1, tracks=bad)

    def test_bad_track_fields_refused(self):
        manager = VideoStreaming()
        bad_kind = [
            {"kind": "subtitle", "codec": "aac", "bitrate_kbps": 128}
        ]
        with self.assertRaises(BadTrackError):
            manager.register_asset("a", 60_000, 1, tracks=bad_kind)
        bad_bitrate = [
            {
                "kind": "video",
                "codec": "h264",
                "bitrate_kbps": True,
                "width": 1920,
                "height": 1080,
            }
        ]
        with self.assertRaises(BadTrackError):
            manager.register_asset("a", 60_000, 2, tracks=bad_bitrate)

    def test_unknown_asset_lookup(self):
        manager = _vs_with_asset()
        with self.assertRaises(UnknownAssetError):
            manager.asset("nope")


class TestManifest(unittest.TestCase):
    def test_hls_master_shape(self):
        manager = _vs_with_asset()
        mft = manager.manifest("movie-1", 2)
        self.assertIsInstance(mft, ManifestRecord)
        self.assertTrue(mft.verify())
        self.assertEqual(mft.format, "hls")
        self.assertEqual(mft.kind, "master")
        text = mft.text
        self.assertTrue(text.startswith("#EXTM3U"))
        self.assertIn("#EXT-X-STREAM-INF", text)
        self.assertIn("RESOLUTION=1920x1080", text)
        self.assertIn('CODECS="avc1.64001f,mp4a.40.2"', text)
        self.assertIn('GROUP-ID="audio"', text)
        self.assertIn("BANDWIDTH=8000000", text)

    def test_dash_mpd_shape(self):
        manager = _vs_with_asset()
        mft = manager.manifest("movie-1", 2, format="dash")
        self.assertTrue(mft.verify())
        self.assertEqual(mft.format, "dash")
        text = mft.text
        self.assertIn("<MPD", text)
        self.assertIn("<AdaptationSet", text)
        self.assertIn("<Representation", text)
        self.assertIn("SegmentTemplate", text)
        self.assertIn('bandwidth="8000000"', text)
        self.assertIn('mediaPresentationDuration="PT60.000S"', text)

    def test_bad_format_refused(self):
        manager = _vs_with_asset()
        with self.assertRaises(BadFormatError):
            manager.manifest("movie-1", 2, format="smooth")

    def test_unknown_asset_refused(self):
        manager = VideoStreaming()
        with self.assertRaises(UnknownAssetError):
            manager.manifest("ghost", 1)

    def test_manifest_determinism_across_instances(self):
        a = _vs_with_asset()
        b = _vs_with_asset()
        ma = a.manifest("movie-1", 2)
        mb = b.manifest("movie-1", 2)
        self.assertEqual(ma.text, mb.text)
        self.assertEqual(ma.digest, mb.digest)

    def test_media_playlist_shape(self):
        manager = _vs_with_asset()
        media = manager.media_playlist("movie-1", 0, 2)
        self.assertTrue(media.verify())
        self.assertEqual(media.kind, "media")
        self.assertEqual(media.track_index, 0)
        self.assertIn("#EXT-X-TARGETDURATION:6", media.text)
        self.assertIn("#EXT-X-ENDLIST", media.text)
        # 10 segments of 6s for 60s
        self.assertEqual(media.text.count("#EXTINF:"), 10)

    def test_media_playlist_bad_track_refused(self):
        manager = _vs_with_asset()
        with self.assertRaises(OutOfRangeError):
            manager.media_playlist("movie-1", 9, 2)

    def test_unknown_manifest_lookup(self):
        manager = _vs_with_asset()
        with self.assertRaises(UnknownManifestError):
            manager.manifest_record("mft-999")


class TestSegment(unittest.TestCase):
    def test_roundtrip_and_verify(self):
        manager = _vs_with_asset()
        seg = manager.segment("movie-1", 0, 0, 2)
        self.assertIsInstance(seg, SegmentRecord)
        self.assertTrue(seg.verify())
        self.assertEqual(seg.uri, "movie-1/t0/seg-0.m4s")
        self.assertEqual(seg.duration_ms, 6000)
        self.assertEqual(seg.start_byte, 0)
        self.assertEqual(seg.end_byte, 8000 * 6000 // 8)

    def test_segment_byte_ranges_chain(self):
        manager = _vs_with_asset()
        s0 = manager.segment("movie-1", 0, 0, 2)
        s1 = manager.segment("movie-1", 0, 1, 3)
        self.assertEqual(s1.start_byte, s0.end_byte)

    def test_segment_count(self):
        manager = _vs_with_asset()
        self.assertEqual(manager.segment_count("movie-1"), 10)

    def test_out_of_range_refused(self):
        manager = _vs_with_asset()
        with self.assertRaises(OutOfRangeError):
            manager.segment("movie-1", 0, 10, 2)
        with self.assertRaises(OutOfRangeError):
            manager.segment("movie-1", 5, 0, 3)

    def test_unknown_segment_lookup(self):
        manager = _vs_with_asset()
        with self.assertRaises(UnknownSegmentError):
            manager.segment_record("seg-999")

    def test_segment_determinism_across_instances(self):
        a = _vs_with_asset()
        b = _vs_with_asset()
        sa = a.segment("movie-1", 0, 3, 2)
        sb = b.segment("movie-1", 0, 3, 2)
        self.assertEqual(sa.digest, sb.digest)
        self.assertEqual(sa.uri, sb.uri)


class TestDRM(unittest.TestCase):
    def test_roundtrip_and_verify(self):
        manager = _vs_with_asset()
        drm = manager.drm(
            "movie-1", 2, system="widevine", license_url="https://lic.example/wv"
        )
        self.assertIsInstance(drm, DRMRecord)
        self.assertTrue(drm.verify())
        self.assertEqual(drm.system, "widevine")
        self.assertEqual(len(drm.key_id), 32)
        self.assertTrue(drm.pssh_b64)

    def test_key_id_deterministic_across_instances(self):
        a = _vs_with_asset()
        b = _vs_with_asset()
        da = a.drm("movie-1", 2, system="fairplay")
        db = b.drm("movie-1", 2, system="fairplay")
        self.assertEqual(da.key_id, db.key_id)
        self.assertEqual(da.digest, db.digest)

    def test_duplicate_drm_refused(self):
        manager = _vs_with_asset()
        manager.drm("movie-1", 2, system="widevine")
        with self.assertRaises(DuplicateDRMError):
            manager.drm("movie-1", 3, system="widevine")

    def test_bad_system_refused(self):
        manager = _vs_with_asset()
        with self.assertRaises(ValidationError):
            manager.drm("movie-1", 2, system="marlin")

    def test_unknown_asset_refused(self):
        manager = VideoStreaming()
        with self.assertRaises(UnknownAssetError):
            manager.drm("ghost", 1)

    def test_hls_master_signals_drm_session_data(self):
        manager = _vs_with_asset()
        drm = manager.drm(
            "movie-1", 2, system="widevine", license_url="https://lic.example/wv"
        )
        mft = manager.manifest("movie-1", 3, drm_id=drm.drm_id)
        self.assertIn("#EXT-X-SESSION-DATA", mft.text)
        self.assertIn('VALUE="widevine"', mft.text)

    def test_hls_media_playlist_embeds_key(self):
        manager = _vs_with_asset()
        drm = manager.drm(
            "movie-1", 2, system="widevine", license_url="https://lic.example/wv"
        )
        media = manager.media_playlist("movie-1", 0, 3, drm_id=drm.drm_id)
        self.assertTrue(media.verify())
        self.assertIn("#EXT-X-KEY", media.text)
        self.assertIn("SAMPLE-AES-CTR", media.text)
        self.assertIn("https://lic.example/wv", media.text)
        self.assertIn("IV=0x", media.text)

    def test_dash_manifest_embeds_content_protection(self):
        manager = _vs_with_asset()
        drm = manager.drm("movie-1", 2, system="playready")
        mft = manager.manifest("movie-1", 3, format="dash", drm_id=drm.drm_id)
        self.assertIn("ContentProtection", mft.text)
        self.assertIn(
            "urn:uuid:9a04f079-9840-4286-ab92-34bf9b2fc53c", mft.text
        )
        self.assertIn(drm.pssh_b64, mft.text)

    def test_unknown_drm_in_manifest_refused(self):
        manager = _vs_with_asset()
        with self.assertRaises(UnknownDRMError):
            manager.manifest("movie-1", 2, drm_id="drm-999")

    def test_drm_wrong_asset_refused(self):
        manager = _vs_with_asset()
        manager.register_asset("movie-2", 30_000, 2, tracks=_tracks())
        drm = manager.drm("movie-2", 3, system="widevine")
        with self.assertRaises(ValidationError):
            manager.manifest("movie-1", 4, drm_id=drm.drm_id)


class TestSeqDiscipline(unittest.TestCase):
    def test_seq_rewind_refused(self):
        manager = _vs_with_asset()
        with self.assertRaises(SeqOrderError):
            manager.manifest("movie-1", 1)

    def test_bool_seq_refused(self):
        manager = _vs_with_asset()
        with self.assertRaises(ValidationError):
            manager.manifest("movie-1", True)

    def test_failed_mutation_consumes_seq(self):
        manager = _vs_with_asset()
        with self.assertRaises(UnknownAssetError):
            manager.manifest("ghost", 2)
        # seq 2 is burned; the next valid mutation needs seq 3
        with self.assertRaises(SeqOrderError):
            manager.manifest("movie-1", 2)
        mft = manager.manifest("movie-1", 3)
        self.assertTrue(mft.verify())


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        manager = _vs_with_asset()
        manager.manifest("movie-1", 2)
        manager.segment("movie-1", 0, 0, 3)
        manager.drm("movie-1", 4)
        log = manager.audit_log()
        kinds = [e["kind"] for e in log]
        self.assertEqual(
            kinds,
            ["asset-registered", "manifest-built", "segment-emitted", "drm-bound"],
        )
        for event in log:
            self.assertEqual(event["module"], "video-streaming")
            self.assertEqual(event["version"], "video-streaming.v1")
            self.assertEqual(event["schema"], "audit.ndjson/1")

    def test_audit_bad_kind(self):
        with self.assertRaises(ValidationError):
            video_streaming_audit_event("nope", 1, "x")

    def test_audit_helper_ok(self):
        event = video_streaming_audit_event("manifest-built", 7, "mft-1")
        self.assertEqual(event["record_id"], "mft-1")
        self.assertEqual(event["seq"], 7)


class TestViews(unittest.TestCase):
    def test_views_and_snapshot(self):
        manager = _vs_with_asset()
        manager.manifest("movie-1", 2)
        manager.segment("movie-1", 1, 0, 3)
        manager.drm("movie-1", 4)
        self.assertEqual(manager.asset_ids(), ["movie-1"])
        self.assertEqual(len(manager.manifest_ids()), 1)
        self.assertEqual(len(manager.segment_ids()), 1)
        self.assertEqual(len(manager.drm_ids()), 1)
        snap = manager.as_dict()
        self.assertEqual(len(snap["assets"]), 1)
        self.assertEqual(len(snap["manifests"]), 1)

    def test_records_frozen(self):
        manager = _vs_with_asset()
        asset = manager.asset("movie-1")
        with self.assertRaises(Exception):
            asset.duration_ms = 1  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
