#!/usr/bin/env python3
"""Northstar 受信回执公共原语；不执行候选代码、扫描器或网络动作。"""
from __future__ import annotations

import base64
import binascii
import ctypes
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "cicd-evidence-integration" / "security-evidence-contract"))
from security_evidence import EvidenceError, strict_json_loads, _read_path, _Directory, _validators, _context_semantics

MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_RECEIPT_BYTES = 3 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
PAYLOAD_TYPE = "application/vnd.northstar.receipt.v1+json"
KINDS = frozenset({"scan-plan", "scan-capture", "expectation", "build-capture", "release-seal"})
HEX = re.compile(r"[a-f0-9]{64}\Z")
COMMIT = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})\Z")
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")


def wire(value: Any) -> bytes:
    try:
        raw = (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
        strict_json_loads(raw)
        return raw
    except (TypeError, ValueError, RecursionError) as exc:
        raise EvidenceError("无法安全序列化有界JSON对象") from exc


def sha(raw: bytes) -> str:
    if not isinstance(raw, bytes):
        raise EvidenceError("摘要输入必须是bytes")
    return hashlib.sha256(raw).hexdigest()


def clock(now: datetime | None = None) -> datetime:
    value = datetime.now(timezone.utc) if now is None else now
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise EvidenceError("宿主时钟必须是aware datetime")
    return value.astimezone(timezone.utc)


def stamp(value: datetime) -> str:
    return clock(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    if type(value) is not str or len(value) > 32 or not TIME.fullmatch(value):
        raise EvidenceError("回执时间必须为有界UTC RFC3339")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise EvidenceError("回执时间不是有效日期") from exc


def validate_identity(identity: Any) -> None:
    if type(identity) is not dict or set(identity) != {"repository", "run_id", "run_attempt", "source_commit", "nonce"}:
        raise EvidenceError("当前CI身份字段不完整或含额外字段")
    if type(identity["repository"]) is not str or not REPO.fullmatch(identity["repository"]):
        raise EvidenceError("repository格式无效")
    if type(identity["run_id"]) is not str or not NAME.fullmatch(identity["run_id"]):
        raise EvidenceError("run_id格式无效")
    if type(identity["run_attempt"]) is not int or not 1 <= identity["run_attempt"] <= 1_000_000:
        raise EvidenceError("run_attempt必须为严格正整数")
    if type(identity["source_commit"]) is not str or not COMMIT.fullmatch(identity["source_commit"]):
        raise EvidenceError("source_commit格式无效")
    if type(identity["nonce"]) is not str or not HEX.fullmatch(identity["nonce"]):
        raise EvidenceError("nonce格式无效")


def _decode64(value: Any, maximum: int, exact: int | None = None) -> bytes:
    if type(value) is not str or len(value) > ((maximum + 2) // 3) * 4 + 4:
        raise EvidenceError("base64字段类型或大小无效")
    try:
        raw = base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise EvidenceError("base64字段无法解码") from exc
    if len(raw) > maximum or (exact is not None and len(raw) != exact):
        raise EvidenceError("base64解码长度无效")
    return raw


def validate_trust_store(store: Any) -> None:
    if type(store) is not dict or set(store) != {"schema", "keys"} or store["schema"] != "northstar.receipt-trust.v1":
        raise EvidenceError("信任根Schema无效")
    if type(store["keys"]) is not dict or not 1 <= len(store["keys"]) <= 128:
        raise EvidenceError("信任根key集合无效")
    for key_id, key in store["keys"].items():
        if type(key_id) is not str or not HEX.fullmatch(key_id):
            raise EvidenceError("信任根keyid无效")
        if type(key) is not dict or set(key) != {"public_key", "kinds", "repository", "not_before", "not_after", "revoked"}:
            raise EvidenceError("信任根key字段无效")
        pub = _decode64(key["public_key"], 32, 32)
        if sha(pub) != key_id:
            raise EvidenceError("keyid与公钥实际字节不匹配")
        kinds = key["kinds"]
        if type(kinds) is not list or not 1 <= len(kinds) <= len(KINDS) or any(type(k) is not str or k not in KINDS for k in kinds) or len(kinds) != len(set(kinds)):
            raise EvidenceError("公钥角色集合无效")
        if type(key["repository"]) is not str or not REPO.fullmatch(key["repository"]):
            raise EvidenceError("公钥repository范围无效")
        if type(key["revoked"]) is not bool or parse_time(key["not_before"]) >= parse_time(key["not_after"]):
            raise EvidenceError("公钥有效期或撤销状态无效")


def load_trust_store(path: str | Path) -> dict[str, Any]:
    value = strict_json_loads(_read_path(path, MAX_JSON_BYTES))
    validate_trust_store(value)
    return value


def pae(payload_type: str, payload: bytes) -> bytes:
    typ = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(typ)).encode("ascii") + b" " + typ + b" " + str(len(payload)).encode("ascii") + b" " + payload


def _payload_semantics(payload: dict[str, Any], expected_kind: str, expected_identity: dict[str, Any], key: dict[str, Any], now: datetime) -> None:
    if set(payload) != {"schema", "kind", "identity", "issued_at", "expires_at", "body"} or payload.get("schema") != "northstar.signed-receipt.v1":
        raise EvidenceError("已签名payload合同无效")
    if payload.get("kind") != expected_kind or expected_kind not in KINDS or type(payload.get("body")) is not dict:
        raise EvidenceError("已签名回执类型无效")
    validate_identity(payload["identity"])
    if payload["identity"] != expected_identity:
        raise EvidenceError("回执不属于当前CI身份")
    if key["repository"] != expected_identity["repository"] or expected_kind not in key["kinds"]:
        raise EvidenceError("已验签公钥没有此仓库/回执角色授权")
    issued, expires = parse_time(payload["issued_at"]), parse_time(payload["expires_at"])
    before, after = parse_time(key["not_before"]), parse_time(key["not_after"])
    if key["revoked"] or not before <= now <= after or not before <= issued < expires <= after:
        raise EvidenceError("已验签公钥已撤销或不在有效期")
    if not 0 < (expires - issued).total_seconds() <= 14_400:
        raise EvidenceError("回执有效期超出预算")
    if issued > now + timedelta(seconds=60) or now >= expires:
        raise EvidenceError("回执在未来或已过期")


def verify_receipt(raw: bytes, trust_store: dict[str, Any], *, expected_kind: str, expected_identity: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    validate_identity(expected_identity)
    validate_trust_store(trust_store)
    at = clock(now)
    if type(raw) is not bytes or len(raw) > MAX_RECEIPT_BYTES:
        raise EvidenceError("签名封装超过预算")
    envelope = strict_json_loads(raw)
    if set(envelope) != {"payloadType", "payload", "signatures"}:
        raise EvidenceError("签名封装字段无效")
    typ = envelope["payloadType"]
    if type(typ) is not str or len(typ) > 256:
        raise EvidenceError("payloadType格式无效")
    signatures = envelope["signatures"]
    if type(signatures) is not list or len(signatures) != 1 or type(signatures[0]) is not dict or set(signatures[0]) != {"keyid", "sig"}:
        raise EvidenceError("当前profile要求一个明确签名")
    key_id = signatures[0]["keyid"]
    if type(key_id) is not str or not HEX.fullmatch(key_id) or key_id not in trust_store["keys"]:
        raise EvidenceError("没有匹配的受信公钥")
    key = trust_store["keys"][key_id]
    payload_raw = _decode64(envelope["payload"], MAX_JSON_BYTES)
    signature = _decode64(signatures[0]["sig"], 64, 64)
    public = Ed25519PublicKey.from_public_bytes(_decode64(key["public_key"], 32, 32))
    try:
        public.verify(signature, pae(typ, payload_raw))
    except InvalidSignature as exc:
        raise EvidenceError("签名无法验证") from exc
    # keyid仅作候选key查找hint；授权绑定实际已验签公钥及运维部署的角色策略。
    if typ != PAYLOAD_TYPE:
        raise EvidenceError("不支持的已认证payloadType")
    # 只解析刚才验签的同一payload bytes，不重新读取或重新解析envelope。
    payload = strict_json_loads(payload_raw)
    _payload_semantics(payload, expected_kind, expected_identity, key, at)
    return payload


def create_receipt(kind: str, identity: dict[str, Any], body: dict[str, Any], private_key: Ed25519PrivateKey, trust_store: dict[str, Any], *, now: datetime | None = None, ttl_seconds: int = 1800) -> bytes:
    validate_identity(identity)
    validate_trust_store(trust_store)
    if kind not in KINDS or type(body) is not dict or not isinstance(private_key, Ed25519PrivateKey):
        raise EvidenceError("签名参数无效")
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 14_400:
        raise EvidenceError("签名TTL无效")
    at = clock(now)
    payload = {"schema": "northstar.signed-receipt.v1", "kind": kind, "identity": identity, "issued_at": stamp(at), "expires_at": stamp(at + timedelta(seconds=ttl_seconds)), "body": body}
    raw = wire(payload)
    if len(raw) > MAX_JSON_BYTES:
        raise EvidenceError("待签名payload超过预算")
    public = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = sha(public)
    envelope = {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(raw).decode("ascii"), "signatures": [{"keyid": key_id, "sig": base64.b64encode(private_key.sign(pae(PAYLOAD_TYPE, raw))).decode("ascii")}]}
    encoded = wire(envelope)
    # 自验签同时强制当前key角色/仓库/有效期授权，签错角色不返回任何回执。
    verify_receipt(encoded, trust_store, expected_kind=kind, expected_identity=identity, now=at)
    return encoded


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    target = Path(os.path.expanduser(os.fspath(path)))
    if not NAME.fullmatch(target.name):
        raise EvidenceError("私钥文件名无效")
    with _Directory(target.parent) as parent:
        fd = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=parent.fd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.getuid() or before.st_mode & 0o077 or before.st_size > 8192:
                raise EvidenceError("私钥必须为当前owner的无外部权限普通文件")
            raw = os.read(fd, 8193)
            after = os.fstat(fd)
            ident = lambda v: (v.st_dev, v.st_ino, v.st_size, v.st_mtime_ns, v.st_ctime_ns, v.st_nlink, v.st_mode, v.st_uid)
            if len(raw) != before.st_size or len(raw) > 8192 or ident(before) != ident(after):
                raise EvidenceError("私钥文件读取期间发生变化")
        finally:
            os.close(fd)
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except (ValueError, TypeError) as exc:
        raise EvidenceError("无法解析部署的私钥") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise EvidenceError("当前profile仅接受Ed25519私钥")
    return key


def file_manifest(files: dict[str, bytes]) -> list[dict[str, Any]]:
    if type(files) is not dict or not 1 <= len(files) <= 128:
        raise EvidenceError("文件集合数量无效")
    out, total = [], 0
    for name in sorted(files):
        raw = files[name]
        if type(name) is not str or not NAME.fullmatch(name) or type(raw) is not bytes or len(raw) > MAX_FILE_BYTES:
            raise EvidenceError("文件名/类型/字节预算无效")
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise EvidenceError("文件集合超过总预算")
        out.append({"name": name, "sha256": sha(raw), "bytes": len(raw)})
    return out


def read_manifest_files(root: str | Path, manifest: list[dict[str, Any]], *, max_total: int = MAX_TOTAL_BYTES) -> dict[str, bytes]:
    if type(manifest) is not list or not 1 <= len(manifest) <= 128 or type(max_total) is not int or not 0 <= max_total <= MAX_TOTAL_BYTES:
        raise EvidenceError("清单数量/总预算无效")
    expected, total = {}, 0
    for item in manifest:
        if type(item) is not dict or set(item) != {"name", "sha256", "bytes"}:
            raise EvidenceError("文件清单字段无效")
        name, digest, size = item["name"], item["sha256"], item["bytes"]
        if type(name) is not str or not NAME.fullmatch(name) or name in expected or type(digest) is not str or not HEX.fullmatch(digest):
            raise EvidenceError("文件清单路径/摘要无效或重复")
        if type(size) is not int or not 0 <= size <= MAX_FILE_BYTES:
            raise EvidenceError("文件清单字节数无效")
        total += size
        if total > max_total:
            raise EvidenceError("文件清单超过总预算")
        expected[name] = item
    result = {}
    with _Directory(root) as directory:
        before = set(os.listdir(directory.fd))
        if before != set(expected):
            raise EvidenceError("实际文件集与已认证清单不一致")
        for name, item in expected.items():
            raw = directory.read(name, item["bytes"])
            if len(raw) != item["bytes"] or sha(raw) != item["sha256"]:
                raise EvidenceError("实际文件字节与已认证清单不一致")
            result[name] = raw
        if set(os.listdir(directory.fd)) != before:
            raise EvidenceError("文件集读取期间发生变化")
    return result


def publish_directory(output_dir: str | Path, files: dict[str, bytes]) -> None:
    # 仅发布数据，不发布私钥；调用方决定签名后应包含的全部业务文件。
    file_manifest(files)
    target = Path(os.path.expanduser(os.fspath(output_dir)))
    if not NAME.fullmatch(target.name):
        raise EvidenceError("封存目标目录名无效")
    lib = ctypes.CDLL(None, use_errno=True)
    rename = getattr(lib, "renameat2", None)
    if rename is None:
        raise EvidenceError("平台缺少原子不可覆盖renameat2")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    stage = "stage-" + secrets.token_hex(16)
    published = False
    with _Directory(target.parent) as parent:
        os.mkdir(stage, 0o700, dir_fd=parent.fd)
        stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent.fd)
        try:
            for name, raw in files.items():
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=stage_fd)
                try:
                    view = memoryview(raw)
                    while view:
                        size = os.write(fd, view)
                        if size <= 0:
                            raise EvidenceError("写入封存数据失败")
                        view = view[size:]
                    os.fchmod(fd, 0o400)
                    os.fsync(fd)
                finally:
                    os.close(fd)
            os.fchmod(stage_fd, 0o500)
            os.fsync(stage_fd)
            # Linux RENAME_NOREPLACE=1；已有目录、文件或symlink一律不覆盖。
            rc = rename(parent.fd, stage.encode("ascii"), parent.fd, target.name.encode("ascii"), 1)
            if rc != 0:
                raise OSError(ctypes.get_errno(), "atomic no-replace publication failed")
            published = True
            os.fsync(parent.fd)
        except (OSError, ValueError) as exc:
            raise EvidenceError("原子封存失败；不覆盖现有目标") from exc
        finally:
            if not published:
                os.fchmod(stage_fd, 0o700)
                for name in os.listdir(stage_fd):
                    os.unlink(name, dir_fd=stage_fd)
            os.close(stage_fd)
            if not published:
                os.rmdir(stage, dir_fd=parent.fd)
