#!/usr/bin/env python3
"""仅在受保护签名job把已有secret装入0700临时目录；不生成生产密钥。"""
from __future__ import annotations

import argparse
import os
import re
import secrets
from pathlib import Path

from trusted_common import EvidenceError, _Directory, load_private_key


def materialize(env_name: str, root: str | Path) -> Path:
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", env_name):
        raise EvidenceError("secret环境变量名无效")
    value = os.environ.pop(env_name, None)
    if type(value) is not str or not value or len(value.encode("utf-8")) > 8192:
        raise EvidenceError("未配置所需签名secret或超过预算")
    name = "key-" + secrets.token_hex(16)
    with _Directory(root) as parent:
        os.mkdir(name, 0o700, dir_fd=parent.fd)
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent.fd)
        try:
            out = os.open("signer.pem", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                data = memoryview(value.encode("utf-8"))
                while data:
                    size = os.write(out, data)
                    if size <= 0:
                        raise EvidenceError("无法装载签名secret")
                    data = data[size:]
                os.fsync(out)
            finally:
                os.close(out)
            path = Path(os.path.abspath(os.fspath(root))) / name / "signer.pem"
            load_private_key(path)
            return path
        except BaseException:
            for item in os.listdir(fd):
                os.unlink(item, dir_fd=fd)
            os.rmdir(name, dir_fd=parent.fd)
            raise
        finally:
            os.close(fd)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="受保护签名job临时装载已有Ed25519 secret；stdout仅私钥路径。")
    parser.add_argument("--env-name", required=True)
    parser.add_argument("--root", required=True)
    args = parser.parse_args(argv)
    try:
        print(materialize(args.env_name, args.root))
        return 0
    except Exception:
        # 不输出异常详情、环境变量内容或私钥。
        print("signing key unavailable", file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
