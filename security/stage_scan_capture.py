#!/usr/bin/env python3
"""Verify a co-packaged native capture, then stage only its authenticated scan files.

The signed receipt is kept at its original path; no unsigned file becomes a pin.
This bridges the supervisor's 7-file output to the existing strict producer's
6-file evidence directory without relaxing that producer's closed file set.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from trusted_common import EvidenceError, _Directory, _read_path, file_manifest, load_trust_store, publish_directory, sha, strict_json_loads, validate_identity, verify_receipt


def stage_scan_capture(capture_dir, output_dir, trust_store, expected_identity, expected_plan_sha256):
    validate_identity(expected_identity)
    source = Path(capture_dir)
    raw = _read_path(source / 'capture.dsse.json', 3145728)
    payload = verify_receipt(raw, trust_store, expected_kind='scan-capture', expected_identity=expected_identity)
    body = payload['body']
    if type(body) is not dict or set(body) != {'schema','plan_sha256','files'} or body['schema'] != 'northstar.scan-capture.v1' or body['plan_sha256'] != expected_plan_sha256:
        raise EvidenceError('scan capture does not bind the independently verified plan')
    items = body['files']
    if type(items) is not list or not 1 <= len(items) <= 128:
        raise EvidenceError('scan capture manifest is outside budget')
    files = {}
    wanted = set()
    total = 0
    for item in items:
        if type(item) is not dict or set(item) != {'name','sha256','bytes'} or type(item['bytes']) is not int or not 0 <= item['bytes'] <= 16777216:
            raise EvidenceError('scan capture manifest entry is invalid')
        name = item['name']
        if type(name) is not str or name in wanted or name == 'capture.dsse.json':
            raise EvidenceError('scan capture file name is invalid or duplicated')
        wanted.add(name)
        total += item['bytes']
    if total > 67108864:
        raise EvidenceError('scan capture exceeds total budget')
    with _Directory(source) as directory:
        if set(os.listdir(directory.fd)) != wanted | {'capture.dsse.json'}:
            raise EvidenceError('scan capture directory has omitted or extra files')
        if directory.read('capture.dsse.json',3145728) != raw:
            raise EvidenceError('scan capture receipt changed during staging')
        for item in items:
            # _Directory.read enforces single safe filename, no-follow, regular/nlink1.
            data = directory.read(item['name'],item['bytes'])
            if len(data) != item['bytes'] or sha(data) != item['sha256']:
                raise EvidenceError('captured native bytes differ from signed manifest')
            files[item['name']] = data
        if set(os.listdir(directory.fd)) != wanted | {'capture.dsse.json'}:
            raise EvidenceError('scan capture directory changed during staging')
    if file_manifest(files) != items:
        raise EvidenceError('scan capture manifest is not canonical')
    publish_directory(output_dir,files)
    return {'exit_code':0,'evidence_dir':str(output_dir),'capture_path':str(source/'capture.dsse.json'),'capture_sha256':sha(raw),'files_staged':len(files)}


def main(argv=None):
    p=argparse.ArgumentParser(description='Authenticate a native capture then stage exact evidence files; no scan/signing.')
    for name in ('capture-dir','output','trust-store','identity','verified-plan'):
        p.add_argument('--'+name,required=True)
    args=p.parse_args(argv)
    try:
        store=load_trust_store(args.trust_store)
        identity=strict_json_loads(_read_path(args.identity))
        plan_raw=_read_path(args.verified_plan,3145728)
        verify_receipt(plan_raw,store,expected_kind='scan-plan',expected_identity=identity)
        result=stage_scan_capture(args.capture_dir,args.output,store,identity,sha(plan_raw))
    except Exception as error:
        result={'exit_code':2,'error':type(error).__name__}
    print(json.dumps(result,sort_keys=True))
    return result['exit_code']


if __name__=='__main__': raise SystemExit(main())
