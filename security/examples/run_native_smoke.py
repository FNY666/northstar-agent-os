#!/usr/bin/env python3
"""Actual native scanner/OSV DB smoke on self-owned Git fixtures, never production.

Dangerous fixture source is only scanned, never imported/executed. Scanner/network
isolation must come from the native runner. All signing keys are ephemeral memory
fixtures and no test success proves production signing/control-plane provenance.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'tests'))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from producer_fixtures import key_id,trust_entry
from trusted_common import EvidenceError,create_receipt,publish_directory,sha,wire
from produce_expectation import RELEASE_COMPONENTS,produce_expectation
from freeze_inputs import freeze_inputs,validate_requirements
from export_git_snapshot import export_git_snapshot
from native_runner import run_isolation_probes
from scan_supervisor import capture_scans,profile_pins,input_manifest_sha256
from stage_scan_capture import stage_scan_capture


def git(repo,*args):
    env={'PATH':'/usr/bin:/bin','HOME':str(repo.parent),'LANG':'C.UTF-8','GIT_CONFIG_GLOBAL':os.devnull,'GIT_CONFIG_NOSYSTEM':'1','GIT_TERMINAL_PROMPT':'0'}
    return subprocess.check_output(['git','-c','core.hooksPath=/dev/null','-C',str(repo),*args],env=env,stderr=subprocess.DEVNULL).decode().strip()


def one_case(parent,role,profile,pins):
    case=parent/role
    case.mkdir()
    source=case/'source'
    source.mkdir()
    git(source,'init','--quiet')
    git(source,'config','user.name','Northstar Local Native Lab')
    git(source,'config','user.email','northstar-local-native-lab@example.invalid')
    (source/'README.md').write_text('Self-owned native scan fixture; not a deployment.\n')
    git(source,'add','README.md')
    git(source,'commit','--quiet','-m','fixture base')
    start_commit=git(source,'rev-parse','HEAD')
    src=source/'src'
    src.mkdir()
    pack=ROOT/'native_fixtures/rule-pack'
    source_case='normal' if role=='benign' else 'vulnerable'
    for path in sorted((pack/'semgrep'/source_case).iterdir()):
        if path.suffix not in ('.py','.js'):continue
        data=path.read_bytes()
        # Deliberate suppression attempt; disable-nosem must keep this finding.
        if role=='attack' and path.name=='python_dynamic_execution.py':
            text=data.decode()
            data='\n'.join(line+'  # nosem' if 'eval(' in line or 'exec(' in line else line for line in text.splitlines()).encode()+b'\n'
        (src/path.name).write_bytes(data)
    req=(pack/'osv'/source_case/'requirements.txt').read_bytes()
    validate_requirements(req)
    (source/'requirements.txt').write_bytes(req)
    git(source,'add','.')
    git(source,'commit','--quiet','-m','fixture candidate')
    commit=git(source,'rev-parse','HEAD')
    patch=subprocess.check_output(['git','-c','core.hooksPath=/dev/null','-C',str(source),'diff','--binary',start_commit,commit,'--'],env={'PATH':'/usr/bin:/bin','GIT_CONFIG_GLOBAL':os.devnull,'GIT_CONFIG_NOSYSTEM':'1'})
    sempaths=sorted(p.relative_to(source).as_posix() for p in src.iterdir())
    snapshot=export_git_snapshot(source,commit,case/'git-snapshot')
    committed=Path(snapshot['output_dir'])/'source'
    freeze_inputs(committed,case/'semgrep-input',sempaths)
    freeze_inputs(committed,case/'osv-input',['requirements.txt'])
    seminputs={p:(committed/p).read_bytes() for p in sempaths}
    osvinputs={'requirements.txt':(committed/'requirements.txt').read_bytes()}
    now=datetime.now(timezone.utc)
    identity={'repository':'northstar/local-native-lab','run_id':'native-live-'+role,'run_attempt':1,'source_commit':commit,'nonce':secrets.token_hex(32)}
    keys={name:Ed25519PrivateKey.generate() for name in ('plan','capture','expectation')}
    rolemap={'plan':['scan-plan'],'capture':['scan-capture'],'expectation':['expectation']}
    trust={'schema':'northstar.receipt-trust.v1','keys':{key_id(key):trust_entry(key,rolemap[name],identity['repository'],now) for name,key in keys.items()}}
    template={'schema':'northstar.security-expectation.v1','run_id':identity['run_id'],'subject':{'start_commit':start_commit,'patch_sha256':sha(patch),'candidate_manifest_sha256':snapshot['candidate_manifest_sha256']},
              'policy':{'id':'local-native-smoke-policy','sha256':sha(wire({'blocking':['critical','high'],'unknown':'review'})),'blocking_severities':['critical','high'],'unknown_severity':'review','max_scan_age_seconds':3600,'max_database_age_seconds':86400,'max_clock_skew_seconds':60,'max_duration_ms':180000},'tools':{}}
    for tool,inputs in (('semgrep',seminputs),('osv-scanner',osvinputs)):
        prefix='semgrep' if tool=='semgrep' else 'osv'
        template['tools'][tool]={'required':True,'not_applicable_reason':None,'evidence_file':prefix+'-evidence.json',**pins['tools'][tool],
                                'scan_view_manifest_sha256':input_manifest_sha256(inputs),'isolation_backend':'bwrap',
                                'expected_inputs':[{'path':p,'sha256':sha(data),'ecosystems':['PyPI'] if tool=='osv-scanner' else [],'min_packages':len(validate_requirements(data)) if tool=='osv-scanner' else 0} for p,data in sorted(inputs.items())]}
    body={'schema':'northstar.scan-plan.v1','expectation_template':template,'release_components':list(RELEASE_COMPONENTS),'release_version':'0.1.0'}
    plan_raw=create_receipt('scan-plan',identity,body,keys['plan'],trust)
    plan_path=case/'plan.dsse.json'
    plan_path.write_bytes(plan_raw)
    profile_path=case/'host-profile.json'
    profile_path.write_bytes(wire(profile))
    capture=capture_scans(plan_path,profile_path,case/'semgrep-input',case/'osv-input',case/'capture',trust,identity,keys['capture'])
    stage=stage_scan_capture(case/'capture',case/'captured-evidence',trust,identity,sha(plan_raw))
    produced=produce_expectation(plan_path,case/'capture/capture.dsse.json',case/'captured-evidence',case/'produced',trust,identity,keys['expectation'])
    expected='pass' if role=='benign' else 'block'
    if produced['decision']!=expected:
        raise EvidenceError('actual native gate does not meet the paired smoke expectation: '+role+'='+produced['decision'])
    return {'role':role,'expected':expected,'decision':produced['decision'],'exit_code':produced['exit_code'],'scans':capture['scans'],
            'source_commit':commit,'start_commit':start_commit,'candidate_manifest_sha256':snapshot['candidate_manifest_sha256'],'git_tree':snapshot['git_tree'],
            'input_source':'verified-git-objects','candidate_is_self_owned_fixture':True,'actual_scanners_executed':True,'actual_offline_database_used':True,'private_keys_persisted':False}


def main():
    p=argparse.ArgumentParser(description='Actual two-scanner local fixture smoke; not production signing or release.')
    p.add_argument('--tools-root',default='/home/ubuntu/northstar-tools')
    p.add_argument('--output',required=True)
    args=p.parse_args()
    output=Path(args.output)
    output.mkdir(parents=True,exist_ok=False)
    tools=Path(args.tools_root)
    snapshot=json.loads((tools/'db/snapshot.json').read_bytes())
    profile={'schema':'northstar.native-scan-profile.v1','semgrep_root':str(tools/'semgrep'),'osv_root':str(tools/'osv'),'policy_dir':str(ROOT/'rules'),'database_dir':str(tools/'db'),
             'database_updated_at':snapshot['updated_at'],'database_ecosystems':snapshot['ecosystems'],'bwrap_path':str(tools/'bwrap/usr/bin/bwrap')}
    try:
        probes=run_isolation_probes(bwrap_path=Path(profile['bwrap_path']))
        if not probes['passed']:raise EvidenceError('actual isolation probes did not pass')
        probes={key:value for key,value in probes.items() if key not in ('stdout','stderr')}
        pins=profile_pins(profile)
        result={'test_fixture_only':True,'production_trust_root_verified':False,'release_eligible':False,'isolation_probes':probes,'cases':[one_case(output,role,profile,pins) for role in ('benign','attack')]}
        (output/'summary.json').write_bytes(wire(result))
        print(json.dumps(result,ensure_ascii=False,indent=2))
        return 0
    except Exception as error:
        result={'test_fixture_only':True,'release_eligible':False,'exit_code':2,'error':type(error).__name__,'reason':str(error)}
        (output/'failure.json').write_bytes(wire(result))
        print(json.dumps(result,ensure_ascii=False))
        return 2


if __name__=='__main__':raise SystemExit(main())
