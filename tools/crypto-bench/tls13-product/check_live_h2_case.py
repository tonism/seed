#!/usr/bin/env python3
"""Bind explicitly scoped wire flows to reviewed live VM conversation evidence.

Encrypted control records are not model turns. Visible answers and the bound
runtime's cryptographic gates supply the semantics unavailable in a pcap.
This gate performs no provider calls and never reads configuration contents.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import sys

HERE=Path(__file__).resolve().parent

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value
    spec.loader.exec_module(value);return value

def reviewed_native_completion(case,binding,result,events):
    """Validate a separate visual review without replacing the automatic miss."""
    assert binding.get('native_program') and binding.get('case_scope','main')=='main'
    assert not result['answer'] and result['error']=='KeyboardInterrupt()'
    manual=json.loads((case/'manual-completion.json').read_text())
    submitted=[e for e in events if e['event']=='submitted']
    completed=[e for e in events if e['event']=='answer']
    assert manual['turn']==len(submitted)==len(completed)+1
    assert len(result['turns'])==len(completed) and all(result['turns'])
    assert manual['ready'] and manual['input_prompt_returned']
    assert manual['semantic_ax_decimal']==42 and manual['semantic_bytes']=='B8 2A 00 CB'
    assert manual['visible_response']
    stopped=next(e['utc_epoch'] for e in events if e['event']=='controller_error')
    assert submitted[-1]['utc_epoch']<manual['utc_epoch']<=stopped
    screenshot=case/manual['screenshot']
    assert screenshot.parent==case and screenshot.suffix=='.png'
    assert hashlib.sha256(screenshot.read_bytes()).hexdigest()==manual['screenshot_sha256']
    kind=manual.get('review_kind','numeric-format-mismatch')
    if kind=='numeric-format-mismatch':
        assert not manual['numeric_format_followed']
    else:
        assert kind=='ocr-omission' and manual['numeric_format_followed'] is True
        # Require the unchanged detector's omission on these exact reviewed
        # pixels, a recognized prompt, and completion within the native budget.
        observation=json.loads((case/'ocr-observation.json').read_text())
        assert observation['screenshot']==manual['screenshot']
        assert observation['screenshot_sha256']==manual['screenshot_sha256']
        assert observation['expected']=='42' and observation['missing']==['42']
        assert observation['engine'] and observation['lines']
        assert '42' not in ' '.join(observation['lines'])
        assert observation['visual_prompt'] and observation['ocr_prompt']
        assert manual['utc_epoch']<=observation['observed_utc_epoch']<=stopped
        assert manual['utc_epoch']-submitted[-1]['utc_epoch']<=2400
    return manual

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('case',type=Path)
    ap.add_argument('--ports',type=int,nargs='+',required=True,
                    help='All acquisition/resumption client ports for this exact VM, in order')
    ap.add_argument('--manual-completion',action='store_true',
                    help='Use a separately reviewed final native answer after stopping a literal-text oracle')
    args=ap.parse_args();case=args.case
    assert len(args.ports) in (2,4) and len(set(args.ports))==len(args.ports)
    binding=json.loads((case/'binding.json').read_text())
    result=json.loads((case/'result.json').read_text())
    events=json.loads((case/'events.json').read_text())
    assert result['greeting']
    manual=None
    if args.manual_completion:
        manual=reviewed_native_completion(case,binding,result,events)
        events.append(dict(event='answer',turn=manual['turn'],ready=True,utc_epoch=manual['utc_epoch']))
    else:
        assert result['answer'] and not result['error']
    assert result['image_unchanged'] and all(result['protected_unchanged'].values())
    assert result.get('visual_answers_verified'), 'review saved answer screenshots before claiming acceptance'
    core_hashes=[h for p,h in binding['protected_before'].items() if p.endswith('/SEED.SYS')]
    assert len(core_hashes)==1
    full=module('seed_h2_286_wire',HERE/'live_286_pcap.py')
    floor=module('seed_h2_8088_wire',HERE.parent/'tls13-poc/live_k15_pcap.py')
    parser=full if binding['ram_kib']==512 else floor
    # Use the full TCP collector on both routes: it rejects hidden holes and
    # reused tuples rather than folding an extra SYN into an earlier flow.
    flows=[f for f in full.collect_flows(case/'wire.pcap') if f.client[1] in args.ports]
    assert [f.client[1] for f in flows]==args.ports
    launch=next(e['utc_epoch'] for e in events if e['event']=='vm_launch')
    observed=[];analyses=[];records=[]
    for i,f in enumerate(flows):
        x=parser.analyze_flow(f);assert x is not None
        c,ct=f.client_stream.contiguous();s,st=f.server_stream.contiguous()
        cr=list(full.walk_records(c));sr=list(full.walk_records(s))
        assert full.records_cover_stream(cr,c) and full.records_cover_stream(sr,s)
        assert not f.client_stream.conflict and not f.server_stream.conflict
        assert f.client_syn_timestamp>=launch
        if parser is full:
            assert x['client_hello']['alpn']=='h2'
            assert x['role']==('resumption-use' if i%2 else 'acquisition')
            assert x['deadline_met'] and not x['stream_gap']
        else:
            assert x['client_alpn']=='h2' and x['passed']
            assert x['profile']==('resumed' if i%2 else 'fresh')
        assert [5+r[3] for r in cr[1:4]]==[58,79,31]
        if i%2==0:
            assert len(cr)==4, 'acquisition emitted more than Finished/preface/SETTINGS ACK'
            assert f.client_fin_timestamp is not None
            assert f.client_reset_timestamp is None
            assert f.client_fin_timestamp>max(st[r[0]] for r in sr)
        else:
            assert flows[i-1].client_fin_timestamp<f.client_syn_timestamp
        observed.append(dict(client_port=f.client[1],role='use' if i%2 else 'acquisition',
            client_records=len(cr),server_records=len(sr),
            server_hello_to_finished_seconds=x['server_hello_to_client_finished_seconds']))
        analyses.append(x);records.append((f,cr,ct,sr,st))
    if parser is full:
        for field in ('random','session','mlkem','x25519'):
            assert full._all_unique(analyses,field),field
    turns=[]
    for submit in (e for e in events if e['event']=='submitted'):
        done=next(e for e in events if e['event']=='answer' and e['turn']==submit['turn'])
        assert done['ready']
        lo=submit['utc_epoch']-5;hi=done['utc_epoch'];sent=received=0
        used=[]
        for i,(f,cr,ct,sr,st) in enumerate(records):
            if not i%2:continue
            tx=sum(lo<=ct[r[0]]<=hi for r in cr[3:])
            rx=sum(lo<=st[r[0]]<=hi for r in sr if r[1]==23)
            if tx or rx:used.append(f.client[1])
            sent+=tx;received+=rx
        assert sent and received
        turns.append(dict(turn=submit['turn'],client_records=sent,server_records=received,
                          use_ports=used,submit_to_ready_seconds=hi-submit['utc_epoch']))
    scope=binding.get('case_scope','main')
    if scope=='nic-regression':
        # Main CPU/RAM acceptance retains its longer dependent/native test.
        # A NIC regression explicitly requires first reply, reuse, then one
        # idle reconnection with a dependent reply, all on the same card.
        assert binding['ram_kib']==16 and binding['entry']=='basic'
        assert binding['idle_before_turn']==2 and binding['idle_seconds']>=600
        assert len(turns)>=2 and len(flows)==4
        assert turns[0]['use_ports']==[args.ports[1]]
        # A stale socket may accept the first send before the peer's close is
        # observed. That pending human turn can use the one bounded reconnect,
        # just as on the main-path gate. The old connection must retire before
        # the fresh acquisition below, and the answer must use the new session.
        assert turns[1]['use_ports'] in ([args.ports[3]],[args.ports[1],args.ports[3]])
    else:
        assert scope=='main' and len(turns)>=4
    if len(flows)==4:
        assert flows[1].close_timestamp is not None
        assert flows[1].close_timestamp<flows[2].client_syn_timestamp
        assert any(flows[3].client[1] in row['use_ports'] for row in turns)
    report=dict(passed=True,scope='explicit flows and visually reviewed completed UI turns',
        case_scope=scope,
        ports=args.ports,core_sha256=core_hashes[0],flows=observed,turns=turns,
        reconnect_observed=len(flows)==4,
        manual_completion=manual,
        wire_sha256=hashlib.sha256((case/'wire.pcap').read_bytes()).hexdigest(),limits=__doc__)
    (case/'h2-live-gate.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
