#!/usr/bin/env python3
"""Compose the TLS sealer and resident TCP sender below the live X/T phase.

Only the NIC transmit leaf is mocked. Execute in exactly 16 KiB and compare
every emitted TLS record with the independent host oracle. Receive-record
limits and the allocated request-buffer/ENV layout are separate contracts.
"""
from pathlib import Path
import argparse,hashlib,importlib.util,json,struct,sys
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('send_bounds_app',ROOT/'tools/check-tls13-app.py')
A=importlib.util.module_from_spec(spec);sys.modules[spec.name]=A;spec.loader.exec_module(A)
spec=importlib.util.spec_from_file_location('send_bounds_dispatch',ROOT/'tools/check-tls13-core-dispatch.py')
D=importlib.util.module_from_spec(spec);sys.modules[spec.name]=D;spec.loader.exec_module(D)
BOOT=ROOT/'targets/ibm_pc_5150/boot';BUILD=ROOT/'build/ibm_pc_5150'
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--core',type=Path,default=BUILD/'SEED.SYS')
parser.add_argument('--listing',type=Path,default=BUILD/'SEED.SYS.lst')
parser.add_argument('--report',type=Path,default=BUILD/'tls13-send-bounds.json')
ARGS=parser.parse_args()
S=A.CHECK_LAYOUT.parse_equates([BOOT/'core/layout.inc',BOOT/'core/data.inc'])
CORE=ARGS.core.read_bytes();LISTING=ARGS.listing.read_text()

def symbol(name):
    if name in S:return S[name]
    return D.resolve_symbol(LISTING,name)

ENTRY=symbol('tls_send_application_data_current_seq')
KEND=symbol('core_link_window_end')
RETURN=0x04f0;TRANSMIT=0x04f2;INPUT=0x2e00
KEY=hashlib.sha256(b'Seed synthetic bounded outgoing record').digest();IV=bytes(range(12))
LIMIT=S['net_setup_frame_scratch_len']-S['tcp_payload_offset']-S['tls_record_header_len']-S['tls_aead_tag_len']-S['tls13_inner_type_len']
POINTERS=(symbol('tls_app_data_ptr'),symbol('tls_app_plain_ptr')+2)

def run(length):
    u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x4000)
    u.mem_write(0,b'\xa5'*0x4000);u.mem_write(0x1000,CORE[:KEND-0x1000])
    A.initialize_runtime_constants(u,S)
    plain=hashlib.shake_256(b'bounded TLS send').digest(length)
    u.mem_write(INPUT,plain)
    u.mem_write(S['tls_client_write_key'],KEY);u.mem_write(S['tls_client_write_iv'],IV)
    u.mem_write(S['tls_client_record_seq'],(1).to_bytes(8,'big'))
    u.mem_write(S['tls_app_len'],struct.pack('<H',length))
    u.mem_write(symbol('tls_app_plain_ptr'),struct.pack('<H',INPUT))
    u.mem_write(symbol('nic_vt_transmit'),struct.pack('<H',TRANSMIT))
    u.mem_write(0x3ffe,struct.pack('<H',RETURN))
    for reg in (UC_X86_REG_CS,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS):u.reg_write(reg,0)
    u.reg_write(UC_X86_REG_SP,0x3ffe);u.reg_write(UC_X86_REG_EFLAGS,2)
    frames=[];live_code=bytes(u.mem_read(0x0900,0x600))
    config=bytes(u.mem_read(S['chat_model_cache'],0x3f00-S['chat_model_cache']))
    def guard(machine,access,address,size,value,data):
        spans=[(0x06b0,0x0900),(0x0f00,0x1000),(0x3600,S['chat_model_cache']),POINTERS,(0x3f1c,0x4000)]
        assert any(a<=address and address+size<=b for a,b in spans),('outbound overwrite',length,hex(address),size)
    def transmit(machine,address,size,data):
        si=machine.reg_read(UC_X86_REG_SI);cx=machine.reg_read(UC_X86_REG_CX)
        assert si==S['ne_tx_frame'] and cx<=S['net_setup_frame_scratch_len'],('wire exceeds NIC scratch',cx)
        frames.append(bytes(machine.mem_read(si,cx)));D.near_return(machine,False)
    u.hook_add(UC_HOOK_MEM_WRITE,guard)
    u.hook_add(UC_HOOK_CODE,transmit,begin=TRANSMIT,end=TRANSMIT)
    u.hook_add(UC_HOOK_CODE,lambda machine,a,z,d:machine.emu_stop(),begin=RETURN,end=RETURN)
    u.emu_start(ENTRY,RETURN+1,count=25_000_000)
    assert u.reg_read(UC_X86_REG_IP)==RETURN and u.reg_read(UC_X86_REG_SP)==0x4000
    ok=not bool(u.reg_read(UC_X86_REG_EFLAGS)&1)
    assert ok==(length<=LIMIT),('outbound acceptance',length,ok,LIMIT)
    assert bytes(u.mem_read(0x0900,0x600))==live_code
    assert bytes(u.mem_read(S['chat_model_cache'],len(config)))==config
    assert int.from_bytes(u.mem_read(S['tls_client_record_seq'],8),'big')==1+int(ok)
    if ok:
        expected=A.server_record(KEY,IV,1,plain)
        assert len(frames)==1 and frames[0][S['tcp_payload_offset']:]==expected
        assert len(frames[0])==S['tcp_payload_offset']+len(expected)
    else:assert not frames
    return dict(plaintext_bytes=length,accepted=ok,frame_bytes=len(frames[0]) if frames else 0)

def main():
    assert LIMIT==436
    rows=[run(n) for n in (0,1,15,16,17,63,64,65,360,LIMIT-1,LIMIT,LIMIT+1,439,440,441)]
    report=dict(passed=True,cases=len(rows),mapped_ram_bytes=16384,send_plaintext_limit=LIMIT,
        allocated_plaintext_bytes=S['api_request_plain_len'],core_sha256=hashlib.sha256(CORE).hexdigest(),rows=rows,
        limits=['NIC device operation/timing and complete request construction are separate gates.'])
    ARGS.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return 0
if __name__=='__main__':raise SystemExit(main())
