#!/usr/bin/env python3
"""Real Seed ChaCha/Poly1305 + H2 collection and post-tag phases in 16 KiB.

TCP arrivals, phase replacement, outgoing credit and publication are explicit
host leaves. No live endpoint, full product lifetime or calibrated time claim.
"""
from image_binding import TEST_IMAGE
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BUILD = TEST_IMAGE

from hpack import Encoder
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.x86_const import *

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    obj=importlib.util.module_from_spec(spec);sys.modules[name]=obj
    spec.loader.exec_module(obj);return obj
A=module('opt020_real_aead',ROOT/'tools/check-tls13-app.py')
D=module('opt020_real_dispatch',ROOT/'tools/check-tls13-core-dispatch.py')
S=A.CHECK_LAYOUT.parse_equates([ROOT/'targets/ibm_pc_5150/boot/core/layout.inc',ROOT/'targets/ibm_pc_5150/boot/core/data.inc'])
CORE=(BUILD/'SEED.SYS').read_bytes()
LISTING=(BUILD/'SEED.SYS.lst').read_text()
META=json.loads((BUILD/'build.json').read_text())
POST=(TEST_IMAGE/'h2_post.bin').read_bytes()
KEND=META['labels']['core_link_window_end']
KEY=hashlib.sha256(b'OPT020 real CPU8086 receive synthetic server key').digest()
IV=bytes(range(12))
LIVE=0x2e00;WORK=0x2e1c;DATA=0x2e70;CTL=0x3070;HP=0x3570;HPEND=0x35bc
H2=0x062e;PREFIX=H2+68;RETURN=0x04f0

def symbol(name):
    if name in META['labels']:return META['labels'][name]
    for i,line in enumerate(LISTING.splitlines()):
        if re.search(r'^\s*\d+\s+(?:<\d+>\s*)?'+name+r'(?::|\s+equ\s+\$)\s*$',line):
            for line in LISTING.splitlines()[i:]:
                m=re.match(r'^\s*\d+\s+([0-9A-F]{8})\s',line)
                if m:return 0x1000+int(m[1],16)
    return D.resolve_symbol(LISTING,name)

def frame(typ,body=b'',flags=0,stream=1):
    return len(body).to_bytes(3,'big')+bytes([typ,flags])+stream.to_bytes(4,'big')+body
def settings():return frame(4,stream=0)+frame(4,flags=1,stream=0)
def encoded(fields,encoder=None):
    if encoder is None:encoder=Encoder();encoder.header_table_size=0
    return encoder.encode(fields)
def response(body=b'hello',stream=1,encoder=None):
    return frame(1,encoded([(b':status',b'200'),(b'content-length',str(len(body)).encode())],encoder),4,stream)+frame(0,body,1,stream)

class VM:
    def __init__(self,chunk=458,trace=False):
        self.u=Uc(UC_ARCH_X86,UC_MODE_16);self.u.mem_map(0,0x4000)
        self.u.mem_write(0,b'\xa5'*0x4000)
        self.u.mem_write(0x1000,CORE[:KEND-0x1000])
        self.u.mem_write(LIVE,bytes(0x3600-LIVE))
        self.u.mem_write(H2,bytes(84))
        A.initialize_runtime_constants(self.u,S)
        self.u.mem_write(S['tls_server_write_key'],KEY)
        self.u.mem_write(S['tls_server_write_iv'],IV)
        self.u.mem_write(S['tls_server_record_seq'],bytes(8))
        self.w16('tls_buffered_payload_len',0)
        self.w16('tls_buffered_payload_ptr',0)
        self.u.mem_write(0x413,(16).to_bytes(2,'little'))
        for r in (UC_X86_REG_CS,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS):self.u.reg_write(r,0)
        self.chunk=chunk;self.wire=b'';self.pos=0;self.nextseq=0;self.phase='K'
        self.verified=False;self.output=bytearray();self.replies=bytearray()
        self.ack_positions=[];self.records=0;self.lowest_stack=0x4000
        self.trace_enabled=trace;self.trace=bytearray();self.trace_count=0
        self.trace_ack=[];self.running=False;self.entry=None
        self.u.hook_add(UC_HOOK_MEM_WRITE,self.guard)
        for address,callback in (
            (symbol('tcp_receive_payload'),self.receive),
            (symbol('ne_transmit_tcp_ack'),self.ack),
            (0x0540,self.fallback),
            (symbol('tls_h2_tag_verified'),self.tag_verified),
        ):
            self.u.hook_add(UC_HOOK_CODE,callback,begin=address,end=address)
        self.u.mem_write(D.EXPECTED_CALLBACKS['nic_vt_rx_fallback'],(0x0540).to_bytes(2,'little'))
        self.u.hook_add(UC_HOOK_CODE,lambda u,a,z,d:u.emu_stop(),begin=RETURN,end=RETURN)
        if trace:self.u.hook_add(UC_HOOK_CODE,self.trace_instruction)
        assert self.post(0)

    def read(self,addr,n):return bytes(self.u.mem_read(addr,n))
    def w16(self,name,value):self.u.mem_write(S.get(name,name),int(value).to_bytes(2,'little'))
    def u16(self,name):return int.from_bytes(self.read(S.get(name,name),2),'little')
    def guard(self,u,access,addr,size,value,data):
        if not self.running:return
        self.lowest_stack=min(self.lowest_stack,addr) if addr>=0x3f00 else self.lowest_stack
        if self.phase=='post':
            spans=[(H2,PREFIX+16),(LIVE,HPEND),(0x3f00,0x4000)]
        else:
            spans=[(0x06b0,0x0900),(0x0f00,0x1000),(WORK,HP),
                   (HPEND,0x35fd),(0x3600,S['tls_pre_response_scratch_end']),
                   (S['tls_app_len'],S['chat_model_cache']),(0x3f00,0x4000)]
            if self.verified:spans += [(LIVE,WORK),(0x0619,0x061c)]
        assert any(lo<=addr and addr+size<=hi for lo,hi in spans),('write',self.phase,hex(self.entry),hex(addr),size,self.verified)
    def receive(self,u,addr,size,data):
        assert self.phase=='K'
        if self.pos==len(self.wire):D.near_return(u,True);return
        n=min(self.chunk,len(self.wire)-self.pos)
        part=self.wire[self.pos:self.pos+n];self.pos+=n
        # The real NIC aliases and destroys all primitive scratch between
        # ciphertext fragments. Preserve neither a hidden MAC nor keystream.
        self.u.mem_write(0x0700,b'\x9b'*512)
        self.u.mem_write(0x0700,part)
        self.w16('tcp_rx_payload_ptr',0x0700);self.w16('tcp_rx_payload_len',len(part))
        D.near_return(u,False)
    def fallback(self,u,addr,size,data):D.near_return(u,True)
    def ack(self,u,addr,size,data):
        self.ack_positions.append(self.pos)
        if self.trace_enabled:self.trace_ack.append(self.trace_count)
        D.near_return(u,False)
    def tag_verified(self,u,addr,size,data):
        if self.phase!='K':return  # Same code address can belong to post phase.
        assert self.u16('tls_app_record_len')==0
        self.verified=True
    def trace_instruction(self,u,addr,size,data):
        if self.phase=='K' and not self.verified:
            self.trace.extend(addr.to_bytes(2,'little'));self.trace_count+=1
    def switch(self,phase):
        if phase==self.phase:return
        body=POST if phase=='post' else CORE[0x800:KEND-0x1000]
        self.u.mem_write(0x1800,body)
        self.u.ctl_remove_cache(0x1800,max(KEND,0x1800+len(POST)))
        self.phase=phase
    def call(self,entry):
        self.entry=entry;self.u.mem_write(0x3ffe,RETURN.to_bytes(2,'little'))
        self.u.reg_write(UC_X86_REG_SP,0x3ffe);self.u.reg_write(UC_X86_REG_EFLAGS,2)
        self.running=True
        try:self.u.emu_start(entry,RETURN+1,count=60_000_000)
        finally:self.running=False
        assert self.u.reg_read(UC_X86_REG_IP)==RETURN,('no return',hex(entry),hex(self.u.reg_read(UC_X86_REG_IP)))
        assert self.u.reg_read(UC_X86_REG_SP)==0x4000
        assert all(self.u.reg_read(r)==0 for r in (UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS))
        return not bool(self.u.reg_read(UC_X86_REG_EFLAGS)&1)
    def post(self,index):
        self.switch('post');return self.call(int.from_bytes(POST[index*2:index*2+2],'little'))
    def append(self,plain,*,kind=0x17,pad=0,forge=False,truncate=0):
        wire=A.server_record(KEY,IV,self.nextseq,plain,kind,pad);self.nextseq+=1
        if forge:wire=wire[:-1]+bytes([wire[-1]^1])
        if truncate:wire=wire[:-truncate]
        self.wire+=wire
    def record(self,expected=True,post_expected=True):
        before_live=self.read(LIVE,28);before_hp=self.read(HP,76);before_h2=self.read(H2,84)
        seq=self.read(S['tls_server_record_seq'],8)
        self.switch('K');self.verified=False
        self.trace.clear();self.trace_count=0;self.trace_ack.clear()
        ok=self.call(symbol('tls_receive_application_data'));self.records+=1
        assert ok==expected,('receive',self.records,ok,expected,self.pos,len(self.wire),self.read(S['tls_finished_tag'],16).hex(),self.read(S['tls_received_tag'],16).hex())
        assert self.read(HP,76)==before_hp and self.read(H2,84)==before_h2,'TLS modified post-tag state'
        assert self.read(HPEND,65)==bytes(65),'saved MAC not erased'
        assert self.read(0x0700,512)==bytes(512),'primitive work not erased'
        assert self.read(S['tls_app_record_buffer'],577)==bytes(577),'TLS prefix not erased'
        assert self.read(S['tls_server_record_seq'],8)==(int.from_bytes(seq,'big')+int(ok)).to_bytes(8,'big')
        assert self.read(0x2df0,16)==b'\xa5'*16
        assert self.read(0x35fd,3)==bytes(3)
        assert self.read(S['chat_model_cache'],0x3f00-S['chat_model_cache'])==b'\xa5'*(0x3f00-S['chat_model_cache'])
        if not ok:
            assert self.read(LIVE,28)==before_live
            assert self.read(WORK,HP-WORK)==bytes(HP-WORK)
            assert self.read(S['tls_rx_copy'],592)==bytes(592)
            assert not self.u16('tls_buffered_payload_len')
            return False
        tail=self.u16('tls_buffered_payload_len');assert tail<=self.chunk
        assert self.read(S['tls_rx_copy']+tail,592-tail)==bytes(592-tail)
        kind=self.read(S['tls_app_content_type'],1)[0]
        if kind==0x16:
            assert self.read(LIVE,28)==before_live
            assert self.read(WORK,HP-WORK)==bytes(HP-WORK)
            return True
        assert kind==0x17
        charged=self.u.reg_read(UC_X86_REG_DX)
        ok=self.post(2);assert ok==post_expected,('post',self.read(H2,68).hex())
        if not ok:return False
        n=self.u.reg_read(UC_X86_REG_AX);prefix=self.u.reg_read(UC_X86_REG_BX);rest=self.u.reg_read(UC_X86_REG_CX)
        assert n<=512 and prefix<=16 and rest<=1280
        self.output.extend(self.read(DATA,n));self.replies.extend(self.read(PREFIX,prefix)+self.read(CTL,rest))
        self.switch('K');self.verified=True
        assert self.call(symbol('h2_rx_consume_credit'))
        assert self.u.reg_read(UC_X86_REG_AX)==charged
        assert self.call(symbol('h2_rx_consume_credit'))
        assert self.u.reg_read(UC_X86_REG_AX)==0
        return True
    def ready(self):
        self.append(settings());self.record();assert self.post(1)
        # This receiver-only fixture starts after the caller has sent request
        # END_STREAM and granted its initial response window. Real outbound
        # ownership/credit is exercised by check_h2_outbound/requests.
        self.w16(LIVE+16,512)
        self.u.mem_write(H2+61,b'\0')
        self.replies.clear()

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--quick',action='store_true');ap.add_argument('--trace-only',action='store_true');args=ap.parse_args()
    rows=[]
    def result(name,v,**kw):
        rows.append(dict(name=name,records=v.records,body=len(v.output),stack_bytes=0x4000-v.lowest_stack,**kw))
        print(name,'PASS',flush=True)
    for chunk in (() if args.trace_only else (458,) if args.quick else (1,2,5,17,31,64,458)):
        v=VM(chunk);v.ready();v.append(response());assert v.record();assert v.output==b'hello'
        result('fragment-'+str(chunk),v)
    # Several encrypted records in the same TCP payload; sending/erasing the
    # prefix must not consume or corrupt the following ciphertext tail.
    v=VM();v.ready();e=Encoder();e.header_table_size=0
    body=b'fortytwo'
    head=frame(1,encoded([(b':status',b'200')],e),4)
    v.append(head);v.append(frame(0,body,1));v.record();assert v.u16('tls_buffered_payload_len')>0
    v.u.mem_write(S['tls_app_record_buffer'],b'\xd5'*577)  # outbound TX arena overwrite
    v.record();assert v.output==body;result('encrypted-next-record-tail',v)
    if not args.quick:
        for length in (() if args.trace_only else (2048,4230,16384)):
            v=VM();v.ready();data=response(bytes(range(256))*2)
            wire=frame(0xee,bytes(length-len(data)-9))+data
            v.append(wire,pad=239 if length==16384 else 11);v.record()
            assert v.output==bytes(range(256))*2;result('legal-content-'+str(length),v)
        # Ticket interleaved while HPACK and CONTINUATION are live.
        v=VM(31);v.ready();head=encoded([(b':status',b'200'),(b'x',b'abcde'*80)])
        v.append(frame(1,head[:9]));v.record()
        ticket=A.new_session_ticket(b'synthetic-ticket')
        v.append(ticket,kind=0x16,pad=80);v.record()
        v.append(frame(9,head[9:],4)+frame(0,b'hello',1));v.record()
        assert v.output==b'hello';result('ticket-during-continued-header',v)
        for name,plain,kind,pad,forge,truncate in (
            ('forged-body',response(),0x17,0,True,0),
            ('forged-control',frame(6,b'12345678',stream=0),0x17,0,True,0),
            ('forged-ticket',ticket,0x16,0,True,0),
            ('invalid-inner-type',response(),0x18,0,False,0),
            ('all-zero-inner',bytes(30),0,0,False,0),
            ('invalid-ticket',bytes(40),0x16,0,False,0),
            ('oversize-ticket',bytes(577),0x16,0,False,0),
            ('alert-close',b'\x01\x00',0x15,32,False,0),
            ('alert-bad-level',b'\x03\x00',0x15,0,False,0),
            ('truncated-tag',response(),0x17,0,False,1),
            ('truncated-cipher',response(),0x17,0,False,25),
            ('data-credit-overrun',response(b'x'*513),0x17,0,False,0),
            ('control-resource-exhaustion',frame(6,b'12345678',stream=0)*76,0x17,0,False,0),
        ):
            v=VM();v.ready();v.append(plain,kind=kind,pad=pad,forge=forge,truncate=truncate)
            v.record(expected=False);assert not v.output and not v.replies;result(name,v)
        # Equal public record/segment geometry: the real crypto + collector
        # follow exactly the same pre-verification instruction/ACK schedule.
        traces=[]
        for name,plain in (('zero',bytes(600)),('ff',b'\xff'*600),
                            ('valid-shape',(response()+bytes(600))[:600])):
            v=VM(chunk=127,trace=True);v.ready();v.append(plain,forge=True);v.record(expected=False)
            traces.append((hashlib.sha256(v.trace).hexdigest(),v.trace_count,v.trace_ack))
            (BUILD/('trace-'+name+'.bin')).write_bytes(v.trace)
            result('trace-'+name,v,instructions=v.trace_count,ack_instruction_positions=v.trace_ack)
        (BUILD/'aead-trace-comparison.json').write_text(json.dumps(dict(equal=traces[0]==traces[1]==traces[2],traces=traces,core_sha256=hashlib.sha256(CORE).hexdigest()),indent=2)+'\n')
        assert traces[0]==traces[1]==traces[2],traces
    report=dict(passed=True,quick=args.quick,trace_only=args.trace_only,cases=len(rows),core_sha256=hashlib.sha256(CORE).hexdigest(),
        post_sha256=hashlib.sha256(POST).hexdigest(),k_bytes=META['k_bytes'],mapped_ram_bytes=16384,
        rows=rows,limits=[__doc__,'Instruction identity is not calibrated 8088 execution time or a complete interrupt/physical timing proof.',
        'Only the receive AEAD and post-tag phases are composed. No ALPN, outbound framing, loader, whole-product erase or live acceptance claim.'])
    (BUILD/('aead-quick.json' if args.quick else 'aead-trace-gate.json' if args.trace_only else 'aead-gate.json')).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='rows'},indent=2))

if __name__=='__main__':main()
