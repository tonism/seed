#!/usr/bin/env python3
"""Actual R/X/H2/AEAD/T exchange with an independent local HTTP/2 peer.

16 KiB conventional RAM plus ordinary video state. BIOS media/NIC/display
and provider responses are fixture leaves. The real resident reconnect/turn
scheduler and real original-speed/provider behavior are not yet acceptance.
"""
from image_binding import TEST_IMAGE
from pathlib import Path
import argparse,hashlib,json,struct
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import *
import check_h2_requests as Q
R=Q.R;HERE=Q.HERE;OUT=TEST_IMAGE;S=Q.S
INFO=json.loads((OUT/'build.json').read_text())
Q.OUT=OUT;Q.INFO=INFO
R.CORE=(OUT/'SEED.SYS').read_bytes();R.LISTING=(OUT/'SEED.SYS.lst').read_text()
R.META['labels']=dict(INFO['labels']);Q.T.P.INFO['labels'].update(INFO['labels'])
assert hashlib.sha256(R.CORE).hexdigest()==INFO['core_sha256']
from h2.events import WindowUpdated

def event(text,complete=True):
    out=b'data: '+json.dumps({'type':'response.output_text.delta','delta':text},separators=(',',':')).encode()+b'\n\n'
    if complete:out+=b'data: {"type":"response.completed"}\n\n'
    return out

class VM(Q.VM):
    def __init__(self,text='fortytwo',*,complete=True,terminal=True,status=200,window=427):
        self.response=event(text,complete);self.sent_response=0;self.terminal=terminal
        self.response_status=status;self.response_started=False;self.rendered=bytearray()
        self.fail_after_render=None;self.cancel_after_render=False;self.fin_count=0
        super().__init__(window=window,cold=False,prompt=b'hi')
        self.u.mem_write(S['reconnect_retries'],b'\1')
        self.u.hook_add(UC_HOOK_CODE,self.print_char,begin=R.symbol('print_char'),end=R.symbol('print_char'))
        if not getattr(self,'text_terminal',False):
            self.u.hook_add(UC_HOOK_CODE,lambda u,a,z,d:R.D.near_return(u,False),
                begin=R.symbol('scroll_text_area'),end=R.symbol('scroll_text_area'))
    def print_char(self,u,addr,size,data):
        self.rendered.append(u.reg_read(UC_X86_REG_AX)&255)
        self.u.mem_write(S['cursor_col'],bytes([(self.read(S['cursor_col'],1)[0]+1)&255]))
        if self.fail_after_render is not None and self.fail_read is None:
            self.fail_read=len(self.disk_reads)+self.fail_after_render
        if self.cancel_after_render:self.u.mem_write(S['esc_stop'],b'\1')
        R.D.near_return(u,False)
    def guard(self,u,access,addr,size,value,data):
        if self.running and self.request_phase=='exchange' and 0x0d00<=addr and addr+size<=0x0f00:
            return                           # authenticated native-call capture
        return super().guard(u,access,addr,size,value,data)
    def bios(self,u,interrupt,data):
        assert interrupt==0x13
        ax=u.reg_read(UC_X86_REG_AX);cx=u.reg_read(UC_X86_REG_CX);dx=u.reg_read(UC_X86_REG_DX)
        sector=(((cx>>8)|((cx&0xc0)<<2))+(dx>>8))*8+(cx&63)-1-11
        dest=(u.reg_read(UC_X86_REG_ES)<<4)+u.reg_read(UC_X86_REG_BX)
        if (sector==167 and dest==0x2a00) or (190<=sector<192 and dest==0x0900+(sector-190)*512):
            assert ax==0x0201
            ordinal=len(self.disk_reads)+1;failed=self.fail_read==ordinal
            self.disk_reads.append(dict(sector=sector,destination=dest,failed=failed))
            u.mem_write(dest,b'\xcc'*256 if failed else R.CORE[sector*512:(sector+1)*512])
            u.ctl_remove_cache(dest,dest+512);R.D.set_carry(u,failed);return
        return super().bios(u,interrupt,data)
    def transmit(self,u,addr,size,data):
        n=u.reg_read(UC_X86_REG_CX)
        if n<=60 and not (n>54 and self.read(0x0700+54,1)==b'\x17'):
            assert n<=512
            self.fin_count+=1;R.D.near_return(u,False);return
        return super().transmit(u,addr,size,data)
    def peer(self,plain):
        super().peer(plain)
        if not self.ended:return
        stream=self.ended[-1]
        if not self.response_started:
            self.response_started=True
            self.server.send_headers(stream,[(b':status',str(self.response_status).encode()),
                (b'content-type',b'text/event-stream')])
        available=self.server.local_flow_control_window(stream)
        while self.sent_response<len(self.response) and available>0:
            n=min(available,512,len(self.response)-self.sent_response)
            end=self.terminal and self.sent_response+n==len(self.response)
            self.server.send_data(stream,self.response[self.sent_response:self.sent_response+n],end_stream=end)
            self.sent_response+=n;available=self.server.local_flow_control_window(stream)
        pending=self.server.data_to_send()
        if pending:self.append(pending)
    def run_exchange(self,expected=True):
        # X returned the actual T phase key/destination; the K entry loads T,
        # then owns all receives, control sends, publication and final credit.
        self.request_phase='exchange';self.phase='K';self.in_swap=True
        try:ok=self.call(R.symbol('agent_api_exchange'))
        finally:self.request_phase=None;self.in_swap=False
        assert ok==expected,('exchange',ok,expected,self.read(R.H2,68).hex(),bytes(self.rendered)[-120:])
        assert self.read(S['chat_key_cache'],S['seed_key_len'])==self.saved_key
        # The last allocated model-cache byte is the existing one-shot
        # prompt/context flag, not part of the bounded model/reasoning value.
        assert self.read(S['chat_model_cache'],S['seed_model_len']-1)==self.saved_model[:-1]
        assert self.read(0x2800,512)==(OUT/'request-aux-sector.bin').read_bytes()
        if ok:
            assert self.read(S['api_stream_completed'],1)==b'\3'
            assert self.read(R.H2+18,1)==b'\2' and self.u16('tls_buffered_payload_len')==0
        else:
            assert self.read(0x06c4,1)==b'\0'
            assert not any(self.read(R.LIVE,0x3b9c-R.LIVE))
            assert not any(self.read(R.H2,86))
            assert self.fin_count==1,'failed exchange did not close its socket'
        return self

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--quick',action='store_true');args=ap.parse_args();rows=[]
    def row(name,v):
        rows.append(dict(name=name,rendered_bytes=len(v.rendered),response_bytes=v.sent_response,
            disk_reads=len(v.disk_reads),tls_records=len(v.transmitted),stack_low=hex(v.lowest_stack)))
        print(name,'PASS',rows[-1],flush=True)
    v=VM();v.request();v.run_exchange();assert v.rendered==b'fortytwo';row('complete-answer',v)
    # Reuse keeps the acknowledged H2 state and opens stream three, with no
    # second preface and no reset of the cryptographic record sequences.
    v.headers=[];v.body.clear();v.ended=[];v.rendered.clear();v.response=event('fifty')
    v.sent_response=0;v.response_started=False
    v.request();v.run_exchange();assert v.rendered==b'fifty';row('same-connection-second-answer',v)
    if not args.quick:
        v=VM('x'*1300);v.request();v.run_exchange();assert v.rendered==b'x'*1300;row('multi-window-answer',v)
        for name,kwargs in [('missing-model-completion',dict(complete=False)),
                            ('missing-END_STREAM',dict(terminal=False)),
                            ('provider-error',dict(status=429))]:
            v=VM(**kwargs);v.request();v.run_exchange(False)
            if name=='provider-error':
                assert not v.rendered and v.read(S['reconnect_retries'],1)==b'\1'
            else:assert v.read(S['reconnect_retries'],1)==b'\0','rendered answer could replay'
            row(name,v)
        v=VM('x'*700);v.cancel_after_render=True;v.request();v.run_exchange(False)
        assert v.read(S['reconnect_retries'],1)==b'\0';row('cancel-during-render',v)
        # Next response record's H2 swap can fail at all 16 positions after
        # a visible partial answer. The response owner must suppress replay.
        for fail in range(1,17):
            v=VM('x'*700);v.fail_after_render=fail;v.request();v.run_exchange(False)
            assert v.rendered and v.read(S['reconnect_retries'],1)==b'\0'
            row('partial-disk-after-output-'+str(fail),v)
    report=dict(passed=True,quick=args.quick,cases=len(rows),mapped_conventional_ram_bytes=16384,
        core_sha256=INFO['core_sha256'],exchange_bytes=INFO['exchange_bytes'],rows=rows,
        limits=[__doc__,'Tool-only results, cold-parent/scheduler/reconnect composition, all failures, far/ENV/native/IRQ lifetimes and original-speed/NIC/286 acceptance remain.'])
    (OUT/('exchange-quick.json' if args.quick else 'exchange-gate.json')).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='rows'},indent=2))

if __name__=='__main__':main()
