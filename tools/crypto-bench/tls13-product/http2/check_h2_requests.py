#!/usr/bin/env python3
"""Execute real R/X serializers, H2/AEAD, floppy reads and TCP in 16 KiB.

The provider is an independent local h2 state machine. Its response body/T
scanner, resident turn/reconnect scheduler and physical NIC remain outside
this request-composition gate. Only ordinary video text is mapped above RAM.
"""
from image_binding import TEST_IMAGE
from pathlib import Path
import argparse,hashlib,json,struct
from unicorn.x86_const import *
import check_h2_outbound as T
R=T.R;HERE=T.HERE;OUT=TEST_IMAGE;ROOT=HERE.parents[3]
INFO=json.loads((OUT/'build.json').read_text())
R.CORE=(OUT/'SEED.SYS').read_bytes();R.LISTING=(OUT/'SEED.SYS.lst').read_text()
R.META['labels']=dict(INFO['labels'])
assert hashlib.sha256(R.CORE).hexdigest()==INFO['core_sha256']
J=R.module('h2_request_old_gate',ROOT/'tools/check-tls13-product-reconnect.py')
product=(TEST_IMAGE/'SEED.SYS').read_bytes()
DISK,DATA_START,ASSETS=J.parse_product_image(TEST_IMAGE/'floppy-160k.img',product)
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.settings import SettingCodes
from h2.events import DataReceived,StreamEnded,RequestReceived
PROMPT=b'What is "six times seven"? Keep the \\ sign.'
MODEL=b'gpt-6.1-sol';KEY=b'sk-synthetic-h2-request-key'
S=J.STREAM

class VM(T.VM):
    def __init__(self,window=17,cold=False,context=b'',compacting=False,key=KEY,prompt=PROMPT):
        self.request_phase=None;self.asset_reads=[];self.stack_top=0x4000
        super().__init__()
        self.u.mem_map(0xb8000,0x8000);self.u.mem_write(0xb8000,b'\0'*0x8000)
        self.server=H2Connection(config=H2Configuration(client_side=False));self.server.initiate_connection()
        self.server.update_settings({SettingCodes.INITIAL_WINDOW_SIZE:window})
        preface=b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'+R.frame(4,b'\0\1'+bytes(4)+b'\0\2'+bytes(4)+b'\0\4'+bytes(4),stream=0)
        self.server.receive_data(preface);self.append(self.server.data_to_send());self.record()
        self.server.receive_data(bytes(self.replies));self.replies.clear()
        self.headers=[];self.body=bytearray();self.ended=[];self.on_plain=self.peer
        self.window=window
        def w8(name,n):self.u.mem_write(S.get(name,name),bytes([n]))
        def w16(name,n):self.u.mem_write(S.get(name,name),struct.pack('<H',n))
        def w32(name,n):self.u.mem_write(S.get(name,name),struct.pack('<I',n))
        w16(S['handoff_addr']+S['handoff_ram_top'],0x4000)
        w16(S['handoff_addr']+S['handoff_flags'],0)
        w8(S['handoff_addr']+S['handoff_status'],1 if cold else 3)
        for name,asset in [('id','identity'),('compact','compact'),('tools','tools')]:
            cluster,size,_=ASSETS[asset];w16('prompt_'+name+'_cluster',cluster);w16('prompt_'+name+'_size',size)
        for name in ('agent_loop_pending','agent_loop_count','tool_fc_state','compact_next'):w8(name,0)
        w8('compacting_msg',int(compacting))
        for name,n in [('chat_context_len_var',96),('chat_compact_threshold',72),
                       ('chat_effective_cap',96),('chat_context_used',len(context)),('note_len',0),
                       ('far_log_seg_var',0),('ems_page_count',0)]:w16(name,n)
        for name in ('far_flushed_len','far_flushed_esc','far_window_cap'):w32(name,0)
        # BASIC boot scratch is not guaranteed to be zero. Both the cold
        # greeting and ready requests must replace stale dialogue metadata.
        w16('dialogue_off',0xe731);w32('dialogue_cnt',0xffffffff)
        for name in ('far_arena_base','far_arena_top','far_ctx_base'):w32(name,0x10000)
        self.u.mem_write(S['chat_context_start'],context+bytes(96-len(context)))
        model=MODEL+b'","reasoning":{"effort":"max"}'
        self.u.mem_write(S['chat_model_cache'],(model+b'\0').ljust(S['seed_model_len'],b'\0'))
        self.u.mem_write(S['chat_key_cache'],(key+b'\0').ljust(S['seed_key_len'],b'\0'))
        w8('chat_resend_prompt_len',0 if cold else len(prompt))
        w16('video_seg',0xb800);w8('screen_cols',80);w8('dpi_prompt_marker_row',0x80|5)
        row=5;col=2
        for char in prompt:
            self.u.mem_write(0xb8000+(row*80+col)*2,bytes((char,7)))
            col+=1
            if col==80:row+=1;col=2
        self.video=self.read(0xb8000,0x8000)
        self.saved_key=self.read(S['chat_key_cache'],S['seed_key_len'])
        self.saved_model=self.read(S['chat_model_cache'],S['seed_model_len'])
    def guard(self,u,access,addr,size,value,data):
        if not self.running:return
        if self.request_phase:
            spans=[(0x0619,0x061c),(R.H2,R.H2+86),(0x06b0,0x0900),
                   (0x0f00,0x1000),(R.WORK,0x3f00),(0x3f00,0x4000),T.POINTER_SPAN]
            if self.request_phase=='R':spans.append((0x2800,0x2a00))
            if self.verified or self.phase=='post':spans.append((R.LIVE,R.WORK))
            ip=u.reg_read(UC_X86_REG_IP)
            if 0x2800<=ip<0x2a00:spans.append((R.LIVE,R.WORK))
            if self.phase=='post' or self.in_swap:spans.append((0x2600,0x2785))
            assert any(a<=addr and addr+size<=b for a,b in spans),('request write',self.request_phase,self.phase,hex(ip),hex(addr),size)
            if 0x3f00<=addr<0x4000:self.lowest_stack=min(self.lowest_stack,addr)
            return
        return super().guard(u,access,addr,size,value,data)
    def bios(self,u,interrupt,data):
        assert interrupt==0x13
        ax=u.reg_read(UC_X86_REG_AX);bx=u.reg_read(UC_X86_REG_BX)
        cx=u.reg_read(UC_X86_REG_CX);dx=u.reg_read(UC_X86_REG_DX)
        assert ax==0x0201,'writable or multi-sector disk access'
        lba=(((cx>>8)|((cx&0xc0)<<2))+(dx>>8))*8+(cx&63)-1
        dest=(u.reg_read(UC_X86_REG_ES)<<4)+bx
        if lba==11+167 and dest==0x2a00:
            # X publishes the authenticated-response owner before returning
            # its T phase key to the resident scheduler.
            self.disk_reads.append(dict(sector=167,destination=dest,failed=False))
            u.mem_write(dest,R.CORE[167*512:168*512])
            u.ctl_remove_cache(dest,dest+512);R.D.set_carry(u,False);return
        if 11<=lba<11+len(R.CORE)//512:
            return super().bios(u,interrupt,data)
        candidates={DATA_START+c-2:name for name,(c,n,b) in ASSETS.items()}
        assert lba in candidates and dest==0x2e70,('unexpected asset read',lba,hex(dest))
        self.asset_reads.append(candidates[lba]);u.mem_write(dest,DISK[lba*512:(lba+1)*512])
        R.D.set_carry(u,False)
    def peer(self,plain):
        for event in self.server.receive_data(plain):
            if isinstance(event,RequestReceived):
                self.headers.append(dict(event.headers))
                if self.window==0:self.server.increment_flow_control_window(29,event.stream_id)
            if isinstance(event,DataReceived):
                self.body.extend(event.data)
                if self.window==0:self.server.increment_flow_control_window(event.flow_controlled_length,event.stream_id)
                else:self.server.acknowledge_received_data(event.flow_controlled_length,event.stream_id)
            if isinstance(event,StreamEnded):self.ended.append(event.stream_id)
        pending=self.server.data_to_send()
        if pending:self.append(pending)
    def call(self,entry):
        if self.request_phase not in ('R','X'):return super().call(entry)
        # A one-byte stream window intentionally exercises over a thousand
        # real AEAD and 16-sector phase round trips in one X invocation.
        self.entry=entry;self.u.mem_write(self.stack_top-2,R.RETURN.to_bytes(2,'little'))
        self.u.reg_write(UC_X86_REG_SP,self.stack_top-2);self.u.reg_write(UC_X86_REG_EFLAGS,2)
        self.running=True
        try:self.u.emu_start(entry,R.RETURN+1,count=300_000_000)
        finally:self.running=False
        assert self.u.reg_read(UC_X86_REG_IP)==R.RETURN,('no return',hex(entry),hex(self.u.reg_read(UC_X86_REG_IP)))
        assert self.u.reg_read(UC_X86_REG_SP)==self.stack_top
        assert all(self.u.reg_read(r)==0 for r in (UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS))
        return not bool(self.u.reg_read(UC_X86_REG_EFLAGS)&1)
    def request(self):
        previous_stream=int.from_bytes(self.read(R.H2+20,4),'big')
        expected_stream=previous_stream+2 if previous_stream else 1
        r_sector,r_count,_=R.D.phase_geometry(R.CORE,b'R')
        x_sector,x_count,x_dest=R.D.phase_geometry(R.CORE,b'X')
        self.u.mem_write(0x0700,R.CORE[r_sector*512:(r_sector+r_count)*512]);self.u.ctl_remove_cache(0x0700,0x1000)
        self.request_phase='R';self.entry=0x0700
        assert self.call(0x0700),'R failed'
        assert self.read(0x2800,512)==(OUT/'request-aux-sector.bin').read_bytes()
        self.u.mem_write(x_dest,R.CORE[x_sector*512:(x_sector+x_count)*512]);self.u.ctl_remove_cache(x_dest,x_dest+x_count*512)
        self.request_phase='X';self.phase='K';self.in_swap=True
        try:ok=self.call(x_dest)
        finally:self.in_swap=False;self.request_phase=None
        assert ok,('X failed',self.read(R.H2,68).hex(),bytes(self.body)[-150:])
        assert self.read(0xb8000,0x8000)==self.video,'request modified display state'
        assert self.read(S['chat_key_cache'],S['seed_key_len'])==self.saved_key
        assert self.read(S['chat_model_cache'],S['seed_model_len'])==self.saved_model
        assert self.headers and self.ended==[expected_stream]
        available=self.server.local_flow_control_window(expected_stream)
        assert 0<=available<=512
        if not getattr(self,'response_started',False):assert available==512
        assert self.u16(R.LIVE+16)==512 and self.read(R.DATA,512)==bytes(512)
        assert self.read(0x2800,512)==(OUT/'request-aux-sector.bin').read_bytes(),'helper overwritten'
        assert self.u.reg_read(UC_X86_REG_SP)==self.stack_top
        assert all(self.u.reg_read(r)==0 for r in (UC_X86_REG_DS,UC_X86_REG_ES))
        return json.loads(self.body)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--quick',action='store_true');args=parser.parse_args()
    rows=[]
    scenarios=[('cold',dict(cold=True),65535),('ready',dict(),17)]
    if not args.quick:
        scenarios += [('one-byte-credit',dict(),1),('zero-window',dict(),0),
            ('wide-credit',dict(),65535),('maximum-key',dict(key=b'k'*(S['seed_key_len']-1)),127),
            ('compaction',dict(context=b'The earlier answer is forty two. '*2,compacting=True),17)]
    for name,kw,window in scenarios:
        v=VM(window=window,**kw);doc=v.request()
        assert doc['model']=='gpt-6.1-sol' and doc['reasoning']=={'effort':'max'}
        assert doc['stream'] is True and doc['store'] is False
        head=v.headers[0]
        assert head[b':method']==b'POST' and head[b':scheme']==b'https'
        assert head[b':authority']==b'api.openai.com' and head[b':path']==b'/v1/responses'
        assert head[b'content-type']==b'application/json'
        assert head[b'authorization']==b'Bearer '+kw.get('key',KEY)
        if kw.get('cold'):
            assert doc['input']=='Say Hello! ASCII only.' and 'tools' not in doc
        elif kw.get('compacting'):
            text=bytes(x if x>=32 else 32 for x in ASSETS['compact'][2]).decode()
            assert doc['instructions']==text+'~24/48' and 'tools' not in doc
            assert doc['input'][0]['content']==kw['context'].decode()
        else:
            assert doc['tools']==json.loads(ASSETS['tools'][2])
            text=bytes(x if x>=32 else 32 for x in ASSETS['identity'][2]).decode()
            assert doc['instructions'].startswith(text)
            assert doc['input'][0]['content'].endswith(PROMPT.decode())
        rows.append(dict(name=name,body_bytes=len(v.body),tls_records=len(v.transmitted),
                         phase_reads=len(v.disk_reads),asset_reads=v.asset_reads,stack_low=hex(v.lowest_stack)))
        print(name,'PASS',rows[-1],flush=True)
    report=dict(passed=True,quick=args.quick,cases=len(rows),mapped_conventional_ram_bytes=16384,
        core_sha256=INFO['core_sha256'],aux_bytes=INFO['aux_bytes'],r_bytes=INFO['r_bytes'],x_bytes=INFO['x_bytes'],rows=rows,
        limits=[__doc__,'Tool continuation, far-memory sources, failure handling, scheduler and response lifetimes are covered by separate gates.'])
    (OUT/('requests-quick.json' if args.quick else 'requests-gate.json')).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='rows'},indent=2))

if __name__=='__main__':main()
