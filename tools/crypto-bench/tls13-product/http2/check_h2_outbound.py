#!/usr/bin/env python3
"""Real 8086 credit pump, AEAD, disk swaps and TCP sends in exactly 16 KiB.

Request HEADERS and JSON production remain fixture leaves. The tested X-side
sender frames DATA and grants its first response window on the target. BIOS,
NIC transmit/receive and the resident abort return are synthetic leaves.
"""
from image_binding import TEST_IMAGE
from pathlib import Path
import argparse, hashlib, json, struct, types
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import *

HERE=Path(__file__).resolve().parent; OUT=TEST_IMAGE
import check_phase_bridge as P
R=P.R; INFO=json.loads((OUT/'build.json').read_text()); P.INFO=INFO;P.OUT=OUT
R.CORE=(OUT/'SEED.SYS').read_bytes();R.LISTING=(OUT/'SEED.SYS.lst').read_text()
R.POST=(OUT/'h2_post.bin').read_bytes();R.KEND=0x2800
R.META['labels']=dict(INFO['labels'])
assert hashlib.sha256(R.CORE).hexdigest()==INFO['core_sha256']
UPLOAD=(OUT/'upload.bin').read_bytes();UPLOAD_ENTRY=int.from_bytes(UPLOAD[:2],'little')
CLIENT_KEY=hashlib.sha256(b'outbound component synthetic key').digest()
CLIENT_IV=bytes(range(44,56));SOURCE=bytes((i*43+19)%256 for i in range(512))
POINTER_SPAN=(R.symbol('tls_app_data_ptr'),R.symbol('tls_app_plain_ptr')+2)
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.settings import SettingCodes
from h2.events import DataReceived,StreamEnded
from hpack import Encoder

def settings_window(n):return R.frame(4,b'\0\4'+n.to_bytes(4,'big'),stream=0)
def update(n,stream=1):return R.frame(8,n.to_bytes(4,'big'),stream=stream)
def ticket():
    body=struct.pack('>I',3600)+b'\x11\x22\x33\x44\x05nonce\0\x06ticket\0\0'
    return b'\4'+len(body).to_bytes(3,'big')+body

class VM(P.VM):
    def __init__(self,chunk=458):
        self.transmitted=[];self.outgoing=bytearray();self.client_seq=0
        self.fail_send=None;self.on_plain=None;self.source_live=False
        super().__init__(chunk)
        self.u.mem_write(0x0900,UPLOAD)
        for name,value in [('tls_client_write_key',CLIENT_KEY),('tls_client_write_iv',CLIENT_IV),
                           ('tls_client_record_seq',bytes(8))]:self.u.mem_write(R.S[name],value)
        self.u.mem_write(R.symbol('nic_vt_transmit'),struct.pack('<H',0x0542))
        self.u.hook_add(UC_HOOK_CODE,self.transmit,begin=0x0542,end=0x0542)
        self.u.hook_add(UC_HOOK_CODE,lambda u,a,z,d:setattr(self,'verified',False),
            begin=R.symbol('tls_receive_application_data'),end=R.symbol('tls_receive_application_data'))
        self.context=self.read(0x3b9c,0x3f00-0x3b9c)
    def guard(self,u,access,addr,size,value,data):
        if not self.running:return
        if self.phase=='abort':return super().guard(u,access,addr,size,value,data)
        spans=[(0x0619,0x061c),(R.H2,R.H2+86),(0x06b0,0x0900),(0x0f00,0x1000),
               (R.WORK,0x3b9c),(0x3f00,0x4000),POINTER_SPAN]
        if self.phase=='post' or self.verified:spans.append((R.LIVE,R.WORK))
        if self.entry==UPLOAD_ENTRY:spans.append((R.LIVE+16,R.LIVE+18))
        if self.in_swap or self.phase=='post':spans.append((0x2600,0x2600+len(R.POST)-3584))
        assert any(a<=addr and addr+size<=b for a,b in spans),('write',self.phase,hex(addr),size)
        if self.source_live and self.read(R.H2+61,1)==b'\1' and R.DATA<=addr<R.CTL:
            assert self.read(addr,size)==int(value).to_bytes(size,'little'),('source changed',hex(addr))
        if 0x3f00<=addr<0x4000:self.lowest_stack=min(self.lowest_stack,addr)
    def transmit(self,u,addr,size,data):
        si=u.reg_read(UC_X86_REG_SI);n=u.reg_read(UC_X86_REG_CX)
        assert si==0x0700 and 54<n<=512,('packet bounds',hex(si),n)
        raw=self.read(si,n);self.transmitted.append(raw)
        failed=self.fail_send==len(self.transmitted)
        wire=raw[54:];total=5+int.from_bytes(wire[3:5],'big');wire=wire[:total]
        nonce=bytearray(CLIENT_IV)
        for i,b in enumerate(self.client_seq.to_bytes(8,'big')):nonce[4+i]^=b
        plain=ChaCha20Poly1305(CLIENT_KEY).decrypt(bytes(nonce),wire[5:],wire[:5])
        assert plain[-1]==0x17
        if not failed:
            self.client_seq+=1;self.outgoing.extend(plain[:-1])
            if self.on_plain:self.on_plain(plain[:-1])
        R.D.near_return(u,failed)
    def receive(self,u,addr,size,data):
        # The disk bridge must have completed a K restore before ingress.
        assert self.phase=='K',self.phase
        return super().receive(u,addr,size,data)
    def operate(self,entry):
        self.switch('K');self.verified=False
        # Actual K uses this caller-owned frame only after a partial disk swap.
        self.u.mem_write(0x0682,struct.pack('<H',0x3ffe))
        self.in_swap=True
        try:ok=self.call(entry)
        finally:self.in_swap=False
        assert self.read(0x0900,len(UPLOAD))==UPLOAD,'packet/loader overwrote sender'
        assert self.read(0x3b9c,0x3f00-0x3b9c)==self.context
        assert not any(self.read(R.S['tls_app_record_buffer'],577)),'TX/prefix retirement'
        return ok
    def reserve(self,expected=True):
        before=self.read(R.DATA,512)
        ok=self.operate(R.symbol('h2_tx_reserve'));assert ok==expected,('reserve',ok,expected,self.read(R.H2,68).hex())
        if self.phase!='abort':assert self.read(R.DATA,512)==before,'source lost while receiving'
        return self.u.reg_read(UC_X86_REG_AX) if ok else None
    def send(self,payload,end=False,expected=True):
        self.u.mem_write(0x3912+14,payload)
        self.u.reg_write(UC_X86_REG_AX,len(payload));self.u.reg_write(UC_X86_REG_DX,int(end))
        ok=self.operate(UPLOAD_ENTRY);assert ok==expected,('send',ok,expected,len(payload),end)
        return ok
    def stage(self,value=SOURCE):
        assert len(value)==512 and self.read(R.H2+61,1)==b'\1'
        self.u.mem_write(R.DATA,value);self.source_live=True
    def ready(self,window=65535):
        self.append(R.settings()+settings_window(window));self.record();assert self.post(1)
        assert self.u16(R.LIVE+16)==0 and self.read(R.H2+61,1)==b'\1'
        self.replies.clear();self.stage()

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--quick',action='store_true');args=ap.parse_args()
    rows=[]
    def record(name,v,**kw):
        rows.append(dict(name=name,wire_records=len(v.transmitted),disk_reads=len(v.disk_reads),**kw))
        print(name,'PASS',flush=True)
    # Independent signed-window arithmetic, including asymmetric connection
    # and stream limits, a negative SETTINGS decrease, and 31-bit maxima.
    cases=[(1,65535,1),(426,65535,426),(427,65535,427),(428,65535,427),
           (65535,1,1),(65535,426,426),(0x7fffffff,0x7fffffff,427)]
    for stream,connection,want in cases:
        v=VM();v.ready();v.u.mem_write(R.H2+28,struct.pack('<II',stream,connection))
        assert v.reserve()==want;before=len(v.transmitted)
        v.send(SOURCE[:want]);assert v.read(R.DATA,512)==SOURCE
        assert v.u16(R.H2+62)==0 and len(v.transmitted)==before+1
        assert int.from_bytes(v.read(R.H2+28,4),'little')==stream-want
        assert int.from_bytes(v.read(R.H2+32,4),'little')==connection-want
        assert v.outgoing==R.frame(0,SOURCE[:want])
        record(f'window-min-{stream}-{connection}',v)
    for chunk in ((458,) if args.quick else (1,31,458)):
        v=VM(chunk);v.ready(0)
        v.append(R.frame(6,b'12345678',stream=0)[:16])
        v.append(ticket(),kind=0x16)
        v.append(b'8'+update(29))
        assert v.reserve()==29 and v.read(R.DATA,512)==SOURCE
        assert v.outgoing==R.frame(6,b'12345678',1,0)
        assert v.read(0xd00,0x134)==b'\xa5'*0x134,'normal NST touched cold/native capsule'
        v.send(SOURCE[:29],end=True)
        assert v.outgoing.endswith(R.frame(0,SOURCE[:29],1)+update(512))
        assert v.read(R.DATA,512)==bytes(512) and v.u16(R.LIVE+16)==512
        v.append(R.response(b'fortytwo'));v.record();assert v.output==b'fortytwo'
        record('zero-window-NST-split-PING-'+str(chunk),v)
    v=VM();v.ready(1000);assert v.reserve()==427;v.send(SOURCE[:427])
    # Consumed 427; new initial window 0 => -427, then +456 => 29.
    v.append(settings_window(0));v.append(update(456))
    v.u.mem_write(R.H2+32,bytes(4));v.append(update(100,0))
    assert v.reserve()==29 and int.from_bytes(v.read(R.H2+28,4),'little',signed=True)==29
    v.send(b'x'*29);record('negative-stream-and-empty-connection',v)
    v=VM();v.ready(0);v.send(b'',end=True)
    assert v.outgoing==R.frame(0,b'',1)+update(512) and not any(v.read(R.DATA,512))
    record('zero-window-empty-END_STREAM',v)
    for name,plain,forge in [
        ('forged-window',update(100),True),
        ('unexpected-DATA',R.frame(0,b'bad'),False),
        ('early-final-headers',R.frame(1,R.encoded([(b':status',b'413')]),5),False),
        ('peer-GOAWAY',R.frame(7,b'\0\0\0\1'+bytes(4),stream=0),False),
        ('RST-stream',R.frame(3,bytes(4)),False),
    ]:
        v=VM();v.ready(0);v.append(plain,forge=forge);v.reserve(False)
        assert not v.outgoing and v.u16(R.H2+62)==0
        record(name,v)
    v=VM();v.ready(0);v.append(R.frame(6,b'12345678',stream=0)+update(10))
    v.fail_send=1;v.reserve(False);record('control-send-failure',v)
    # Every post-tag phase read may partly overwrite its destination before
    # failing; only the resident owner frame may receive that failed return.
    if not args.quick:
        for fail in range(1,17):
            v=VM();v.ready(0);v.append(update(10));v.disk_reads.clear();v.fail_read=fail
            v.reserve(False);assert len(v.disk_reads)==fail
            if fail>1:assert not any(v.read(R.LIVE,0x3b9c-R.LIVE))
            record('partial-disk-credit-'+str(fail),v)
    # Full legal TLS content during an upload must preserve all 512 source
    # bytes, including when the authenticated control budget is exhausted.
    if not args.quick:
        v=VM();v.ready(0);tail=update(427)
        v.append(R.frame(0xee,bytes(16384-len(tail)-9))+tail,pad=239)
        assert v.reserve()==427;record('maximum-record-with-live-source',v)
        v=VM();v.ready(0);v.append(R.frame(6,b'12345678',stream=0)*76)
        v.reserve(False);record('authenticated-control-exhaustion',v)
    # Independent HTTP/2 peer: request/body setup is a fixture leaf, but all
    # DATA, WINDOW_UPDATE, reply ACKs and their TLS/TCP records are target code.
    body=b'{"input":"'+b'a'*(70000 if not args.quick else 1500)+b'"}'
    server=H2Connection(config=H2Configuration(client_side=False));server.initiate_connection()
    preface=b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'+R.frame(4,b'\0\1'+bytes(4)+b'\0\2'+bytes(4)+b'\0\4'+bytes(4),stream=0)
    server.receive_data(preface)
    v=VM();v.append(server.data_to_send());v.record();server.receive_data(bytes(v.replies));v.replies.clear()
    assert v.post(1);v.stage()
    encoder=Encoder();encoder.header_table_size=0
    headers=encoder.encode([(b':method',b'POST'),(b':scheme',b'https'),(b':authority',b'api.openai.com'),
        (b':path',b'/v1/responses'),(b'content-length',str(len(body)).encode())])
    server.receive_data(R.frame(1,headers,4));received=bytearray();ended=[]
    def peer(plain):
        for event in server.receive_data(plain):
            if isinstance(event,DataReceived):
                received.extend(event.data);server.acknowledge_received_data(event.flow_controlled_length,event.stream_id)
            if isinstance(event,StreamEnded):ended.append(event.stream_id)
        pending=server.data_to_send()
        if pending:v.append(pending)
    v.on_plain=peer;off=0
    while off<len(body):
        quota=v.reserve();n=min(quota,len(body)-off)
        v.stage((body[off:off+512]+bytes(512))[:512])
        v.send(body[off:off+n],end=off+n==len(body));off+=n
    assert bytes(received)==body and ended==[1]
    assert server.local_flow_control_window(1)==512
    assert v.u16(R.LIVE+16)==512 and not any(v.read(R.DATA,512))
    record('independent-h2-large-upload',v,body_bytes=len(body),streams=1)
    report=dict(passed=True,quick=args.quick,cases=len(rows),mapped_ram_bytes=16384,
        core_sha256=INFO['core_sha256'],k_bytes=INFO['k_bytes'],post_bytes=INFO['post_bytes'],
        upload_bytes=len(UPLOAD),upload_sha256=hashlib.sha256(UPLOAD).hexdigest(),rows=rows,
        limits=[__doc__,'R/X serialization, caller retirement, cold-call rebinding and lifetime guards are covered by separate composition gates.',
        'This component gate does not establish live target acceptance.'])
    (OUT/('outbound-quick.json' if args.quick else 'outbound-gate.json')).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='rows'},indent=2))

if __name__=='__main__':main()
