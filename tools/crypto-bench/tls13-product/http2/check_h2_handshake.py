#!/usr/bin/env python3
"""Execute the 8088 ALPN + Finished/controller paths in exactly 16 KiB.

TCP/ACK, BIOS phase read and later FO/CV are explicit leaves. This verifies
handshake transcript/record composition; live boot acceptance is separate.
"""
from image_binding import TEST_IMAGE
from pathlib import Path
import hashlib,hmac,importlib.util,json,os,re,struct,sys
from types import SimpleNamespace
os.environ['TLS13_POC_K14']='1'
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
PREFACE=True
POC=ROOT/'tools/crypto-bench/tls13-poc';OUT=TEST_IMAGE;WORK=OUT/'pack'
sys.path.insert(0,str(POC))
import hello_check as H
import check_tls13_sym_overlay as S
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE
from unicorn.x86_const import *
S.RETURN_SENTINEL=0x0480
EE=bytes.fromhex('0800000b0009001000050003026832')
EE_SNI_FIRST=bytes.fromhex('0800000f000d00000000001000050003026832')
EE_SNI_LAST=bytes.fromhex('0800000f000d00100005000302683200000000')
VALID_EE=(EE,EE_SNI_FIRST,EE_SNI_LAST)
ALPN=EE[6:]
H2_PREFACE=b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'+bytes.fromhex('000018040000000000')+b''.join(struct.pack('>HI',k,v) for k,v in ((1,0),(2,0),(4,0),(6,4096)))
LIVENESS=H2_PREFACE if PREFACE else S.HEAD_REQUEST
report=json.loads((OUT/'build.json').read_text())
phases={i['name']:i for i in report['phases']}
NAMES={'fresh_hello':'fresh_hello_system','resumed_hello':'resumed_hello_system',
       'acq_sym':'acquisition_sym_system','res_sym':'resumption_sym_system'}
def blob(n):return (WORK/(NAMES.get(n,n)+'.bin')).read_bytes()
def label(n, name, origin=0x900):
    lines=(WORK/(NAMES.get(n,n)+'.lst')).read_text().splitlines()
    for i,line in enumerate(lines):
        if re.search(r'^\s*\d+\s+(?:<\d+>\s*)?'+re.escape(name)+r':?\s*$',line):
            for row in lines[i:]:
                m=re.match(r'^\s*\d+\s+([0-9A-F]{8})\s',row)
                if m:return origin+int(m[1],16)
    raise AssertionError(name)
def floor(vm): vm.uc.mem_unmap(0x4000,0xc000);return vm
def deterministic(s,n):return hashlib.shake_256(s).digest(n)
F=H.make_fixture()
def client(resume, identity=None):
    extensions=H.base_extensions(F.ek)
    assert extensions[-18:]==H.extension(21,bytes(14))
    extensions=extensions[:-18]+ALPN+extensions[-18:]+H.extension(45,b'\x01\x01')
    if resume:
        identity=F.identity if identity is None else identity
        ids=H.u16(len(identity)+6)+H.u16(len(identity))+identity+F.age
        extensions+=H.extension(41,ids+H.u16(33)+b'\x20'+bytes(32))
    msg=H.handshake(1,H.client_body_prefix(F.random,F.session,extensions))
    if resume:msg=msg[:-32]+H.resumption_binder(F.psk,msg[:-35])
    return msg,b'\x16\x03\x01'+H.u16(len(msg))+msg
def hello_vm(resume,identity=None):
    name='resumed_hello' if resume else 'fresh_hello'
    image=blob(name); vm=floor(H.Overlay(image,H.parse_header(image)))
    vm.write(0x08c0,F.ek)
    if resume:
        identity=F.identity if identity is None else identity
        vm.write(0x3420,F.random+F.session+F.psk+F.age+struct.pack('<H',len(identity)))
        vm.write(0x3000,identity)
    else:vm.write(0x0560,F.random+F.session)
    vm.call(int(resume));wire,fragments=H.drain_client(vm,F.ek)
    expected=client(resume,identity)
    assert wire==expected[1],('ClientHello',name,len(wire))
    exts=H.client_extensions(wire[5:])
    assert (16,b'\0\x03\x02h2') in exts and all(k!=28 for k,v in exts)
    if resume:assert exts[-1][0]==41 and wire[-32:]==H.resumption_binder(F.psk,wire[5:-35])
    return vm,expected[0]

def hello_cases():
    for resume,n in [(False,0),(True,1),(True,64),(True,191),(True,192)]:
        identity=deterministic(b'identity',n) if resume else None
        vm,msg=hello_vm(resume,identity)
        vm.call(4)
        replay,_=H.drain_client(vm,F.ek)
        assert replay==client(resume,identity)[1]
        server=H.build_server(F.session,F.ciphertext,F.server_x,resumed=resume)
        H.feed_server(vm,server,cuts=(1,2,31,384,71))
        H.verify_transcript_handoff(vm,msg+server)
        assert vm.read(H.HELLO_DIGEST,32)==hashlib.sha256(msg+server).digest()
        vm.call(8)
        assert not any(vm.read(0x3420 if resume else 0x0560,102 if resume else 64))
        print('hello',resume,n,'PASS',flush=True)
    return 5

def ret(uc,carry=False):
    sp=uc.reg_read(UC_X86_REG_SP)
    ip=int.from_bytes(uc.mem_read(sp,2),'little')
    uc.reg_write(UC_X86_REG_SP,sp+2);uc.reg_write(UC_X86_REG_IP,ip)
    uc.reg_write(UC_X86_REG_EFLAGS,(uc.reg_read(UC_X86_REG_EFLAGS)&~1)|int(carry))
def hooks(uc,callbacks):
    for addr,fn in callbacks.items():
        uc.hook_add(UC_HOOK_CODE,lambda u,a,s,d,f=fn:f(u),begin=addr,end=addr)

def hello_tail_case(n,step,ack_base):
    vm,msg=hello_vm(True)
    uc=vm.uc;controller='resumed_hello_controller'
    uc.mem_write(0x2a00,blob(controller))
    uc.mem_write(0xf16,bytes(74));uc.mem_write(0x3b90,bytes(12))
    uc.mem_write(0x15e3,struct.pack('<H',0x0484))
    uc.mem_write(0x06f1,struct.pack('>I',ack_base))
    server=H.build_server(F.session,F.ciphertext,F.server_x,resumed=True)
    record=b'\x16\x03\x03'+H.u16(len(server))+server
    tail=deterministic(b'coalesced encrypted prefix',n)
    # Last SH fragment carries every retained protected byte, including 79.
    chunks=[record[i:i+step] for i in range(0,len(record)-1,step)]
    if b''.join(chunks)==record:chunks[-1]+=tail
    else:chunks.append(record[len(b''.join(chunks)):]+tail)
    expected_ack=(ack_base+len(record)+n)&0xffffffff
    reached=[];seen_ack=[]
    def receive(u):
        assert chunks
        chunk=chunks.pop(0);assert len(chunk)<=438
        u.mem_write(0x0700,chunk)
        u.mem_write(0xfe2,struct.pack('<HH',0x0700,len(chunk)))
        ack=int.from_bytes(u.mem_read(0x06f1,4),'big')
        u.mem_write(0x06f1,struct.pack('>I',(ack+len(chunk))&0xffffffff));ret(u)
    def stop(u):reached.append('transition');u.emu_stop()
    def abort(u):reached.append('abort');u.emu_stop()
    def zero(u):seen_ack.append(int.from_bytes(u.mem_read(0x06f1,4),'big'));ret(u)
    hooks(uc,{0x0484:lambda u:ret(u,True),0x14ed:receive,0x13a6:ret,
              vm.header.entries[10]:zero,0xf00:stop,0xf60:abort})
    uc.reg_write(UC_X86_REG_SP,0x4000);uc.reg_write(UC_X86_REG_EFLAGS,2)
    uc.emu_start(label(controller,'.sent',0x2a00),0,count=60000000)
    if n>83:
        assert reached==['abort'] and not seen_ack
    else:
        assert reached==['transition'],reached
        assert seen_ack==[expected_ack],seen_ack
        assert vm.word(0xf16)==n
        held=vm.read(0xf18,min(n,72))+vm.read(0x3b90,max(0,n-72))
        assert held==tail
        assert not chunks
    return 1

def schedule(resume):
    name='res_sym' if resume else 'acq_sym';image=blob(name)
    vm=floor(S.Overlay(image,S.parse_header(image,expected_magic=b'T13SRR2!' if resume else b'T13SRA2!')))
    vm.call(0)
    msg=client(resume)[0]
    server=H.build_server(F.session,F.ciphertext,F.server_x,resumed=resume)
    transcript=msg+server;shared=deterministic(b'K prime',32)+F.server_x
    if resume:
        vm.write(0xdc0,F.psk);vm.call(13)
        early=S.BASE.hkdf_extract(bytes(32),F.psk)
        derived=S.BASE.hkdf_expand_label(early,b'derived',hashlib.sha256(b'').digest(),32)
        expected=S.derive_traffic(S.BASE.hkdf_extract(derived,shared),transcript)
    else:expected=S.derive_handshake(shared,transcript)
    vm.write(S.HELLO_SERVER_X,S.build_hello_handoff(transcript,F.server_x))
    vm.write(S.SHARED_SECRET,shared[:32]+bytes(32));vm.call(15)
    vm.call(14 if resume else 3)
    for a,k in [(S.CLIENT_HS_KEY,'client_key'),(S.SERVER_HS_KEY,'server_key'),
                (S.CLIENT_FINISHED_KEY,'client_finished'),(S.SERVER_FINISHED_KEY,'server_finished')]:
        assert vm.read(a,32)==expected[k]
    return vm.read(0,0x4000),transcript,expected

FIX=S.O.build_integrated_fixture()
def protected_case(resume,template,step=384,ee=EE,bad_tag=False,bad_finished=False,held=0,tail_after=b''):
    memory,transcript,hs=template;name='resumed_protected' if resume else 'fresh_protected'
    before=ee+(b'' if resume else b''.join(FIX.server_flight_messages[1:3]))
    verify=hmac.new(hs['server_finished'],hashlib.sha256(transcript+before).digest(),hashlib.sha256).digest()
    if bad_finished:verify=bytes([verify[0]^1])+verify[1:]
    content=before+b'\x14\0\0\x20'+verify
    record=S.BASE.encrypted_record(hs['server_key'],hs['server_iv'],0,S.O.CONTENT_HANDSHAKE,content)
    if bad_tag:record=record[:-1]+bytes([record[-1]^1])
    wire=b'\x14\x03\x03\x00\x01\x01'+record
    uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,0x4000);uc.mem_write(0,memory)
    uc.mem_write(0x900,blob(name));uc.mem_write(0xf16,struct.pack('<H',held))
    uc.mem_write(0xf18,wire[:min(held,72)])
    uc.mem_write(0x3b90,wire[72:held] if held>72 else bytes(12))
    uc.mem_write(0x15df,struct.pack('<HHH',0x0482,0x0484,0x0486))
    chunks=[wire[i:i+step] for i in range(held,len(wire),step)]
    if chunks:chunks[-1]+=tail_after
    sent=[];terminal=[];authenticated=[]
    guard=deterministic(b'user cfg and arena',0x3f00-0x3b9c)
    uc.mem_write(0x3b9c,guard);uc.mem_write(0x06c4,b'\0')
    def receive(u):
        if not chunks:terminal.append('unexpected receive');u.emu_stop();return
        chunk=chunks.pop(0);u.mem_write(0x700,chunk)
        u.mem_write(0xfe2,struct.pack('<HH',0x700,len(chunk)));ret(u)
    def send(u):
        sent.append(bytes(u.mem_read(u.reg_read(UC_X86_REG_SI),u.reg_read(UC_X86_REG_CX))));ret(u)
    def nic(u):u.mem_write(0x06d5,bytes(2));ret(u)
    def stop(s):
        def f(u):terminal.append(s);u.emu_stop()
        return f
    callbacks={0x0482:ret,0x0484:nic,0x0486:lambda u:ret(u,True),0x13a6:ret,
        0x13bf:send,0x14ed:receive,0x13e2:ret,0x11e5:ret,0x10c4:stop('offline'),
        0xf60:stop('abort')}
    if resume:callbacks[label(name,'resumed_record_authenticated')]=lambda u:authenticated.append(True)
    hooks(uc,callbacks)
    for r in [UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS,UC_X86_REG_CS]:uc.reg_write(r,0)
    uc.reg_write(UC_X86_REG_SP,0x4000);uc.reg_write(UC_X86_REG_EFLAGS,2)
    uc.emu_start(0x900,0,count=80000000)
    okay=ee in VALID_EE and not bad_tag and not bad_finished and not tail_after
    assert terminal==['offline' if okay else 'abort'],(resume,step,held,terminal,hex(uc.reg_read(UC_X86_REG_IP)))
    assert bytes(uc.mem_read(0x3b9c,len(guard)))==guard
    assert uc.mem_read(0x06c4,1)==b'\0','credential capability published'
    if okay:
        finished=hmac.new(hs['client_finished'],hashlib.sha256(transcript+content).digest(),hashlib.sha256).digest()
        expected=S.BASE.encrypted_record(hs['client_key'],hs['client_iv'],0,S.O.CONTENT_HANDSHAKE,b'\x14\0\0\x20'+finished)
        assert len(sent)==2 and sent[0]==expected
        app=S.O._derive_application(hs['handshake_secret'],transcript+content)
        assert sent[1]==S.BASE.encrypted_record(app['client_key'],app['client_iv'],0,S.O.CONTENT_APPLICATION_DATA,LIVENESS)
        if resume:
            assert not any(uc.mem_read(0xf16,74)) and not any(uc.mem_read(0x3b90,12))
    else:assert not sent, 'failed ALPN/AEAD/Finished transmitted a client Finished'
    return 1

def main():
    bound={n:hashlib.sha256(blob(n)).hexdigest() for n in NAMES.keys()|{'fresh_protected','resumed_protected','resumed_hello_controller'}}
    assert all(phases[n]['sha256']==v for n,v in bound.items()), 'stale phase build report'
    assert hashlib.sha256((OUT/'pack.bin').read_bytes()).hexdigest()==report['pack_sha256']
    total=hello_cases()
    for n in [0,1,42,69,70,71,72,73,78,79,80,81,82,83,84]:
        total+=hello_tail_case(n,31,0xfffffff0)
    print('ServerHello coalescence: PASS',flush=True)
    for resume in (False,True):
        template=schedule(resume)
        for ee in VALID_EE:
            for step in (1,2,5,17,31,64,384):total+=protected_case(resume,template,step,ee=ee)
        for bad in [bytes.fromhex('080000020000'),bytes.fromhex('08000006000400000000'),
                    bytes.fromhex('0800000f000d00000001001000050003026832'),
                    bytes.fromhex('0800000f000d00100005000302683200000001')]:
            total+=protected_case(resume,template,ee=bad)
        total+=protected_case(resume,template,bad_tag=True)
        total+=protected_case(resume,template,bad_finished=True)
        total+=protected_case(resume,template,tail_after=b'\0')
        for i in range(len(EE)):
            bad=EE[:i]+bytes([EE[i]^1])+EE[i+1:]
            total+=protected_case(resume,template,ee=bad)
        if resume:
            for held in (1,42,69,70,71,78,79):total+=protected_case(True,template,17,held=held)
            for ee in VALID_EE[1:]:
                for held in (70,71,72,73,79,80,81,82,83):total+=protected_case(True,template,17,held=held,ee=ee)
        print('Protected flight',resume,'PASS',flush=True)
    assert all(hashlib.sha256(blob(n)).hexdigest()==v for n,v in bound.items()), 'candidate changed during test'
    result=dict(passed=True,cases=total,mapped_ram_bytes=16384,pack_sha256=report['pack_sha256'],
        phases=bound,
        limits=[__doc__,'8088 EE profile requires ALPN h2 and permits one empty SNI acknowledgement in either order.',
            'H2 preface/settings transmission is checked; peer ACK/publication integration is still open.' if PREFACE else 'The unchanged HEAD is a temporary sender fixture, not an H2 request.',
            'Real deadline phase preservation of the nine-byte overflow is a separate gate.'])
    (OUT/'handshake-gate.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
