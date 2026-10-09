#!/usr/bin/env python3
"""Execute cold controllers, real record crypto, H2/NST and sector swaps.

Entry supplies the existing post-FO/restored-SYM ABI. Network arrivals and
BIOS disk are host leaves. Fresh completion stops after the existing lifecycle
has constructed the resumed-HELLO inputs, before repeated KeyGen. Final mode
executes the real success capsule but the parent scheduler's unlock is outside
this gate. This is not bootable/live acceptance.
"""
from image_binding import TEST_IMAGE
from pathlib import Path
import argparse,hashlib,hmac,importlib.util,json,re,struct,sys
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from unicorn import UC_HOOK_CODE,UC_HOOK_INTR
from unicorn.x86_const import *
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--quick',action='store_true')
parser.add_argument('--image-dir',type=Path,default=TEST_IMAGE)
ARGS=parser.parse_args() if __name__=="__main__" else parser.parse_args([]);OUT=ARGS.image_dir.resolve()
sys.path.insert(0,str(HERE));import check_tls_receiver as R
INFO=json.loads((OUT/'build.json').read_text())
R.CORE=(OUT/'SEED.SYS').read_bytes();R.LISTING=(OUT/'SEED.SYS.lst').read_text()
R.KEND=0x2800;R.META['labels']=dict(INFO['labels'])
assert hashlib.sha256(R.CORE).hexdigest()==INFO['core_sha256']
spec=importlib.util.spec_from_file_location('cold_liveness_builder',ROOT/'tools/crypto-bench/tls13-product/build_system_ram_product_pack.py')
B=importlib.util.module_from_spec(spec);sys.modules[spec.name]=B;spec.loader.exec_module(B)
CLIENT_KEY=hashlib.sha256(b'cold H2 client application key').digest()
CLIENT_IV=bytes(range(20,32));MASTER=hashlib.sha256(b'cold H2 master').digest()
SEED=hashlib.sha256(b'cold H2 root seed').digest();UI=bytes(range(31,51))
TICK=123456
POINTER_SPAN=(R.symbol('tls_app_data_ptr'),R.symbol('tls_app_plain_ptr')+2)

def ticket(identity=b'identity',nonce=b'nonce'):
    body=struct.pack('>I',3600)+b'\x11\x22\x33\x44'+bytes([len(nonce)])+nonce
    body+=struct.pack('>H',len(identity))+identity+b'\0\0'
    return b'\x04'+len(body).to_bytes(3,'big')+body
def psk(nonce):
    return hmac.new(MASTER,b'\0\x20\x10tls13 resumption'+bytes([len(nonce)])+nonce+b'\1',hashlib.sha256).digest()
def symbol_in(name,phase):return B.label_address(OUT/(phase+'.lst'),name,0x0900)

class VM(R.VM):
    def __init__(self,fresh,chunk=458):
        self.fresh=fresh;self.disk_reads=[];self.fail_read=None;self.transmitted=[]
        self.fail_send=None;self.ingress_tick=None;self.prepared=False;self.success=False
        self.owner='entry';self.jit_writes=[];self.root_sp=0x3ffe
        super().__init__(chunk)
        self.phase='cold'
        name='fresh_post' if fresh else 'final_post'
        sym='acquisition_sym_system' if fresh else 'resumption_sym_system'
        self.u.mem_write(0x1800,(TEST_IMAGE/'pack'/(sym+'.bin')).read_bytes())
        slot=next(row for row in INFO['controllers'] if row['name']==name)
        self.u.mem_write(0x0900,R.CORE[slot['start']*512:(slot['start']+slot['sectors'])*512])
        for addr,raw in [(0x3838,CLIENT_KEY),(0x3858,CLIENT_IV),(0x3864,R.KEY),(0x3884,R.IV),
                         (0x3890,MASTER),(0x38e0,(1).to_bytes(8,'big')),(0x38e8,bytes(8)),
                         (0x35c0,SEED+b'\xa5\x5a')]:self.u.mem_write(addr,raw)
        self.u.mem_write(0x3f00,struct.pack('<HHH',self.root_sp,self.root_sp^0xffff,0xa55a)+UI+b'\x07\x00')
        self.u.mem_write(0x046c,struct.pack('<I',TICK))
        self.u.mem_write(R.symbol('fs_sectors_per_track'),b'\x08')
        self.u.mem_write(R.symbol('fs_heads'),b'\x01')
        self.u.mem_write(R.symbol('loop_cache_count'),bytes(2))
        self.u.mem_write(0x05fe,b'\x00\xff')
        self.u.mem_write(R.symbol('nic_vt_transmit'),struct.pack('<H',0x0542))
        self.u.hook_add(UC_HOOK_INTR,self.bios)
        self.u.hook_add(UC_HOOK_CODE,self.transmit,begin=0x0542,end=0x0542)
        self.u.hook_add(UC_HOOK_CODE,self.before_load,begin=0x10c4,end=0x10c4)
        for label,owner in [('cold_failed','failed'),('cold_send','sending'),
                            ('.receive','receiving'),('cold_h2','h2'),
                            ('cold_commit_fresh' if fresh else 'cold_commit_final','commit')]:
            address=symbol_in(label,name)
            def mark(u,a,z,d,o=owner):self.owner=o
            self.u.hook_add(UC_HOOK_CODE,mark,begin=address,end=address)
        self.u.hook_add(UC_HOOK_CODE,self.success_entry,begin=0x0f00,end=0x0f00)
        self.u.hook_add(UC_HOOK_CODE,self.abort_entry,begin=0x0f60,end=0x0f60)
        bridge_entry=INFO.get('bridge_entry',0x0898)
        self.u.hook_add(UC_HOOK_CODE,lambda u,a,z,d:setattr(self,'phase','post'),begin=bridge_entry,end=bridge_entry)
        self.u.hook_add(UC_HOOK_CODE,lambda u,a,z,d:setattr(self,'verified',False),
            begin=R.symbol('tls_receive_application_data'),end=R.symbol('tls_receive_application_data'))
        self.before_context=self.read(0x3b9c,0x3f00-0x3b9c)
    def post(self,index):return True  # Actual cold entry initializes via disk.
    def guard(self,u,access,addr,size,value,data):
        if not self.running:return
        spans=[(0x0500,0x0600),(0x0619,0x061c),(0x062e,0x0684),(0x06b0,0x0900),
               (0x0d00,0x1000),(0x1800,0x3b9c),(0x3f00,0x4000),
               POINTER_SPAN]
        if self.owner in ('success','abort'):
            spans.append((0x0700,0x0f60))
        assert any(a<=addr and addr+size<=b for a,b in spans),('cold write',self.owner,self.phase,hex(addr),size)
        if 0x3f00<=addr<0x4000:self.lowest_stack=min(self.lowest_stack,addr)
    def receive(self,u,addr,size,data):
        # Real NIC receive storage is clobbered on every host delivery.
        if self.pos==len(self.wire):R.D.near_return(u,True);return
        if self.ingress_tick is None:
            self.ingress_tick=TICK+9;u.mem_write(0x046c,struct.pack('<I',self.ingress_tick))
        n=min(self.chunk,len(self.wire)-self.pos)
        part=self.wire[self.pos:self.pos+n];self.pos+=n
        u.mem_write(0x0700,b'\x9b'*512);u.mem_write(0x0700,part)
        self.w16('tcp_rx_payload_ptr',0x0700);self.w16('tcp_rx_payload_len',n)
        R.D.near_return(u,False)
    def transmit(self,u,addr,size,data):
        si=u.reg_read(UC_X86_REG_SI);n=u.reg_read(UC_X86_REG_CX)
        assert si==0x0700 and n<=512
        raw=self.read(si,n);self.transmitted.append(raw)
        failed=self.fail_send==len(self.transmitted)
        R.D.near_return(u,failed)
    def before_load(self,u,addr,size,data):
        key=u.reg_read(UC_X86_REG_AX)
        # The fresh owner reaches the unchanged transition, executes its
        # actual two-sector lifecycle prepare call, then attempts res_sym.
        if self.fresh and key==0x0c6d and self.owner=='commit':
            self.prepared=True;u.emu_stop()
    def bios(self,u,interrupt,data):
        assert interrupt==0x13
        ax=u.reg_read(UC_X86_REG_AX);bx=u.reg_read(UC_X86_REG_BX)
        cx=u.reg_read(UC_X86_REG_CX);dx=u.reg_read(UC_X86_REG_DX)
        assert ax==0x0201,'write or multi-sector disk access'
        cylinder=(cx>>8)|((cx&0xc0)<<2);sector=cx&63;head=dx>>8
        file_sector=(cylinder+head)*8+sector-1-11
        dest=u.reg_read(UC_X86_REG_ES)*16+bx
        assert (file_sector==210 and dest==0x0700) or (
            4<=file_sector<19 and dest==0x1800+(file_sector-(4 if file_sector<12 else 12))*512) or (
            169<=file_sector<175 and dest==0x1800+(file_sector-169)*512) or (
            self.fresh and 145<=file_sector<147 and dest==0x0900+(file_sector-145)*512),(file_sector,hex(dest))
        ordinal=len(self.disk_reads)+1;failed=self.fail_read==ordinal
        self.disk_reads.append(dict(sector=file_sector,destination=dest,failed=failed))
        u.mem_write(dest,b'\xcc'*256 if failed else R.CORE[file_sector*512:(file_sector+1)*512])
        u.ctl_remove_cache(dest,dest+512)
        if file_sector==11:self.phase='K'
        if file_sector==174:self.phase='NST'
        R.D.set_carry(u,failed)
    def success_entry(self,u,addr,size,data):
        if not self.fresh:self.owner='success';self.success=True
    def abort_entry(self,u,addr,size,data):self.owner='abort'
    def run(self,ok=True):
        self.entry=0x0900;self.running=True
        self.u.mem_write(self.root_sp,struct.pack('<H',R.RETURN))
        self.u.reg_write(UC_X86_REG_SP,self.root_sp);self.u.reg_write(UC_X86_REG_EFLAGS,2)
        try:self.u.emu_start(0x0900,R.RETURN+1,count=100_000_000)
        finally:self.running=False
        assert self.prepared or self.u.reg_read(UC_X86_REG_IP)==R.RETURN,('no return',hex(self.u.reg_read(UC_X86_REG_IP)))
        actual=self.prepared if self.fresh else self.success and not bool(self.u.reg_read(UC_X86_REG_EFLAGS)&1)
        assert actual==ok,('liveness',self.fresh,actual,ok,self.owner,self.read(R.H2,68).hex())
        assert self.read(0x3b9c,0x3f00-0x3b9c)==self.before_context
        if self.prepared:
            assert self.read(0x3400,32)==SEED
            assert self.read(0x3460,32)==psk(b'nonce')
            assert self.read(0x3480,6)==b'\x11\x22\x33\x44\x08\x00'
            assert self.read(0x3486,8)==b'identity'
            assert self.read(0x35c0,8)==struct.pack('<IHH',self.ingress_tick,0,3600)
            assert not any(self.read(0x0d00,0x134)) and not any(self.read(R.H2,86))
        else:
            assert self.u.reg_read(UC_X86_REG_SP)==self.root_sp+2
            assert self.read(0x0f55,20)==UI and self.read(0x0f33,1)==b'\x07'
            assert not any(self.read(0x3f00,28)) and not any(self.read(0x0700,0x0800))
            assert self.read(0x06c4,1)==b'\0','parent alone may publish readiness'
            if ok:
                assert self.read(0x3600,32)==CLIENT_KEY and self.read(0x3620,32)==R.KEY
                assert self.read(0x3640,12)==CLIENT_IV and self.read(0x364c,12)==R.IV
                assert self.read(R.H2+47,3)==b'\1\0\0'
                assert not any(self.read(0x3668,0x3b9c-0x3668))
            else:
                assert not any(self.read(0x1800,0x3b9c-0x1800))
                assert not any(self.read(R.H2,86))
        # Independently decrypt every outbound TLS record. This includes
        # actual resident TCP framing and record sealing, never credentials.
        plaintext=b'';seq=1
        for frame in self.transmitted:
            if len(frame)<=54:continue
            wire=frame[54:]
            # Minimum Ethernet padding can extend short empty TCP controls.
            if wire[0]!=0x17:continue
            total=5+int.from_bytes(wire[3:5],'big');wire=wire[:total]
            nonce=bytearray(CLIENT_IV)
            for i,b in enumerate(seq.to_bytes(8,'big')):nonce[4+i]^=b
            raw=ChaCha20Poly1305(CLIENT_KEY).decrypt(bytes(nonce),wire[5:],wire[:5])
            assert raw[-1]==0x17;plaintext+=raw[:-1];seq+=1
        self.plaintext=plaintext
        return self

def fixture(fresh,chunk=458,*,ack=True,ticket_ok=True,forge=False,ping=False):
    v=VM(fresh,chunk)
    plain=R.frame(4,stream=0)
    if ack:plain+=R.frame(4,flags=1,stream=0)
    if ping:plain+=R.frame(6,b'12345678',stream=0)
    v.append(plain,forge=forge)
    if fresh and ticket_ok:v.append(ticket(),kind=0x16)
    return v

def main():
    args=ARGS
    rows=[];baselines={}
    for fresh in (False,True):
        for chunk in ((458,) if args.quick else (1,31,458)):
            v=fixture(fresh,chunk,ping=True).run()
            assert v.plaintext==R.frame(4,flags=1,stream=0)+R.frame(6,b'12345678',1,0)
            rows.append(dict(name=('fresh' if fresh else 'final')+'-disk-crypto-'+str(chunk),reads=len(v.disk_reads),
                reply_bytes=len(v.plaintext),stack_low=hex(v.lowest_stack)))
            print(rows[-1]['name'],'PASS',flush=True)
            if chunk==458:baselines[fresh]=len(v.disk_reads)
        for name,kw in [('no-settings-ack',dict(ack=False)),('forged-settings',dict(forge=True))]:
            v=fixture(fresh,**kw).run(False);rows.append(dict(name=('fresh-' if fresh else 'final-')+name))
        v=fixture(fresh);v.fail_send=1;v.run(False)
        rows.append(dict(name=('fresh-' if fresh else 'final-')+'failed-control-transmit'))
    v=fixture(True,ticket_ok=False).run(False);rows.append(dict(name='fresh-no-ticket'))
    if not args.quick:
        for fresh in (False,True):
            v=VM(fresh);pings=R.frame(6,b'12345678',stream=0)*74
            v.append(R.settings()+pings)
            if fresh:v.append(ticket(),kind=0x16)
            v.run();assert v.plaintext==R.frame(4,flags=1,stream=0)+R.frame(6,b'12345678',1,0)*74
            rows.append(dict(name=('fresh-' if fresh else 'final-')+'multi-record-control-send',reply_bytes=len(v.plaintext)))
            v=VM(fresh);v.append(R.frame(4,stream=0)+R.frame(6,b'12345678',stream=0)[:16])
            v.append(ticket(),kind=0x16)
            v.append(b'8'+R.frame(4,flags=1,stream=0))
            v.run();assert v.plaintext==R.frame(4,flags=1,stream=0)+R.frame(6,b'12345678',1,0)
            rows.append(dict(name=('fresh-' if fresh else 'final-')+'NST-during-partial-PING'))
            for label,plain in [('unexpected-data',R.settings()+R.frame(0,b'x')),
                    ('peer-goaway',R.settings()+R.frame(7,bytes(8),stream=0)),
                    ('control-exhaustion',R.settings()+pings+R.frame(6,b'12345678',stream=0)),
                    ('ACK-before-SETTINGS',R.frame(4,flags=1,stream=0))]:
                v=VM(fresh);v.append(plain);v.run(False)
                rows.append(dict(name=('fresh-' if fresh else 'final-')+label))
        v=VM(False);prefix=R.settings();v.append(prefix+R.frame(0xee,bytes(16384-len(prefix)-9),stream=0),pad=239)
        v.run();assert v.plaintext==R.frame(4,flags=1,stream=0)
        rows.append(dict(name='final-maximum-TLS-content-and-padding'))
    # All actual phase read positions: partial destination writes before CF.
    if not args.quick:
        for fresh,count in baselines.items():
            for fail in range(1,count+1):
                v=fixture(fresh,ping=True);v.fail_read=fail;v.run(False)
                assert len(v.disk_reads)==fail
                rows.append(dict(name=('fresh' if fresh else 'final')+'-partial-disk-'+str(fail)))
                if fail%10==0:print('disk matrix',fresh,fail,'/',count,flush=True)
    report=dict(passed=True,quick=args.quick,cases=len(rows),mapped_ram_bytes=16384,
        core_sha256=hashlib.sha256(R.CORE).hexdigest(),controllers=INFO['controllers'],rows=rows,
        limits=[__doc__,'Real NIC timing, interrupts, full stack/register erasure, root-to-publication composition and all normal H2 callers remain to be validated.'])
    (OUT/('liveness-quick.json' if args.quick else 'liveness-gate.json')).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='rows'},indent=2))
if __name__=='__main__':main()
