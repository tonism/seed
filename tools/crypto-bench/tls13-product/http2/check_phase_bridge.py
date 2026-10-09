#!/usr/bin/env python3
"""Execute actual resident disk loader, K receiver and H2 swap in exact 16 KiB.

BIOS media, TCP arrivals, the caller's abort anchor, publication and outgoing
control/credit are host leaves. Every sector read/failure, including a partial
sector scribble, executes the emitted transition code.
"""
from image_binding import TEST_IMAGE
from pathlib import Path
import hashlib,json,re,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import check_tls_receiver as R
from unicorn import UC_HOOK_INTR,UC_HOOK_CODE
from unicorn.x86_const import *
HERE=Path(__file__).resolve().parent;OUT=TEST_IMAGE
INFO=json.loads((OUT/'build.json').read_text())
R.CORE=(OUT/'SEED.SYS').read_bytes();R.LISTING=(OUT/'SEED.SYS.lst').read_text()
R.KEND=INFO['labels']['core_link_window_end'];R.META['labels'].update(INFO['labels'])
ABORT=0x04f2
def bridge_symbol(name):
    lines=(OUT/'bridge.lst').read_text().splitlines()
    for i,line in enumerate(lines):
        if re.search(r'\b'+name+r'\s+equ\s+\$',line):
            for line in lines[i:]:
                m=re.match(r'^\s*\d+\s+([0-9A-F]{8})\s',line)
                if m:return INFO['bridge_entry']+int(m[1],16)
    raise AssertionError(name)

class VM(R.VM):
    def __init__(self,chunk=458):
        self.disk_reads=[];self.fail_read=None;self.aborted=False;self.in_swap=False
        super().__init__(chunk)
    def post(self,index):
        # R's initializer reaches here once before installing our real-media
        # hooks; install them on first use, with product callbacks unchanged.
        if not getattr(self,'disk_installed',False):
            self.disk_installed=True
            self.u.hook_add(UC_HOOK_INTR,self.bios)
            self.u.hook_add(UC_HOOK_CODE,lambda u,a,z,d:u.emu_stop(),begin=ABORT,end=ABORT)
            for name,phase in (('bridge_enter_post','post'),('bridge_leave_post','K'),('bridge_abort','abort')):
                def mark(u,a,z,d,p=phase):self.phase=p
                addr=bridge_symbol(name);self.u.hook_add(UC_HOOK_CODE,mark,begin=addr,end=addr)
            self.u.mem_write(R.symbol('fs_sectors_per_track'),b'\x08')
            self.u.mem_write(R.symbol('fs_heads'),b'\x01')
            self.u.mem_write(R.symbol('loop_cache_count'),bytes(2))
            self.u.mem_write(0x05fe,b'\x00\xff')  # entropy recorder frozen by route
        self.switch('K')
        self.u.mem_write(0x0682,(0x3ffe).to_bytes(2,'little'))
        self.u.mem_write(0x3ffc,R.RETURN.to_bytes(2,'little'))
        self.u.mem_write(0x3ffe,ABORT.to_bytes(2,'little'))
        self.u.reg_write(UC_X86_REG_SP,0x3ffc);self.u.reg_write(UC_X86_REG_AX,index*2)
        self.u.reg_write(UC_X86_REG_EFLAGS,2)
        self.entry=INFO['labels']['tls_h2_invoke'];self.running=True;self.in_swap=True
        try:self.u.emu_start(self.entry,ABORT+1,count=2_000_000)
        finally:self.running=False;self.in_swap=False
        ip=self.u.reg_read(UC_X86_REG_IP);self.aborted=ip==ABORT
        assert ip in (R.RETURN,ABORT),('did not return',hex(ip))
        assert self.u.reg_read(UC_X86_REG_SP)==(0x4000 if self.aborted else 0x3ffe)
        assert all(self.u.reg_read(r)==0 for r in (UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS))
        if not self.aborted:
            assert self.read(0x1800,4096)==R.CORE[4*512:12*512],'K was not fully restored'
            self.phase='K'
        return not bool(self.u.reg_read(UC_X86_REG_EFLAGS)&1)
    def bios(self,u,interrupt,data):
        assert interrupt==0x13,interrupt
        ax=u.reg_read(UC_X86_REG_AX);bx=u.reg_read(UC_X86_REG_BX)
        cx=u.reg_read(UC_X86_REG_CX);dx=u.reg_read(UC_X86_REG_DX)
        assert ax==0x0201,'write or multi-sector BIOS operation'
        cylinder=(cx>>8)|((cx&0xc0)<<2);sector=(cx&0x3f);head=dx>>8
        lba=(cylinder+head)*8+sector-1;file_sector=lba-(4+7)  # linked LOADER_SECTORS=4
        dest=u.reg_read(UC_X86_REG_ES)*16+bx
        ordinal=len(self.disk_reads)+1
        failed=self.fail_read==ordinal
        self.disk_reads.append(dict(sector=file_sector,destination=dest,failed=failed))
        assert (file_sector==INFO['bootstrap_sector'] and dest==0x0700) or (
            12<=file_sector<19 and dest==0x1800+(file_sector-12)*512) or (
            4<=file_sector<12 and dest==0x1800+(file_sector-4)*512)
        assert dest+512<=0x4000
        part=(b'\xcc'*256 if failed else R.CORE[file_sector*512:(file_sector+1)*512])
        u.mem_write(dest,part);u.ctl_remove_cache(dest,dest+512)
        R.D.set_carry(u,failed)
    def guard(self,u,access,addr,size,value,data):
        if not self.running:return
        if self.in_swap and self.phase=='abort':
            spans=[(0x062e,0x0684),(0x06c4,0x06c5),(0x2e00,0x3b9c),(0x3f00,0x4000)]
            assert any(lo<=addr and addr+size<=hi for lo,hi in spans),('abort write',hex(addr),size)
            return
        if self.in_swap and 0x2600<=addr and addr+size<=0x2600+len(R.POST)-3584:
            return  # emitted REP MOVSB of the independently bound final fragment
        return super().guard(u,access,addr,size,value,data)

def main():
    rows=[]
    # Constructor runs init through disk; settings/response now execute the real
    # AEAD and post-tag swap, with a following encrypted record retained across it.
    for chunk in (1,31,458):
        v=VM(chunk);v.ready();v.append(R.frame(1,R.encoded([(b':status',b'200')]),4))
        v.append(R.frame(0,b'fortytwo',1));v.record();v.record()
        assert v.output==b'fortytwo' and not v.aborted
        rows.append(dict(name='disk-composed-'+str(chunk),records=v.records,reads=len(v.disk_reads),body=len(v.output)))

    # Return flags must survive a successful K reload after a protocol rejection.
    v=VM();v.ready();v.append(R.frame(0,b'bad-before-headers'));v.record(post_expected=False)
    assert v.phase=='K' and not v.aborted
    rows.append(dict(name='post-error-carry-restored',reads=len(v.disk_reads)))

    # A successful operation performs 1 bootstrap + 7 post-head + 8 K reads.
    # Inject failure at EVERY read, partially overwriting that sector first.
    for fail in range(1,17):
        v=VM();v.disk_reads.clear();v.fail_read=fail
        before_context=v.read(0x3b9c,0x3f00-0x3b9c)
        before_native=v.read(0x0900,0x700)
        v.u.mem_write(0x2e00,b'\x71'*(0x3b9c-0x2e00))
        v.u.mem_write(0x06c4,b'\x01')
        ok=v.post(0);assert not ok and len(v.disk_reads)==fail
        assert v.read(0x3b9c,0x3f00-0x3b9c)==before_context
        assert v.read(0x0900,0x700)==before_native,'T/native capture state clobbered'
        if fail==1:
            assert not v.aborted  # intact K reports load failure to its caller
        else:
            assert v.aborted and v.read(0x06c4,1)==b'\0'
            assert v.read(0x062e,86)==bytes(86)
            assert v.read(0x2e00,0x3b9c-0x2e00)==bytes(0x3b9c-0x2e00)
        rows.append(dict(name='partial-sector-failure-'+str(fail),safe_resident_unwind=v.aborted,
                         intact_k_return=not v.aborted,context_and_native_untouched=True))

    report=dict(passed=True,cases=len(rows),core_sha256=hashlib.sha256(R.CORE).hexdigest(),
        bytes=len(R.CORE),k_bytes=INFO['k_bytes'],bridge_bytes=INFO['bridge_bytes'],mapped_ram_bytes=16384,
        rows=rows,limits=[__doc__,'The caller-owned resident abort anchor is set by this gate; all product callers must be wired and lifetime-checked.',
        'No provider/ALPN/outgoing control/flow grant or target BIOS/NIC timing claim; not a bootable product integration.'])
    (OUT/'phase_bridge-gate.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='rows'},indent=2))

if __name__=="__main__": main()
