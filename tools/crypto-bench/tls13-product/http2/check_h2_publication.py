#!/usr/bin/env python3
"""Real root frame + final H2 liveness + publication + first request in 16 KiB.

The cryptographic acquisition/resumption/FO flight is an explicit fixture leaf:
after the real root snapshots its caller and enters the NIC, that leaf supplies
the post-FO symmetric ABI. The real final controller, AEAD, H2, success/abort
capsules, parent READY publication, R/X/T and scheduler all execute unchanged.
This closes a lifetime boundary, not the missing full cryptographic boot gate.
"""
from image_binding import TEST_IMAGE
import argparse,copy,json,struct
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import *
import check_h2_scheduler as G
from h2.connection import H2Connection
from h2.config import H2Configuration
from h2.settings import SettingCodes
from h2.events import RequestReceived
R=G.R;Q=G.Q;E=G.E;S=G.S;OUT=G.OUT;T=Q.T
SYM=(TEST_IMAGE/'pack/resumption_sym_system.bin').read_bytes()

class VM(G.VM):
    def __init__(self,modes=('ok',),*,plans=(dict(text='fortytwo'),)):
        self.cold_active=False;self.flight_ready=False;self.successes=0
        self.modes=list(modes);self.publications=[];self.credentials=[];self.cold_restores=0
        super().__init__(plans=plans)
        self.u.mem_write(0x06c4,b'\0');self.u.mem_write(0x3600,bytes(104))
        self.u.mem_write(S['dpi_reached'],b'\1')
        a=R.symbol('load_core_sectors_at')
        self.u.hook_add(UC_HOOK_CODE,self.flight_leaf,begin=a,end=a)
        self.u.hook_add(UC_HOOK_CODE,self.success,begin=0x0f00,end=0x0f00)
    def establish(self,u,a,z,d):
        # Do not intercept this routine's return: execute the real resident
        # route selector, root load/call, NIC restoration and READY store.
        assert self.routes<len(self.modes),'unexpected route retry'
        assert self.read(0x06c4,1)==b'\0'
        assert not any(self.read(0x3600,104))
        self.routes+=1;self.cold_active=True;self.flight_ready=False
    def flight_leaf(self,u,a,z,d):
        if not self.cold_active or self.flight_ready:return
        if self.read(0x3f04,2)!=b'\x5a\xa5':return
        # First root call to the loader follows its actual frame publication
        # and NIC-enter. This deliberately replaces only the secure flight.
        assert self.leases[-1]=='enter'
        assert self.read(0x06c4,1)==b'\2'
        self.flight_ready=True
        self.server=H2Connection(config=H2Configuration(client_side=False))
        self.server.initiate_connection()
        self.server.update_settings({SettingCodes.INITIAL_WINDOW_SIZE:427})
        preface=b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'+R.frame(4,
            b'\0\1'+bytes(4)+b'\0\2'+bytes(4)+b'\0\4'+bytes(4)+b'\0\6\0\0\x10\0',stream=0)
        self.server.receive_data(preface);pending=self.server.data_to_send()
        mode=self.modes[self.routes-1]
        if mode=='no-ACK':
            assert pending.endswith(R.frame(4,flags=1,stream=0));pending=pending[:-9]
        self.current_request=None;self.reply_plan=None
        self.wire=b'';self.pos=0;self.nextseq=0;self.client_seq=1
        self.append(pending,forge=mode=='forged')
        self.u.mem_write(0x1800,SYM)
        self.u.ctl_remove_cache(0x1800,0x1800+len(SYM))
        for addr,raw in ((0x3838,T.CLIENT_KEY),(0x3858,T.CLIENT_IV),(0x3864,R.KEY),(0x3884,R.IV),
                         (0x38e0,(1).to_bytes(8,'big')),(0x38e8,bytes(8))):
            self.u.mem_write(addr,raw)
        self.u.mem_write(0x0900,R.CORE[165*512:168*512]);self.u.ctl_remove_cache(0x0900,0x0f00)
        self.request_phase='cold';self.phase='cold'
        u.reg_write(UC_X86_REG_IP,0x0900)
    def success(self,u,a,z,d):
        if not self.cold_active or not self.flight_ready:return
        assert self.read(R.H2+47,2)==b'\1\0','success without SETTINGS and ACK'
        assert self.read(0x06c4,1)!=b'\1','early READY publication'
        self.successes+=1
    def restore(self,u,a,z,d):
        if self.cold_active:
            self.cold_restores+=1
            assert self.read(0x06c4,1)==b'\0','READY precedes NIC restoration'
            assert self.read(0x3f00,28)==getattr(self,'retired_root_frame',bytes(28)),'root caller frame remains live'
            assert not any(self.read(0x1800,0x3600-0x1800)), 'retired overlays remain'
            assert not any(self.read(0x3668,0x3b9c-0x3668)), 'retired private TLS state remains'
            self.cold_active=False;self.request_phase='scheduler';self.phase='K'
        return super().restore(u,a,z,d)
    def bios(self,u,interrupt,data):
        if interrupt==0x13:
            cx=u.reg_read(UC_X86_REG_CX);dx=u.reg_read(UC_X86_REG_DX)
            sector=(((cx>>8)|((cx&0xc0)<<2))+(dx>>8))*8+(cx&63)-1-11
            dest=(u.reg_read(UC_X86_REG_ES)<<4)+u.reg_read(UC_X86_REG_BX)
            if sector==147 and dest==0x3400:
                assert u.reg_read(UC_X86_REG_AX)==0x0201
                self.disk_reads.append(dict(sector=sector,destination=dest,failed=False))
                u.mem_write(dest,R.CORE[sector*512:(sector+1)*512]);u.ctl_remove_cache(dest,dest+512)
                R.D.set_carry(u,False);return
            if self.cold_active and sector==11:self.phase='K'
        return super().bios(u,interrupt,data)
    def guard(self,u,access,addr,size,value,data):
        if not self.running:return
        if addr==0x06c4 and value==1:
            assert not self.cold_active and self.successes>len(self.publications)
            self.publications.append(dict(ip=u.reg_read(UC_X86_REG_IP),route=self.routes))
        if self.cold_active:
            spans=[(0x0500,0x0600),(0x0619,0x061c),(R.H2,R.H2+86),(0x06b0,0x1000),
                   (0x1800,0x3b9c),(0x3f00,0x4000),T.POINTER_SPAN,
                   (S['dpi_reached'],S['dpi_reached']+1)]
            assert any(a<=addr and addr+size<=b for a,b in spans),('cold publication write',hex(addr),size)
            if 0x3f1c<=addr<0x4000:self.lowest_stack=min(self.lowest_stack,addr)
            return
        # Success scrubs the consumed entropy corpus and counter; subsequent
        # required floppy reads execute the real read sampler again.
        if (0x0500<=addr and addr+size<=0x0578) or addr==0x05fe:
            return
        return super().guard(u,access,addr,size,value,data)
    def peer(self,plain):
        if len(plain)>=4 and plain[3]==1:
            assert self.read(0x06c4,1)==b'\1' and self.publications
            self.credentials.append(self.routes)
        return super().peer(plain)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--quick',action='store_true');args=ap.parse_args();rows=[]
    def row(name,v):
        rows.append(dict(name=name,routes=v.routes,success_capsules=v.successes,
            publications=v.publications,credential_requests=len(v.credentials),requests=len(v.requests),
            disk_reads=len(v.disk_reads),stack_low=hex(v.lowest_stack)))
        print(name,'PASS',rows[-1],flush=True)
    v=VM();v.run()
    assert v.rendered==b'fortytwo' and v.successes==len(v.publications)==len(v.credentials)==1
    row('actual-parent-unlock-to-first-answer',v)
    if not args.quick:
        for mode in ('no-ACK','forged'):
            v=VM(modes=(mode,'ok'));v.run()
            assert v.routes==2 and len(v.credentials)==1 and v.credentials==[2]
            assert v.rendered==b'fortytwo' and len(v.publications)==1
            row(mode+'-before-one-good-route',v)
        v=VM(modes=('no-ACK','no-ACK'),plans=());v.run(False)
        assert not v.credentials and not v.publications and not v.requests and not v.rendered
        v.finish_failed_turn();row('missing-liveness-never-unlocks',v)
    report=dict(passed=True,quick=args.quick,cases=len(rows),mapped_conventional_ram_bytes=16384,
        core_sha256=E.INFO['core_sha256'],rows=rows,limits=[__doc__,
        'The middle secure flight remains a fixture, not a complete boot. Full cold cryptographic chain, all NIC/IRQ/erasure/ENV and original-speed/286 acceptance remain.'])
    (OUT/('publication-quick.json' if args.quick else 'publication-gate.json')).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='rows'},indent=2))

if __name__=='__main__':main()
