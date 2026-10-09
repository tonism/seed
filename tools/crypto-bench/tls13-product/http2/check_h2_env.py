#!/usr/bin/env python3
"""Actual ENV save/restore and post-save HTTP/2 reuse with a synthetic floppy.

Only BIOS media, display and NIC operations are fixture leaves. The 16 KiB
writer, FAT updates, snapshot codec, restore validation and next encrypted
exchange execute the emitted runtime. No user media or credentials are read.
"""
import json,struct
from unicorn.x86_const import *
import check_h2_exchange as E
R=E.R;Q=E.Q;S=E.S;OUT=E.OUT
ENV=R.module('h2_env_format',Q.ROOT/'tools/env-dat.py')

class VM(E.VM):
    def __init__(self,readonly=False):
        self.storage=None;self.disk=bytearray(Q.DISK);self.readonly=readonly;self.writes=[]
        super().__init__()
        self.u.mem_write(0xb8000,b' \x07'*(80*25))
        self.u.mem_write(0xb8000+(5*80+2)*2,b'h\x07i\x07')
        self.video=self.read(0xb8000,0x8000)
        self.u.mem_write(S['chat_pool_start'],b'\xb8\x2a\0\xcb'+bytes(92))
    def bios(self,u,interrupt,data):
        if not self.storage:return super().bios(u,interrupt,data)
        if interrupt==0x10:return  # ordinary snapshot/status display only
        assert interrupt==0x13
        ax=u.reg_read(UC_X86_REG_AX);cx=u.reg_read(UC_X86_REG_CX);dx=u.reg_read(UC_X86_REG_DX)
        lba=(((cx>>8)|((cx&0xc0)<<2))+(dx>>8))*8+(cx&63)-1
        address=(u.reg_read(UC_X86_REG_ES)<<4)+u.reg_read(UC_X86_REG_BX)
        assert ax in (0x0201,0x0301) and 0<=lba<len(self.disk)//512
        if ax==0x0201:
            u.mem_write(address,bytes(self.disk[lba*512:(lba+1)*512]))
            u.ctl_remove_cache(address,address+512)
        else:
            self.writes.append(lba)
            if self.readonly:R.D.set_carry(u,True);return
            self.disk[lba*512:(lba+1)*512]=self.read(address,512)
        R.D.set_carry(u,False)
    def guard(self,u,access,address,size,value,data):
        if self.running and self.storage:
            spans=[(0x0700,0x1000),(0x3f00,0x4000),(0xb8000,0xb8000+4000)]
            if self.storage=='restore':spans += [(0x1800,0x3b9c),(0x3c9c,0x3cce),(0x3e40,0x3f00)]
            assert any(a<=address and address+size<=b for a,b in spans),('ENV write',self.storage,hex(address),size)
            return
        return super().guard(u,access,address,size,value,data)
    def storage_phase(self,key,mode):
        start,count,dest=R.D.phase_geometry(R.CORE,key)
        self.u.mem_write(dest,R.CORE[start*512:(start+count)*512]);self.u.ctl_remove_cache(dest,dest+count*512)
        self.storage=mode;self.request_phase=mode
        try:return self.call(dest)
        finally:self.storage=None;self.request_phase=None
    def snapshot_file(self):
        root=self.disk[7*512:11*512]
        seed=next(root[i:i+32] for i in range(0,len(root),32) if root[i:i+11]==b'SEED       ')
        cluster=struct.unpack_from('<H',seed,26)[0]
        directory=self.disk[(cluster+9)*512:(cluster+10)*512]
        entries=[directory[i:i+32] for i in range(0,512,32) if directory[i:i+11]==b'ENV     DAT']
        if not entries:return None
        cluster,size=struct.unpack_from('<HI',entries[0],26)
        result=bytearray();fat=self.disk[5*512:6*512];seen=set()
        while cluster<0xff8:
            assert cluster>=2 and cluster not in seen;seen.add(cluster)
            result.extend(self.disk[(cluster+9)*512:(cluster+10)*512])
            n=struct.unpack_from('<H',fat,cluster+cluster//2)[0]
            cluster=(n>>4 if cluster&1 else n)&0xfff
        return bytes(result[:size])

def main():
    rows=[]
    for mode in ('writable','readonly','full'):
        readonly=mode=='readonly'
        v=VM(readonly)
        # The packaged image's only free cluster is the last one. Keep that
        # boundary even with the smaller synthetic-config fixture: the old
        # allocator stopped at cluster 300 and incorrectly reported no room.
        last_cluster=len(v.disk)//512-Q.DATA_START+1
        fat=bytearray(v.disk[5*512:6*512])
        for cluster in range(2,last_cluster+1):
            offset=cluster+cluster//2;n=struct.unpack_from('<H',fat,offset)[0]
            if ((n>>4 if cluster&1 else n)&0xfff)==0 and (mode=='full' or cluster!=last_cluster):
                n=(n|0xfff0) if cluster&1 else (n|0x0fff)
                struct.pack_into('<H',fat,offset,n)
        v.disk[5*512:7*512]=fat*2
        original_disk=bytes(v.disk)
        v.request();v.run_exchange()
        live=[(a,v.read(a,n)) for a,n in ((R.H2,86),(R.LIVE,0x3b9c-R.LIVE),
                                       (S['chat_pool_start'],192),(S['chat_key_cache'],S['seed_key_len']))]
        v.u.mem_write(S['save_pending'],b'\1');v.storage_phase(b'W','save')
        assert all(v.read(a,len(b))==b for a,b in live),'save modified H2/keys/user region'
        assert bool(v.writes)==(mode!='full'),(mode,v.writes)
        blob=v.snapshot_file()
        if mode!='writable':
            assert blob is None and bytes(v.disk)==original_disk
        else:
            decoded=ENV.parse(blob)
            assert decoded['header_checksum_ok'] and decoded['payload_checksum_ok']
            assert decoded['region']==live[2][1] and decoded['region_len']==192
            assert decoded['format_version']==2
        # The next turn reuses the very same authenticated session.
        v.video=v.read(0xb8000,0x8000)  # includes the ordinary save-status line
        v.headers=[];v.body.clear();v.ended=[];v.rendered.clear();v.response=E.event('fifty')
        v.sent_response=0;v.response_started=False
        v.request();v.run_exchange();assert v.rendered==b'fifty'
        assert int.from_bytes(v.read(R.H2+20,4),'big')==3
        if blob:
            restored=VM();restored.disk=v.disk.copy()
            restored.u.mem_write(S['chat_pool_start'],b'\xa7'*192)
            assert restored.storage_phase(b'P','restore')
            assert restored.read(S['chat_pool_start'],192)==decoded['region']
            assert restored.read(0xb8000,4000)==decoded['screen_cells']
            for offset in (26,28):
                bad=VM();bad.disk=v.disk.copy();start=bad.disk.find(blob)
                assert start>=0
                bad.disk[start+offset]^=1
                bad.u.mem_write(S['chat_pool_start'],b'\xa7'*192)
                before=bad.read(0xb8000,4000)
                assert not bad.storage_phase(b'P','restore')
                assert bad.read(S['chat_pool_start'],192)==b'\xa7'*192
                assert bad.read(0xb8000,4000)==before
        rows.append(dict(mode=mode,last_data_cluster=last_cluster,write_attempts=len(v.writes),snapshot_bytes=len(blob or b''),reused_stream=3))
    report=dict(passed=True,core_sha256=E.INFO['core_sha256'],rows=rows,limits=__doc__)
    (OUT/'env-gate.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':main()
