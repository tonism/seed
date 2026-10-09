#!/usr/bin/env python3
"""Exact R/X/H2 request serialization on 32 KiB and 512 KiB conventional RAM.

The independent HTTP/2 peer checks decrypted JSON byte-for-byte. The large
context crosses a segment boundary and exceeds the peer's initial window.
BIOS/NIC and cold establishment are explicit leaves, as in check_h2_requests.
"""
import json
import struct
from unicorn.x86_const import *
import check_h2_requests as Q
R=Q.R; S=Q.S; OUT=Q.OUT

class VM(Q.VM):
    def __init__(self, ram, context, far=False, compacting=False):
        self.ram=ram
        super().__init__(window=65535, compacting=compacting)
        self.u.mem_map(0x4000,ram-0x4000)
        self.stack_top=0x8000
        self.w16(S['handoff_addr']+S['handoff_ram_top'],0x8000)
        self.w16(S['chat_context_len_var'],224)
        self.w16(S['chat_compact_threshold'],168)
        self.w16(S['chat_effective_cap'],224)
        self.context_base=S['tools_cache']-224
        if far:
            assert ram==0x80000
            self.w16(S['far_log_seg_var'],0x4000)
            self.u.mem_write(S['far_ctx_base'],struct.pack('<I',0x40000))
            self.u.mem_write(S['far_window_cap'],struct.pack('<I',0x40000))
            self.u.mem_write(S['far_flushed_len'],struct.pack('<I',len(context)))
            self.u.mem_write(S['far_flushed_esc'],struct.pack('<I',len(json.dumps(context.decode()))-2))
            self.w16(S['chat_context_used'],0)
            self.u.mem_write(0x40000,context)
        else:
            self.w16(S['chat_context_used'],len(context))
            self.u.mem_write(self.context_base,context)
        self.source_address=0x40000 if far else self.context_base
        self.source=context
    def guard(self,u,access,addr,size,value,data):
        if self.running and 0x7a40<=addr and addr+size<=0x8000:
            self.lowest_stack=min(self.lowest_stack,addr)
            return
        return super().guard(u,access,addr,size,value,data)

def main():
    rows=[]
    for ram,far,compact,context in (
        (0x8000,False,False,b' U:previous question A:fortytwo'),
        (0x80000,True,False,b' U:previous question A:fortytwo'),
        (0x80000,True,False,(b'A\\B"C\n'*12000)[:65543]),
        (0x80000,True,True,(b' U:prior A:fortytwo\n'*1100)),
    ):
        v=VM(ram,context,far,compact);doc=v.request()
        normalized=bytes(x if x>=32 else 32 for x in context).decode()
        expected=normalized if compact else normalized+'U:'+Q.PROMPT.decode()
        assert doc['input'][0]['content']==expected, (len(context),repr(doc['input'][0]['content'][-100:]))
        assert v.read(v.source_address,len(context))==context,'request modified its source'
        assert doc['model']=='gpt-6.1-sol' and doc['reasoning']=={'effort':'max'}
        assert ('tools' in doc) != compact
        rows.append(dict(ram_bytes=ram,far=far,compaction=compact,context_bytes=len(context),
                         request_bytes=len(v.body),tls_records=len(v.transmitted)))
        print('far request PASS',rows[-1],flush=True)
    (OUT/'far-requests-gate.json').write_text(json.dumps(dict(passed=True,core_sha256=Q.INFO['core_sha256'],
        cases=len(rows),rows=rows,limits=__doc__),indent=2)+'\n')

if __name__=='__main__':main()
