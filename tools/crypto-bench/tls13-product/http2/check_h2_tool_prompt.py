#!/usr/bin/env python3
"""Keep the originating human request through native calls and BIOS scrolling.

Execute the real resident/R/X/T/M/O/DPI bytes against an independent HTTP/2
peer. The text BIOS leaf performs ordinary character writes and scrolls, so
subsequent request serialization reads the same display cells a PC would.
"""
import json
from unicorn.x86_const import *
import check_h2_tools as T
R=T.R;S=T.S;OUT=T.OUT
PROMPT=b'At arena base write B8 2A 00 CB. Run, read, report AX decimal and bytes.'
CONTEXT=b' U:2+2 A:four'

class VM(T.VM):
    def __init__(self,row):
        self.text_terminal=True;self.scrolls=0
        calls=[dict(raw=T.tool_events('write_mem',dict(addr='0x3e40',bytes='b8 2a 00 cb'),'write')),
               dict(raw=T.tool_events('exec',dict(addr='0x3e40'),'exec')),
               dict(raw=T.tool_events('read_mem',dict(addr='0x3e40',len=4),'read')),
               dict(text='AX 42; bytes B8 2A 00 CB')]
        super().__init__(plans=calls,context=CONTEXT,prompt=PROMPT)
        self.u.mem_write(0xb8000,b' \x07'*(80*25))
        self.u.mem_write(0xb8000+(row*80+2)*2,b''.join(bytes((c,7)) for c in PROMPT))
        for name,value in [('dpi_prompt_marker_row',row|0x80),('cursor_row',row+1),
                           ('cursor_col',0),('render_last_type',1)]:
            self.u.mem_write(S[name],bytes([value]))
        self.w16(S['scroll_br'],24*256+79)
    def print_char(self,u,a,z,d):
        row=self.read(S['cursor_row'],1)[0];col=self.read(S['cursor_col'],1)[0]
        assert row<25 and col<80,(row,col)
        self.u.mem_write(0xb8000+(row*80+col)*2,bytes((u.reg_read(UC_X86_REG_AX)&255,
                                                  u.reg_read(UC_X86_REG_BX)&255)))
        return super().print_char(u,a,z,d)
    def bios(self,u,interrupt,data):
        ax=u.reg_read(UC_X86_REG_AX)
        if interrupt==0x10 and ax>>8==6:
            cx=u.reg_read(UC_X86_REG_CX);dx=u.reg_read(UC_X86_REG_DX)
            top=cx>>8;left=cx&255;bottom=dx>>8;right=dx&255;lines=ax&255
            assert (top,left,bottom,right,lines)==(1,0,24,79,1)
            self.scrolls+=1
            self.u.mem_write(0xb8000+top*160,self.read(0xb8000+(top+1)*160,(bottom-top)*160))
            self.u.mem_write(0xb8000+bottom*160,b' \x07'*80)
            return
        return super().bios(u,interrupt,data)

def main():
    rows=[]
    for row in (5,22):
        v=VM(row);v.run();v.loop_to_input()
        assert v.exec_count==1 and v.read(0x3e40,4)==b'\xb8\x2a\0\xcb'
        assert len(v.requests)==4
        for i,req in enumerate(v.requests):
            doc=json.loads(req['body']);text=doc['input'][0]['content']
            human=CONTEXT.decode()+'U:'+PROMPT.decode()
            assert text.startswith(human),(row,i,text)
            assert doc['parallel_tool_calls'] is False
            if i<2:assert text==human
            if i>=2:assert 'Completed tools: write to 0x00003E40;' in text
            if i==3:assert 'execute 0x00003E40 ax=002A cf=0;' in text
            assert len(doc['input'])==(1 if i==0 else 3)
        if row==22:assert v.scrolls>=3
        rows.append(dict(prompt_row=row,scrolls=v.scrolls,requests=len(v.requests)))
    report=dict(passed=True,core_sha256=T.E.INFO['core_sha256'],rows=rows,limits=__doc__)
    (OUT/'tool-prompt-gate.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
