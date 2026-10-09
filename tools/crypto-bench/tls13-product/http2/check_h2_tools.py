#!/usr/bin/env python3
"""Actual authenticated tools -> M/O/DPI -> continuation -> answer at 16 KiB.

The local independent HTTP/2 peer supplies synthetic Responses events; it is
not a model/provider test. BIOS storage/keyboard/display and NIC are leaves.
The real resident chat loop dispatches native memory and returns to input.
"""
import argparse,json,struct
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import *
import check_h2_scheduler as G
R=G.R;E=G.E;S=G.S;OUT=G.OUT

def sse(kind,**fields):
    return b'event: '+kind.encode()+b'\ndata: '+json.dumps(dict(type=kind,**fields),separators=(',',':')).encode()+b'\n\n'
def tool_events(name,args,call_id='call_one',complete=True):
    item=dict(type='function_call',call_id=call_id,name=name,arguments=json.dumps(args,separators=(',',':')))
    result=sse('response.output_item.added',item=dict(item,arguments=''))+sse('response.output_item.done',item=item)
    if complete:result+=sse('response.completed',response=dict(output=[item]))
    return result

class VM(G.VM):
    def __init__(self,*args,**kwargs):
        self.await_input=False;self.input_cursor_visible=False;self.exec_count=0
        self.arena_writes=[];self.main_active=False
        super().__init__(*args,**kwargs)
        self.u.hook_add(UC_HOOK_CODE,self.executed,begin=0x3e40,end=0x3e40)
    def executed(self,u,a,z,d):self.exec_count+=1
    def bios(self,u,interrupt,data):
        ax=u.reg_read(UC_X86_REG_AX)
        if interrupt==0x10:
            assert ax>>8 in (1,2,6,9),hex(ax)
            if ax>>8==1:self.input_cursor_visible=not bool(u.reg_read(UC_X86_REG_CX)&0x2000)
            return
        if interrupt==0x16:
            if ax>>8==1:
                u.reg_write(UC_X86_REG_EFLAGS,u.reg_read(UC_X86_REG_EFLAGS)|0x40)
            else:
                assert ax>>8==0 and self.main_active and self.input_cursor_visible
                self.await_input=True;u.emu_stop()
            return
        assert interrupt==0x13
        cx=u.reg_read(UC_X86_REG_CX);dx=u.reg_read(UC_X86_REG_DX)
        sector=(((cx>>8)|((cx&0xc0)<<2))+(dx>>8))*8+(cx&63)-1-11
        dest=(u.reg_read(UC_X86_REG_ES)<<4)+u.reg_read(UC_X86_REG_BX)
        for key,label in ((b'O','tool-memory'),(b'Y','dpi'),(b'1','previous-tool'),(b'R','dpi-request')):
            start,count,base=R.D.phase_geometry(R.CORE,key)
            if start<=sector<start+count and dest==base+(sector-start)*512:
                assert ax==0x0201
                if key!=b'1':self.request_phase=label
                ordinal=len(self.disk_reads)+1;failed=self.fail_read==ordinal
                self.disk_reads.append(dict(sector=sector,destination=dest,failed=failed))
                u.mem_write(dest,b'\xcc'*256 if failed else R.CORE[sector*512:(sector+1)*512])
                u.ctl_remove_cache(dest,dest+512);R.D.set_carry(u,failed);return
        return super().bios(u,interrupt,data)
    def guard(self,u,access,addr,size,value,data):
        if self.running and 0x3e40<=addr and addr+size<=0x3ea0:
            self.arena_writes.append((addr,size,value))
        if self.running and self.request_phase=='tool-memory' and 0x0d00<=addr and addr+size<=0x0f00:return
        return super().guard(u,access,addr,size,value,data)
    def loop_to_input(self):
        self.u.reg_write(UC_X86_REG_SP,0x4000);self.u.reg_write(UC_X86_REG_EFLAGS,2)
        self.phase='K';self.request_phase='tool';self.in_swap=True;self.running=True;self.main_active=True
        try:self.u.emu_start(R.symbol('chat_loop'),R.RETURN+1,count=300_000_000)
        finally:self.running=False;self.main_active=False;self.in_swap=False;self.request_phase=None
        assert self.await_input,'chat loop did not return to human input'
        assert self.u.reg_read(UC_X86_REG_SP)>=0x3f00
        assert all(self.u.reg_read(reg)==0 for reg in (UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS))
        assert self.read(S['agent_loop_pending'],1)==b'\0'
        assert self.read(S['tool_helper_pending'],1)==b'\0'
        assert self.read(S['chat_key_cache'],S['seed_key_len'])==self.saved_key
        assert self.read(S['chat_model_cache'],S['seed_model_len']-1)==self.saved_model[:-1]
        return self

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--quick',action='store_true');args=ap.parse_args();rows=[]
    def row(name,v):
        docs=[json.loads(req['body']) for req in v.requests]
        assert all(doc['model']=='gpt-6.1-sol' and doc['reasoning']==dict(effort='max') for doc in docs)
        rows.append(dict(name=name,requests=len(v.requests),fresh_routes=v.routes,
            exec_count=v.exec_count,arena_writes=len(v.arena_writes),rendered=bytes(v.rendered).decode('ascii'),
            disk_reads=len(v.disk_reads),stack_low=hex(v.lowest_stack)))
        print(name,'PASS',rows[-1],flush=True)
    program=b'\xb8\x2a\0\xcb' # MOV AX,42; RETF, supplied through write_mem
    calls=[dict(raw=tool_events('write_mem',dict(addr='0x3e40',bytes='b8 2a 00 cb'),'call_write')),
           dict(raw=tool_events('exec',dict(addr='0x3e40'),'call_exec')),
           dict(raw=tool_events('read_mem',dict(addr='0x3e40',len=4),'call_read')),
           dict(text='fortytwo')]
    v=VM(plans=calls);v.run()
    assert not v.rendered and v.read(S['tool_fc_state'],1)==b'\1'
    v.loop_to_input()
    assert v.read(0x3e40,4)==program and v.exec_count==1 and len(v.arena_writes)==4
    assert len(v.requests)==4 and not v.routes
    assert bytes(v.rendered).endswith(b'fortytwo> ')
    docs=[json.loads(r['body']) for r in v.requests]
    outputs=[{i['call_id']:i['output'] for i in d['input'] if i.get('type')=='function_call_output'} for d in docs]
    assert 'write to 0x00003e40' in outputs[1]['call_write'].lower()
    assert 'ax=002a' in outputs[2]['call_exec'].lower()
    assert 'b8 2a 00 cb' in outputs[3]['call_read'].lower()
    assert 'Completed tools: write to 0x00003E40;execute 0x00003E40 ax=002A cf=0;' in docs[3]['input'][0]['content']
    assert [r['stream'] for r in v.requests]==[1,3,5,7]
    row('write-execute-read-answer-return-to-prompt',v)
    if not args.quick:
        # The bounded stateless journal retains whole recent result lines.
        # After eight tools the last result is still sent, with no tool schema,
        # so exhausting the budget produces a final answer instead of silence.
        budget=[dict(raw=tool_events('write_mem',dict(addr=hex(0x3e40+i),bytes=f'{i:02x}'),f'write_{i}')) for i in range(8)]
        v=VM(plans=budget+[dict(text='eight writes complete')]);v.run();v.loop_to_input()
        docs=[json.loads(req['body']) for req in v.requests]
        assert len(docs)==9 and len(v.arena_writes)==8
        assert all(d['parallel_tool_calls'] is False for d in docs[:-1])
        assert 'tools' not in docs[-1]
        assert bytes(v.rendered).endswith(b'eight writes complete> ')
        journal=docs[-1]['input'][0]['content'].split(' Completed tools: ')[1]
        assert len(journal)<=S['fc_history_max'] and journal.endswith(';')
        assert all(line.startswith('write to 0x00003E4') for line in journal.split(';')[:-1])
        assert 'write to 0x00003E46;' in journal and 'write to 0x00003E40;' not in journal
        row('bounded-tool-history-and-final-answer-at-budget',v)
        v=VM(plans=budget+[dict(raw=tool_events('write_mem',dict(addr='0x3e40',bytes='ff'),'over_budget'))])
        v.run();v.loop_to_input()
        assert len(v.arena_writes)==8 and v.read(0x3e40,1)==b'\0'
        assert bytes(v.rendered).endswith(b'> response failed; try again> ')
        row('over-budget-provider-call-never-executes',v)
        # A failed continuation cannot replay a write already performed.
        v=VM(plans=[calls[0],None]);v.run();v.loop_to_input()
        assert v.read(0x3e40,4)==program and len(v.arena_writes)==4 and not v.routes
        assert len(v.requests)==2 and bytes(v.rendered).endswith(b'> response failed; try again> ')
        row('failed-continuation-does-not-replay-write',v)
        # An unexecuted, incomplete call may retry the original human request;
        # M must never see it as callable before both completion boundaries.
        incomplete=dict(raw=tool_events('write_mem',dict(addr='0x3e40',bytes='b8 2a 00 cb'),'call_write',False))
        v=VM(plans=[incomplete,calls[0],dict(text='done')]);v.run();v.loop_to_input()
        assert v.routes==1 and len(v.requests)==3 and len(v.arena_writes)==4
        assert v.requests[0]['body']==v.requests[1]['body']
        assert v.read(0x3e40,4)==program and bytes(v.rendered).endswith(b'done> ')
        row('incomplete-call-retried-before-single-dispatch',v)
    report=dict(passed=True,quick=args.quick,cases=len(rows),mapped_conventional_ram_bytes=16384,
        core_sha256=E.INFO['core_sha256'],rows=rows,limits=[__doc__,
        'This is a synthetic local peer, not a live model. All native/ENV/far cases, whole cold publication, full failure/IRQ/erasure and original-speed/NIC/286 acceptance remain.'])
    (OUT/('tools-quick.json' if args.quick else 'tools-gate.json')).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='rows'},indent=2))

if __name__=='__main__':main()
