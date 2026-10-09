#!/usr/bin/env python3
"""Real resident turn/retry scheduler through R/X, AEAD/H2 and T in 16 KiB.

The authenticated route establishment is a fixture leaf restoring a distinct
connection's post-liveness state. BIOS, NIC and display are leaves; request
construction, authenticated responses, disk swaps, retirement and retry
decisions execute the actual candidate bytes. No live/physical claim.
"""
import argparse,copy,hashlib,json,struct
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import *
import check_h2_exchange as E
from h2.events import DataReceived,StreamEnded,RequestReceived
R=E.R;Q=E.Q;S=E.S;OUT=E.OUT

class VM(E.VM):
    def __init__(self,plans=(dict(text='fortytwo'),),*,context=b'',prompt=b'hi',window=427):
        self.plans=list(plans);self.requests=[];self.routes=0;self.leases=[]
        self.current_request=None;self.reply_plan=None;self.replies_done=[]
        self.scheduler_active=False
        self.fast_type_ticks=0
        super().__init__(window=window)
        self.route_template=copy.deepcopy(self.server)
        self.route_state=[(a,self.read(a,n)) for a,n in ((R.H2,86),(R.LIVE,0x3b9c-R.LIVE))]
        self.route_nextseq=self.nextseq
        self.u.mem_write(0x06c4,b'\1')
        for name in ('chat_turn_failed','esc_stop','esc_panic','tool_helper_pending','agent_loop_pending','agent_loop_count'):
            self.u.mem_write(S[name],b'\0')
        self.u.mem_write(S['chat_context_start'],context+bytes(96-len(context)))
        self.w16(S['chat_context_used'],len(context))
        self.prompt=prompt;self.install_prompt(prompt)
        for stub,name,callback in ((0x0544,'nic_vt_enter',self.enter),
                                   (0x0546,'nic_vt_restore',self.restore)):
            self.u.mem_write(R.symbol(name),struct.pack('<H',stub))
            self.u.hook_add(UC_HOOK_CODE,callback,begin=stub,end=stub)
        a=R.symbol('tls13_product_establish_route')
        self.u.hook_add(UC_HOOK_CODE,self.establish,begin=a,end=a)
        a=R.symbol('wait_ticks')
        self.u.hook_add(UC_HOOK_CODE,self.tick,begin=a,end=a)
    def tick(self,u,a,z,d):
        self.fast_type_ticks+=u.reg_read(UC_X86_REG_CX)
        R.D.near_return(u,False)
    def install_prompt(self,prompt):
        assert len(prompt)<79
        self.u.mem_write(S['dpi_input_len_byte'],bytes([len(prompt)]))
        self.u.mem_write(S['dpi_prompt_marker_row'],bytes([0x80|5]))
        self.u.mem_write(0xb8000+(5*80+2)*2,b''.join(bytes((c,7)) for c in prompt))
    def enter(self,u,a,z,d):
        assert not self.leases or self.leases[-1]=='restore',self.leases
        self.leases.append('enter');R.D.poison_gp(u);R.D.near_return(u,False)
    def restore(self,u,a,z,d):
        assert self.leases[-1]=='enter',self.leases
        self.leases.append('restore');R.D.poison_gp(u);R.D.near_return(u,True)
    def establish(self,u,a,z,d):
        assert self.routes<2,'unbounded fresh-route loop'
        assert self.read(0x06c4,1)==b'\0','route entered with a live capability'
        assert not any(self.read(S['tls_client_write_key'],104)),'old keys survived retirement'
        assert self.read(S['chat_resend_prompt_len'],1)==bytes([len(self.prompt)])
        self.routes+=1;self.server=copy.deepcopy(self.route_template)
        self.wire=b'';self.pos=0;self.nextseq=self.route_nextseq;self.client_seq=0
        for address,value in self.route_state:self.u.mem_write(address,value)
        self.u.mem_write(0x06c4,b'\1')
        self.current_request=None;self.reply_plan=None;self.phase='K'
        R.D.poison_gp(u);R.D.near_return(u,False)
    def bios(self,u,interrupt,data):
        if interrupt==0x10:
            assert u.reg_read(UC_X86_REG_AX)>>8==6,'unexpected display operation'
            return
        assert interrupt==0x13
        ax=u.reg_read(UC_X86_REG_AX);cx=u.reg_read(UC_X86_REG_CX);dx=u.reg_read(UC_X86_REG_DX)
        sector=(((cx>>8)|((cx&0xc0)<<2))+(dx>>8))*8+(cx&63)-1-11
        dest=(u.reg_read(UC_X86_REG_ES)<<4)+u.reg_read(UC_X86_REG_BX)
        for key,label in ((b'R','R'),(b'X','X'),(b'T','exchange'),(b'M','tool')):
            start,count,base=R.D.phase_geometry(R.CORE,key)
            if key==b'R':base=0x0700  # resident run_core_phase, not table-default net entry
            if start<=sector<start+count and dest==base+(sector-start)*512:
                assert ax==0x0201
                self.request_phase=label
                ordinal=len(self.disk_reads)+1;failed=self.fail_read==ordinal
                self.disk_reads.append(dict(sector=sector,destination=dest,failed=failed))
                u.mem_write(dest,b'\xcc'*256 if failed else R.CORE[sector*512:(sector+1)*512])
                u.ctl_remove_cache(dest,dest+512);R.D.set_carry(u,failed);return
        return super().bios(u,interrupt,data)
    def guard(self,u,access,addr,size,value,data):
        if self.running and self.phase=='abort' and R.LIVE<=addr and addr+size<=0x3b9c:return
        if self.running and self.request_phase=='tool' and 0x0d00<=addr and addr+size<=0x0f00:return
        return super().guard(u,access,addr,size,value,data)
    def peer(self,plain):
        for event in self.server.receive_data(plain):
            if isinstance(event,RequestReceived):
                assert self.current_request is None or self.current_request.get('ended'),self.current_request
                assert len(self.requests)<len(self.plans),'unexpected extra request'
                self.current_request=dict(connection=self.routes,stream=event.stream_id,
                    headers=dict(event.headers),body=bytearray(),ended=False)
                self.headers.append(dict(event.headers))
                self.reply_plan=self.plans[len(self.requests)]
                self.response_started=False;self.sent_response=0
            if isinstance(event,DataReceived):
                self.current_request['body'].extend(event.data)
                self.server.acknowledge_received_data(event.flow_controlled_length,event.stream_id)
            if isinstance(event,StreamEnded):
                self.current_request['ended']=True
                self.requests.append(self.current_request)
        request=self.current_request
        plan=self.reply_plan
        if request and request['ended'] and plan is not None:
            stream=request['stream']
            if not self.response_started:
                self.response_started=True
                self.response=plan.get('raw',E.event(plan.get('text','fortytwo'),plan.get('complete',True)))
                self.server.send_headers(stream,[(b':status',str(plan.get('status',200)).encode()),
                                                (b'content-type',b'text/event-stream')])
            available=self.server.local_flow_control_window(stream)
            while self.sent_response<len(self.response) and available>0:
                n=min(available,512,len(self.response)-self.sent_response)
                end=plan.get('terminal',True) and self.sent_response+n==len(self.response)
                self.server.send_data(stream,self.response[self.sent_response:self.sent_response+n],end_stream=end)
                self.sent_response+=n;available=self.server.local_flow_control_window(stream)
        pending=self.server.data_to_send()
        if pending:self.append(pending)
    def run(self,expected=True):
        self.request_phase='scheduler';self.phase='K';self.in_swap=True;self.scheduler_active=True
        try:ok=self.call(R.symbol('prepare_agent_endpoint_path'))
        finally:self.request_phase=None;self.in_swap=False;self.scheduler_active=False
        assert ok==expected,('scheduler',ok,expected,self.requests,bytes(self.rendered))
        assert self.read(S['chat_turn_failed'],1)==bytes([0 if ok else 255])
        assert self.leases==['enter','restore']*(len(self.leases)//2),self.leases
        assert self.read(S['chat_key_cache'],S['seed_key_len'])==self.saved_key
        assert self.read(S['chat_model_cache'],S['seed_model_len']-1)==self.saved_model[:-1]
        if not ok:assert self.read(0x06c4,1)==b'\0'
        return self
    def finish_failed_turn(self,stopped=False):
        before=len(self.rendered);ticks=self.fast_type_ticks
        sector,count,base=R.D.phase_geometry(R.CORE,b'M')
        self.u.reg_write(UC_X86_REG_AX,(count<<8)|sector)
        self.request_phase='tool';self.in_swap=True
        try:self.call(R.symbol('run_core_phase'))
        finally:self.request_phase=None;self.in_swap=False
        want=b'> stopped' if stopped else b'> response failed; try again'
        assert self.rendered[before:]==want,self.rendered[before:]
        assert self.fast_type_ticks-ticks==len(want)
        assert self.read(S['chat_turn_failed'],1)==b'\0'
        assert self.read(S['agent_loop_pending'],1)==b'\0'
        assert not any(self.read(S['tool_fc_state'],S['reconnect_state_end']-S['tool_fc_state']))
        assert not any(self.read(S['fc_capture_buf'],S['fc_capture_max']))

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--quick',action='store_true');args=ap.parse_args();rows=[]
    def row(name,v):
        for req in v.requests:
            doc=json.loads(req['body'])
            assert doc['model']=='gpt-6.1-sol' and doc['reasoning']==dict(effort='max')
            assert req['headers'][b'authorization']==b'Bearer '+Q.KEY
        rows.append(dict(name=name,requests=len(v.requests),fresh_routes=v.routes,
            rendered_bytes=len(v.rendered),disk_reads=len(v.disk_reads),stack_low=hex(v.lowest_stack)))
        print(name,'PASS',rows[-1],flush=True)
    v=VM();v.run();assert v.rendered==b'fortytwo' and not v.routes;row('ready-turn',v)
    v=VM(plans=[None,dict(text='fortytwo')]);v.run()
    assert v.rendered==b'fortytwo' and v.routes==1 and v.requests[0]['body']==v.requests[1]['body']
    row('no-output-bounded-reconnect',v)
    if not args.quick:
        v=VM(plans=[None,None,dict(text='fifty')]);v.run(False)
        assert not v.rendered and v.routes==1 and len(v.requests)==2
        v.finish_failed_turn();row('retry-exhaustion-visible-error',v)
        v.install_prompt(b'hi');before=len(v.rendered);v.run()
        assert v.rendered[before:]==b'fifty' and v.routes==2 and len(v.requests)==3
        row('next-human-after-exhaustion',v)
        v=VM(plans=[dict(complete=False)]);v.run(False)
        assert v.rendered==b'fortytwo' and not v.routes and len(v.requests)==1
        v.finish_failed_turn();row('partial-output-no-replay-visible-error',v)
        v=VM(plans=[dict(text='fortytwo'),dict(text='fifty')]);v.cancel_after_render=True
        v.run(False)
        assert v.rendered and not v.routes and len(v.requests)==1
        v.finish_failed_turn(stopped=True);row('cancel-no-replay-visible-stop',v)
        v.cancel_after_render=False;v.install_prompt(b'hi');before=len(v.rendered);v.run()
        assert v.rendered[before:]==b'fifty' and v.routes==1 and len(v.requests)==2
        row('next-human-after-cancel',v)
        v=VM(plans=[dict(terminal=False)]);v.run(False)
        assert v.rendered==b'fortytwo' and not v.routes;row('missing-END-no-replay',v)
        context=b'Earlier user asked six times seven. The answer was fortytwo. '*1+b'x'*20
        v=VM(plans=[dict(text='fortytwo'),dict(text='fifty')],context=context);v.run()
        assert v.rendered==b'fifty' and not v.routes and len(v.requests)==2
        docs=[json.loads(r['body']) for r in v.requests]
        assert 'tools' not in docs[0] and docs[0]['input'][0]['content']==context.decode()
        assert docs[1]['tools']==json.loads(Q.ASSETS['tools'][2])
        assert docs[1]['instructions'].endswith('fortytwo') and docs[1]['input'][0]['content'].endswith('hi')
        row('compaction-then-answer',v)
        v=VM(plans=[None,dict(text='fortytwo'),dict(text='fifty')],context=context);v.run()
        assert v.rendered==b'fifty' and v.routes==1 and len(v.requests)==3
        assert v.requests[0]['body']==v.requests[1]['body'];row('compaction-retry-then-answer',v)
    report=dict(passed=True,quick=args.quick,cases=len(rows),mapped_conventional_ram_bytes=16384,
        core_sha256=E.INFO['core_sha256'],rows=rows,limits=[__doc__,
        'Cold root publication, native/ENV/far sources, complete failure/IRQ/lifetime/erasure and original-speed provider/NIC/286 gates remain.'])
    (OUT/('scheduler-quick.json' if args.quick else 'scheduler-gate.json')).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='rows'},indent=2))

if __name__=='__main__':main()
