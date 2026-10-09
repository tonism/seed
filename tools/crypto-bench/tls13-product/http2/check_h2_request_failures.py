#!/usr/bin/env python3
"""Exact R/X source-failure cleanup with real AEAD/H2 and partial disk writes.

The network peer, BIOS reads, and display are fixtures. This checks failure
before returning to the resident scheduler, not merely its later key burn.
"""
import hashlib,json,struct
from unicorn.x86_const import *
import check_h2_exchange as E
R=E.R;Q=E.Q;S=E.S;OUT=E.OUT

class VM(E.VM):
    def __init__(self,fail_asset=None,fail_owner=False,compacting=False,cold=False,fail_send=False):
        self.fail_asset=fail_asset;self.fail_owner=fail_owner;self.failed=0
        super().__init__()
        if compacting:self.u.mem_write(S['compacting_msg'],b'\1')
        if cold:
            self.u.mem_write(S['handoff_addr']+S['handoff_status'],b'\1')
            self.u.mem_write(S['chat_resend_prompt_len'],b'\0')
        if fail_send:self.fail_send=len(self.transmitted)+1
    def bios(self,u,interrupt,data):
        if interrupt==0x13:
            cx=u.reg_read(UC_X86_REG_CX);dx=u.reg_read(UC_X86_REG_DX)
            lba=(((cx>>8)|((cx&0xc0)<<2))+(dx>>8))*8+(cx&63)-1
            candidates={Q.DATA_START+c-2:n for n,(c,z,b) in Q.ASSETS.items()}
            if (self.fail_asset and candidates.get(lba)==self.fail_asset) or (self.fail_owner and lba==11+167):
                dest=(u.reg_read(UC_X86_REG_ES)<<4)+u.reg_read(UC_X86_REG_BX)
                u.mem_write(dest,b'\xcc'*256);u.ctl_remove_cache(dest,dest+512)
                self.failed+=1;R.D.set_carry(u,True);return
        return super().bios(u,interrupt,data)
    def fail_request(self):
        start,count,_=R.D.phase_geometry(R.CORE,b'R')
        self.u.mem_write(0x0700,R.CORE[start*512:(start+count)*512]);self.u.ctl_remove_cache(0x0700,0x1000)
        self.request_phase='R';assert self.call(0x0700)
        start,count,dest=R.D.phase_geometry(R.CORE,b'X')
        self.u.mem_write(dest,R.CORE[start*512:(start+count)*512]);self.u.ctl_remove_cache(dest,dest+count*512)
        self.request_phase='X';self.phase='K';self.in_swap=True
        assert not self.call(dest),'source failure reported success'
        self.request_phase=None;self.in_swap=False
        assert self.failed==1 or self.fail_send==len(self.transmitted)
        assert not any(self.read(R.H2,86)),'request failure retained H2 authority/state'
        assert not any(self.read(R.LIVE,0x3b9c-R.LIVE)),'request failure retained keys/request/journals'
        assert self.read(0x06c4,1)==b'\0'
        assert self.read(S['chat_key_cache'],S['seed_key_len'])==self.saved_key
        assert self.read(S['chat_model_cache'],S['seed_model_len']-1)==self.saved_model[:-1]
        assert self.read(0xb8000,0x8000)==self.video

    def reject_metadata(self, changes):
        # A nonempty dialogue makes its pointer authoritative. With a zero
        # count, R intentionally never dereferences that otherwise-dead field.
        self.u.mem_write(S['chat_context_start'],b'A'*40+bytes(56))
        self.w16(S['chat_context_used'],40)
        start,count,_=R.D.phase_geometry(R.CORE,b'R')
        self.u.mem_write(0x0700,R.CORE[start*512:(start+count)*512])
        self.u.ctl_remove_cache(0x0700,0x1000)
        self.request_phase='R'
        assert self.call(0x0700)
        for name,value in changes:
            address=S[name[:-3]]+2 if name.endswith('+hi') else S[name]
            self.w16(address,value)
        start,count,dest=R.D.phase_geometry(R.CORE,b'X')
        self.u.mem_write(dest,R.CORE[start*512:(start+count)*512])
        self.u.ctl_remove_cache(dest,dest+count*512)
        self.request_phase='X';self.phase='K';self.in_swap=True
        assert not self.call(dest),'corrupted metadata reached request serialization'
        self.request_phase=None;self.in_swap=False
        assert not self.headers and not self.body,'credentials/request sent before validation'
        assert not any(self.read(R.H2,86))
        assert not any(self.read(R.LIVE,0x3b9c-R.LIVE))
        assert self.read(0x06c4,1)==b'\0'
        assert self.read(S['chat_key_cache'],S['seed_key_len'])==self.saved_key
        assert self.read(S['chat_model_cache'],S['seed_model_len']-1)==self.saved_model[:-1]
        assert self.read(0xb8000,0x8000)==self.video

def main():
    rows=[]
    for name,kw in [('tools-read',dict(fail_asset='tools')),('identity-read',dict(fail_asset='identity')),
                    ('compact-read',dict(fail_asset='compact',compacting=True)),('response-owner-read',dict(fail_owner=True))]:
        v=VM(**kw);v.fail_request()
        rows.append(dict(name=name,partial_disk_failures=v.failed,stack_low=hex(v.lowest_stack)))
        print(name,'PASS',flush=True)
    cases=[('tools-size',[('prompt_tools_size',385)]),
           ('identity-size',[('prompt_id_size',513)]),
           ('compact-size',[('prompt_compact_size',513)]),
           ('context-cap',[('chat_context_len_var',97)]),
           ('context-used',[('chat_context_used',97)]),
           ('note-used',[('note_len',41)]),
           ('far-segment',[('far_log_seg_var',0x1000)]),
           *[(name,[(field,1)]) for name,field in (
               ('far-count-low','far_flushed_len'),('far-count-high','far_flushed_len+hi'),
               ('far-escaped-low','far_flushed_esc'),('far-escaped-high','far_flushed_esc+hi'))],
           ('dialogue-count-high',[('dialogue_cnt+hi',1)]),
           ('dialogue-before-window',[('dialogue_off',S['chat_context_start']-1)]),
           ('dialogue-past-window',[('dialogue_cnt',97)]),
           ('dialogue-wrap',[('dialogue_off',65535),('dialogue_cnt',2)])]
    for name,changes in cases:
        v=VM();v.reject_metadata(changes)
        rows.append(dict(name=name,request_sent=False,stack_low=hex(v.lowest_stack)))
        print(name,'PASS',flush=True)
    report=dict(passed=True,cases=len(rows),core_sha256=hashlib.sha256(R.CORE).hexdigest(),rows=rows,limits=[__doc__])
    (OUT/'request-failure-gate.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
