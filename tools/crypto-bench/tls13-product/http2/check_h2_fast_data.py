#!/usr/bin/env python3
"""Differentially execute the shipped DATA shortcut and complete H2 parser."""
from pathlib import Path
import hashlib, json, random, re
from image_binding import TEST_IMAGE
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_MEM_WRITE
from unicorn.x86_const import *

OUT=TEST_IMAGE; H2=0x062e;DATA=0x2e70;CTL=0x3070;WORK=0x2e1c
RETURN=0x0400;STACK=0x3ffe
core=(OUT/'SEED.SYS').read_bytes();post=(OUT/'h2_post.bin').read_bytes()
listing=(OUT/'exchange.lst').read_text().splitlines()
start=next(i for i,s in enumerate(listing) if re.search(r'\bfast_data:\s*$',s))
entry=next(0x2a00+int(m[1],16) for s in listing[start:] if (m:=re.match(r'^\s*\d+\s+([0-9A-F]{8})\s',s)))
slow_entry=int.from_bytes(post[4:6],'little')
rng=random.Random(0x2702)
def machine(fast):
    u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,0x4000)
    if fast:
        u.mem_write(0x2800,core[185*512:186*512]);u.mem_write(0x2a00,core[167*512:168*512])
    else:u.mem_write(0x1800,post)
    def write_guard(u,access,addr,size,value,data):
        spans=[(H2,H2+84),(WORK,0x35bc),(0x3f00,0x4000)]
        assert any(a<=addr and addr+size<=b for a,b in spans),(hex(addr),size)
    u.hook_add(UC_HOOK_MEM_WRITE,write_guard)
    return u
fast=machine(True);slow=machine(False)
def execute(u,isfast,state,body,control,position=None,direction=False):
    u.mem_write(H2,bytes(state));u.mem_write(0x2e00,bytes(0x7bc))
    u.mem_write(DATA,bytes(body));u.mem_write(CTL,bytes(control))
    u.mem_write(0x2e6c,(len(body)+len(control) if position is None else position).to_bytes(2,'little'))
    u.mem_write(STACK,RETURN.to_bytes(2,'little'))
    regs={UC_X86_REG_AX:4,UC_X86_REG_BX:0x1234,UC_X86_REG_CX:len(body),
          UC_X86_REG_DX:0x4567,UC_X86_REG_SI:DATA,UC_X86_REG_DI:CTL,UC_X86_REG_BP:len(control),
          UC_X86_REG_SP:STACK,UC_X86_REG_DS:0,UC_X86_REG_ES:0,UC_X86_REG_SS:0,UC_X86_REG_CS:0}
    for r,v in regs.items():u.reg_write(r,v)
    u.reg_write(UC_X86_REG_EFLAGS,0x402 if direction else 2)
    before=bytes(u.mem_read(H2,84))+bytes(u.mem_read(0x2e00,0x7bc))
    u.emu_start(entry if isfast else slow_entry,RETURN,count=1_000_000)
    assert u.reg_read(UC_X86_REG_IP)==RETURN and u.reg_read(UC_X86_REG_SP)==0x4000
    carry=bool(u.reg_read(UC_X86_REG_EFLAGS)&1)
    if isfast and carry:
        assert before==bytes(u.mem_read(H2,84))+bytes(u.mem_read(0x2e00,0x7bc)), 'fallback changed state'
        for r in (UC_X86_REG_CX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_BP):assert u.reg_read(r)==regs[r]
    return dict(carry=carry,direction=bool(u.reg_read(UC_X86_REG_EFLAGS)&0x400),registers=[u.reg_read(r) for r in (UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX)],
                persistent=bytes(u.mem_read(H2,84)).hex(),
                data=bytes(u.mem_read(DATA,512)).hex(),live=bytes(u.mem_read(0x2e00,28)).hex(),
                controls=bytes(u.mem_read(CTL,1280)).hex(),hpack=bytes(u.mem_read(0x3570,76)).hex())
def base(n):
    state=bytearray(rng.randbytes(84))
    state[9:12]=bytes(3);state[16]=0;state[18:20]=b'\x01\0'
    stream=rng.choice([1,3,19,0x7fffffff]);state[20:24]=stream.to_bytes(4,'big')
    count=rng.choice([0,42,65530,0x7fffffff,0xffffff00])
    state[36:40]=count.to_bytes(4,'little')
    state[40:44]=min(0xffffffff,count+n+rng.choice([0,1,512])).to_bytes(4,'little')
    state[44]=rng.randrange(2);state[45:47]=(200).to_bytes(2,'little')
    state[47]=1;state[48]=0;state[49]=0;state[59]=0
    body=rng.randbytes(n);header=bytearray(n.to_bytes(3,'big')+b'\0\0'+stream.to_bytes(4,'big'))
    return state,body,header
rows=[];accepted=0;declined=0
def check(name,state,body,control,position=None,require_fallback=False):
    global accepted,declined
    f=execute(fast,True,state,body,control,position,len(rows)%2)
    if require_fallback:assert f['carry'],name
    if f['carry']:
        declined+=1;rows.append(dict(name=name,fallback_unchanged=True));return
    s=execute(slow,False,state,body,control,position,len(rows)%2)
    assert not s['carry'],(name,'fast accepted baseline refusal')
    assert f==s,(name,{k:(f[k],s[k]) for k in f if f[k]!=s[k]})
    accepted+=1;rows.append(dict(name=name,equivalent=True))
for i in range(800):
    n=rng.choice([0,1,2,16,27,128,255,256,485,511,512])
    state,body,header=base(n);check('valid-or-overflow-'+str(i),state,body,header)
for offset,value in [(9,1),(10,1),(11,1),(16,1),(18,0),(18,2),(19,1),(47,0),(47,2),(59,1)]:
    state,body,header=base(27);state[offset]=value
    check('state-'+str(offset)+'-'+str(value),state,body,header,require_fallback=True)
for offset,value in [(0,1),(1,1),(2,28),(3,1),(3,6),(4,1),(4,8),(4,0x40),(5,0x80),(8,0)]:
    state,body,header=base(27);header[offset]=value
    check('header-'+str(offset)+'-'+str(value),state,body,header,require_fallback=True)
for n in range(9):
    state,body,header=base(27);check('partial-header-'+str(n),state,body,header[:n],require_fallback=True)
state,body,header=base(27);check('extra-control',state,body,header+b'x',require_fallback=True)
for position in (0,35,37,65535):
    state,body,header=base(27);check('position-'+str(position),state,body,header,position,True)
state,body,header=base(513);check('over-capacity',state,body,header,require_fallback=True)
state,body,header=base(27);state[20:24]=header[5:9]=bytes(4)
check('zero-stream',state,body,header,require_fallback=True)
state,body,header=base(27);state[20]|=0x80;header[5]|=0x80
check('reserved-stream-in-state',state,body,header,require_fallback=True)
state,body,header=base(27);state[36:40]=(0xffffffff).to_bytes(4,'little')
check('counter-overflow',state,body,header,require_fallback=True)
state,body,header=base(27);state[36:40]=bytes(4);state[40:44]=(26).to_bytes(4,'little');state[44]=1
check('content-length-overrun',state,body,header,require_fallback=True)
report=dict(passed=True,core_sha256=hashlib.sha256(core).hexdigest(),cases=len(rows),
    equivalent_hot_cases=accepted,side_effect_free_fallback_cases=declined,rows=rows,
    limits=['Compares emitted product shortcut with the unchanged full parser for one authenticated queue handoff.',
            'Persistent H2 state, DATA, controls, collector and HPACK state match; dead per-call parser scratch is excluded.',
            'The separate AEAD/credit/exchange gates cover authentication and composition; live target acceptance remains separate.'])
(OUT/'fast-data-gate.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='rows'},indent=2))
