#!/usr/bin/env python3
"""Authenticated-input-only NST phase: actual SHA/HMAC, guarded 16 KiB RAM."""
from image_binding import TEST_IMAGE
from pathlib import Path
import hashlib,hmac,itertools,json,struct
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
HERE=Path(__file__).resolve().parent;OUT=TEST_IMAGE
RAW=(OUT/'pack/h2_nst.bin').read_bytes();MASTER=hashlib.sha256(b'cold retained resumption master').digest()
ENTRIES=struct.unpack_from('<HH',RAW)
def hs(body):return b'\x04'+len(body).to_bytes(3,'big')+body
def ticket(identity=b'i',nonce=b'n',life=3600,age=b'\x11\x22\x33\x44',ext=b''):
    return hs(struct.pack('>I',life)+age+bytes([len(nonce)])+nonce+struct.pack('>H',len(identity))+identity+struct.pack('>H',len(ext))+ext)
def expand(nonce):
    msg=b'\0\x20\x10tls13 resumption'+bytes([len(nonce)])+nonce+b'\1'
    return hmac.new(MASTER,msg,hashlib.sha256).digest()
class VM:
    def __init__(self,ram=0x4000):
        self.ram=ram;self.stack_floor=0x3f1c if ram==0x4000 else 0x7a40
        self.u=Uc(UC_ARCH_X86,UC_MODE_16);self.u.mem_map(0,ram)
        self.u.mem_write(0,b'\xa5'*ram);self.u.mem_write(0x1800,RAW)
        self.u.mem_write(0xd22,MASTER);self.u.mem_write(0xe30,b'\0')
        self.u.mem_write(0x04f0,b'\xf4');self.writes=[]
        self.u.hook_add(UC_HOOK_MEM_WRITE,self.guard)
    def guard(self,u,ac,addr,size,value,data):
        assert any(a<=addr and addr+size<=b for a,b in [(0xd22,0xe2c),(0xe30,0xe31),(0x2e70,0x30b0),(0x3100,0x3570),(self.stack_floor,self.ram)]),(hex(addr),size)
        self.writes.append((addr,size,value))
    def read(self,a,n):return bytes(self.u.mem_read(a,n))
    def run(self,msg,ok=True,si=0x2e70):
        self.u.mem_write(0x2e70,msg);self.writes=[]
        before=self.read(0,self.ram)
        for r in [UC_X86_REG_CS,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS]:self.u.reg_write(r,0)
        self.u.mem_write(self.ram-2,struct.pack('<H',0x04f0))
        self.u.reg_write(UC_X86_REG_SP,self.ram-2);self.u.reg_write(UC_X86_REG_SI,si)
        self.u.reg_write(UC_X86_REG_CX,len(msg));self.u.reg_write(UC_X86_REG_EFLAGS,2)
        self.u.emu_start(ENTRIES[0],0x04f0,count=10000000)
        assert self.u.reg_read(UC_X86_REG_IP)==0x04f0
        assert self.u.reg_read(UC_X86_REG_SP)==self.ram
        assert bool(self.u.reg_read(UC_X86_REG_EFLAGS)&1)!=ok
        for a,b in [(0,0xd22),(0xe31,0x2e70),(0x30b0,0x3100),(0x3570,self.stack_floor)]:
            assert self.read(a,b-a)==before[a:b],(hex(a),hex(b))
        assert not any(self.read(0x3100,0x470))
        assert not any(self.read(0x2e70,576))
        # Nested SHA/HMAC frames contain secrets. Every byte below the final
        # return is zero except the two ordinary return addresses themselves.
        assert not any(self.read(self.stack_floor,self.ram-6-self.stack_floor))
        if not ok:
            assert self.read(0xd22,0xe31-0xd22)==before[0xd22:0xe31]
        return self

cases=0
for n,i,e in itertools.product([1,2,16,31,32],[1,63,191,192],[b'',bytes.fromhex('002a000400003800'),bytes.fromhex('3a3a0002aaaa')]):
    nonce=bytes(range(n));identity=hashlib.shake_256(b'identity').digest(i)
    v=VM().run(ticket(identity,nonce,ext=e));cases+=1
    assert v.read(0xd42,32)==expand(nonce)
    assert v.read(0xd62,i)==identity and not any(v.read(0xd62+i,192-i))
    assert v.read(0xd22,32)==bytes(32) and v.read(0xe30,1)==b'\1'
    assert v.read(0xe22,10)==struct.pack('<HH',0,3600)+bytes.fromhex('11223344')+struct.pack('<H',i)
    status_at=next(j for j,t in enumerate(v.writes) if t==(0xe30,1,1))
    assert not any(0xd22<=a<0xe31 for a,z,x in v.writes[status_at+1:])
    kept=v.read(0xd22,0xe31-0xd22)
    v.run(ticket(b'second',b'nonce',life=604800));cases+=1
    assert v.read(0xd22,0xe31-0xd22)==kept
print('NST valid bounds/HKDF/repeated tickets PASS',flush=True)

valid=ticket(b'A'*192,b'N'*32)
bad=[b'',* [valid[:n] for n in range(len(valid))],
    ticket(life=0),ticket(life=604801),ticket(nonce=b''),ticket(nonce=b'n'*33),
    ticket(identity=b''),ticket(identity=b'i'*193),ticket(ext=b'\0'),
    ticket(ext=bytes.fromhex('002a0003010203')),ticket(ext=bytes.fromhex('3a3a00003a3a0000')),
    ticket(ext=bytes.fromhex('002a000400000000002a000400000000'))]
for msg in bad:
    VM().run(msg,False);cases+=1
VM().run(valid+b'\0',False);cases+=1
VM().run(valid+ticket(life=0),False);cases+=1
v=VM().run(valid+ticket(b'B',b'M'));cases+=1
assert v.read(0xd42,32)==expand(b'N'*32)
VM().run(ticket(),False,0x2e71);cases+=1
VM().run(b'\0'*577,False);cases+=1
v=VM();v.u.mem_write(0xe30,b'\xa5');v.run(ticket(),False);cases+=1
for msg,ok in [(valid,True),(ticket(life=0),False),(valid+ticket(b'B',b'M'),True)]:
    v=VM(0x8000).run(msg,ok);cases+=1
    if ok:assert v.read(0xd42,32)==expand(b'N'*32)
print('32 KiB live arena/return shadow and stack cleanup PASS',flush=True)
result=dict(passed=True,cases=cases,mapped_ram_bytes=16384,bytes=len(RAW),image_sha256=hashlib.sha256(RAW).hexdigest(),
    limits=[__doc__,'Input authentication, disk loading and cold-controller handoff are caller responsibilities; this is not a linked product path.'])
(OUT/'nst-gate.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
