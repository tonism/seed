#!/usr/bin/env python3
"""Authenticated normal NST validation, including duplicate extension types."""
import hashlib,json,struct
import check_h2_exchange as E
R=E.R;OUT=E.OUT
def ext(kind,value=b''):return struct.pack('>HH',kind,len(value))+value
def ticket(extensions=b''):
    body=struct.pack('>II',3600,123)+b'\x05nonce\0\x06ticket'+struct.pack('>H',len(extensions))+extensions
    return b'\4'+len(body).to_bytes(3,'big')+body
def main():
    rows=[]
    cases=[('empty',ticket(),True),('unknown',ticket(ext(0x1234,b'abc')),True),
           ('early-data',ticket(ext(42,bytes(4))),True),
           ('duplicate-unknown',ticket(ext(0x1234)+ext(0x1234,b'a')),False),
           ('duplicate-early-data',ticket(ext(42,bytes(4))*2),False),
           ('nonadjacent-duplicate',ticket(ext(0x1234,b'x')+ext(0x2345,b'yyy')+ext(0x1234)),False),
           ('same-type-different-messages',ticket(ext(0x1234))*2,True),
           ('second-message-duplicate',ticket()+ticket(ext(9)*2),False),
           ('bad-extension-length',ticket(ext(42,b'bad')),False)]
    for n in (1,2,17,100):cases.append(('unique-types-'+str(n),ticket(b''.join(ext(1000+i) for i in range(n))),True))
    for name,plain,want in cases:
        v=E.VM();v.u.mem_write(R.H2+65,b'\1');v.u.mem_write(R.H2+61,b'\1')
        source=bytes((i*37)%256 for i in range(512));v.u.mem_write(R.DATA,source)
        native=v.read(0xd00,0x200);h2=v.read(R.H2,68)
        v.append(plain,kind=0x16);v.verified=False
        ok=v.call(R.symbol('tls_receive_application_data'))
        assert ok==want,(name,ok,want)
        assert v.read(0xd00,0x200)==native,'normal NST touched native state'
        if want:
            assert v.read(R.H2,68)==h2
            assert v.read(R.DATA,512)==source,'normal NST damaged live upload source'
        assert not any(v.read(R.S['tls_app_record_buffer'],577))
        rows.append(dict(name=name,accepted=ok,bytes=len(plain)))
        print(name,'PASS',flush=True)
    report=dict(passed=True,cases=len(rows),core_sha256=hashlib.sha256(R.CORE).hexdigest(),rows=rows)
    (OUT/'normal-nst-gate.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
