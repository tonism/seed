#!/usr/bin/env python3
"""Validate bounded receive-credit batching against an independent h2 peer.

Actual R/X/K/H2/T bytes and AEAD execute in guarded 16 KiB RAM. BIOS, NIC,
display and provider are fixture leaves; this is not target timing evidence.
"""
from pathlib import Path
import hashlib, json
from image_binding import TEST_IMAGE
import check_h2_exchange as E
R=E.R

class VM(E.VM):
    def __init__(self,*,pattern=(27,485),body_size=4096,tls_split=0,padded=False,trailers=False,ping_split=False,forge_at=None,overrun=False):
        self.pattern=list(pattern);self.initial_pattern=list(pattern)
        self.tls_split=tls_split;self.padded=padded;self.trailers=trailers;self.ping_split=ping_split
        self.ping_sent=False;self.forge_at=forge_at;self.overrun=overrun;self.attacked=False
        self.server_data_frames=[];self.grants=[];self.server_tls=0
        self.ping_acks=[]
        self.client_frame_wire=bytearray()
        super().__init__('fortytwo',window=65535)
        # Ignored metadata plus a short visible delta and explicit completion.
        prefix=b'data: {"type":"response.created","padding":"'
        suffix=b'"}\n\n'+E.event('fortytwo')
        assert body_size>=len(prefix)+len(suffix)
        self.response=prefix+b'x'*(body_size-len(prefix)-len(suffix))+suffix
    def append_response(self,payload):
        parts=[payload]
        if self.tls_split and len(payload)>self.tls_split:
            parts=[payload[:self.tls_split],payload[self.tls_split:]]
        for part in parts:
            self.server_tls+=1
            self.append(part,forge=self.server_tls==self.forge_at)
    def peer(self,plain):
        # These are authenticated synthetic TLS plaintexts observed by the
        # independent peer, never recorded live keys or decrypted user traffic.
        self.client_frame_wire.extend(plain)
        while len(self.client_frame_wire)>=9:
            wire=self.client_frame_wire
            n=int.from_bytes(wire[:3],'big');typ=wire[3]
            if len(wire)<9+n:break
            if typ==8:
                assert n==4
                self.grants.append(dict(stream=int.from_bytes(wire[5:9],'big'),
                                        increment=int.from_bytes(wire[9:13],'big')))
            if typ==6:
                assert n==8 and wire[4]==1 and wire[5:9]==b'\0'*4
                self.ping_acks.append(bytes(wire[9:17]))
            del wire[:9+n]
        E.Q.VM.peer(self,plain)
        if not self.ended:return
        stream=self.ended[-1]
        if not self.response_started:
            self.response_started=True
            self.server.send_headers(stream,[(b':status',b'200'),(b'content-type',b'text/event-stream'),
                (b'content-length',str(len(self.response)).encode())])
            self.append_response(self.server.data_to_send())
        available=self.server.local_flow_control_window(stream)
        while self.sent_response<len(self.response) and available>0 and not self.attacked:
            desired=self.pattern.pop(0) if self.pattern else available
            raw=min(desired,available,512)
            pad=7 if self.padded and raw>8 else None
            overhead=pad+1 if pad is not None else 0
            n=min(raw-overhead,len(self.response)-self.sent_response)
            end=self.sent_response+n==len(self.response)
            self.server.send_data(stream,self.response[self.sent_response:self.sent_response+n],
                                  end_stream=end and not self.trailers,pad_length=pad)
            self.sent_response+=n
            self.server_data_frames.append(dict(data=n,flow=n+overhead,end=end and not self.trailers))
            self.append_response(self.server.data_to_send())
            if self.overrun and not self.attacked:
                self.append_response(R.frame(0,b'X'*512,stream=stream));self.attacked=True
                break
            if self.ping_split and not self.ping_sent:
                self.ping_sent=True;self.server.ping(b'credit25')
                wire=self.server.data_to_send()
                # Complete PING header and half payload precede its remainder.
                self.append_response(wire[:13]);self.append_response(wire[13:])
            if end and self.trailers:
                self.server.send_headers(stream,[(b'x-end',b'yes')],end_stream=True)
                self.append_response(self.server.data_to_send())
            available=self.server.local_flow_control_window(stream)

def run(name,**kw):
    v=VM(**kw);v.request()
    reads=len(v.disk_reads);sent=len(v.transmitted)
    fail=kw.get('forge_at') is not None or kw.get('overrun',False)
    v.run_exchange(not fail)
    conn=sum(g['increment'] for g in v.grants if g['stream']==0)
    stream=sum(g['increment'] for g in v.grants if g['stream']!=0)
    flow=sum(f['flow'] for f in v.server_data_frames)
    if not fail:
        assert not v.client_frame_wire
        assert v.rendered==b'fortytwo',v.rendered
        assert v.sent_response==len(v.response)
        assert conn==flow,(name,conn,flow)
        assert 0<=stream-flow<=512,(name,stream,flow)
        assert all(g['increment']==512 for g in v.grants if g['stream']!=0),v.grants
        if kw.get('ping_split'):assert v.ping_acks==[b'credit25'],v.ping_acks
    else:
        assert not v.rendered
        assert conn<=flow
    row=dict(name=name,passed=True,body_bytes=len(v.response),data_frames=len(v.server_data_frames),
        frame_flow_sizes=[f['flow'] for f in v.server_data_frames],
        server_response_tls_records=v.server_tls,exchange_disk_reads=len(v.disk_reads)-reads,
        exchange_outgoing_records=len(v.transmitted)-sent,
        conn_credit_returned=conn,stream_credit_granted=stream,
        rendered=v.rendered.decode(),failed_as_expected=fail,grants=v.grants,
        ping_ack_payloads=[p.hex() for p in v.ping_acks],
        stack_low=hex(v.lowest_stack),response_sha256=hashlib.sha256(v.response).hexdigest())
    print(name,'PASS', 'frames',row['data_frames'],'reads',row['exchange_disk_reads'],
          'outgoing',row['exchange_outgoing_records'],flush=True)
    return row

rows=[]
scenarios=[('split-27-485',dict()),('unsplit-512',dict(pattern=(512,)))]
scenarios += [('split-1-511',dict(pattern=(1,511))),
        ('split-three',dict(pattern=(17,111,384))),
        ('split-TLS-header',dict(tls_split=5)),
        ('split-TLS-DATA-body',dict(tls_split=36)),
        ('padded-DATA',dict(padded=True)),
        ('trailer-END_STREAM',dict(trailers=True,body_size=4059)),
        ('carried-PING',dict(ping_split=True)),
        ('small-final-partial',dict(body_size=200)),
        ('forged-header',dict(forge_at=1)),
        ('forged-first-DATA',dict(forge_at=2)),
        ('forged-pending-DATA',dict(forge_at=3))]
scenarios.append(('ungranted-overrun',dict(overrun=True)))
for name,kw in scenarios:rows.append(run(name,**kw))
report=dict(passed=True,core_sha256=E.INFO['core_sha256'],cases=len(rows),rows=rows,
    limits=['Exact emitted response owner, R/X/K/H2/T and real AEAD; synthetic keys only.',
            'Independent h2 peer enforces actual stream/connection credit. BIOS/NIC/display are fixture leaves.',
            'Counts are complete affected exchange record/read counts, not original-speed elapsed-time or live acceptance.',
            'Cancellation, native/compaction, repeated streams, loader failures and reconnect retain separate required gates.'])
(TEST_IMAGE/'receive-credit-gate.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='rows'},indent=2),flush=True)
