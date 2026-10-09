#!/usr/bin/env python3
"""Peer TCP receive-window backpressure across short H2 control records."""
from image_binding import TEST_IMAGE
from pathlib import Path
import argparse,json,struct
import check_h2_exchange as E
R=E.R
class WindowVM(E.VM):
 def __init__(self,**kw):
  self.window_gate=False;self.acknowledged=0;self.blocked=[];self.packet_ends=[]
  super().__init__(**kw)
 def ack(self,u,a,z,d):
  self.acknowledged=self.pos
  return super().ack(u,a,z,d)
 def transmit(self,u,a,z,d):
  self.acknowledged=self.pos
  return super().transmit(u,a,z,d)
 def receive(self,u,a,z,d):
  if not self.window_gate:return super().receive(u,a,z,d)
  available=256-(self.pos-self.acknowledged)
  remaining=min(e for e in self.packet_ends if e>self.pos)-self.pos if self.pos<len(self.wire) else 0
  # A legal sender can withhold a large write until at least half the last
  # advertised 256-byte receive window opens. Small writes still fit whole.
  if available<=0 or (remaining>available and available<128):
   self.blocked.append(dict(position=self.pos,unacked=self.pos-self.acknowledged))
   R.D.near_return(u,True);return
  prior=self.chunk;self.chunk=min(prior,available,remaining) if remaining else prior
  try:return super().receive(u,a,z,d)
  finally:self.chunk=prior
 def install_controls(self,n):
  from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
  seq=int.from_bytes(self.read(R.S['tls_server_record_seq'],8),'big');old=self.wire[self.pos:];off=0;plains=[]
  while off<len(old):
   size=5+int.from_bytes(old[off+3:off+5],'big');wire=old[off:off+size]
   nonce=bytearray(R.IV)
   for i,b in enumerate((seq+len(plains)).to_bytes(8,'big')):nonce[4+i]^=b
   plain=ChaCha20Poly1305(R.KEY).decrypt(bytes(nonce),wire[5:],wire[:5]);plains.append((plain[:-1],plain[-1]));off+=size
  controls=[(R.frame(8,(1).to_bytes(4,'big'),stream=0),23)]*n
  self.wire=self.wire[:self.pos];self.packet_ends=[]
  for i,(plain,kind) in enumerate(controls+plains):
   self.wire+=R.A.server_record(R.KEY,R.IV,seq+i,plain,kind,0);self.packet_ends.append(len(self.wire))
  self.nextseq=seq+len(controls)+len(plains);self.acknowledged=self.pos;self.window_gate=True

def main():
 p=argparse.ArgumentParser();p.add_argument('--expect-stall',action='store_true');a=p.parse_args();rows=[]
 for n in ([6] if a.expect_stall else [0,1,6,8,20]):
  v=WindowVM();v.request();v.install_controls(n);v.run_exchange(not a.expect_stall)
  if a.expect_stall:assert v.blocked and not v.rendered
  else:assert v.rendered==b'fortytwo' and not v.blocked
  row=dict(controls=n,blocked=v.blocked,acks=len(v.ack_positions),rendered_bytes=len(v.rendered));rows.append(row);print(row,flush=True)
 Path(E.OUT/('tcp-window-before.json' if a.expect_stall else 'tcp-window-gate.json')).write_text(json.dumps(dict(passed=True,expected_stall=a.expect_stall,core_sha256=E.INFO['core_sha256'],rows=rows),indent=2)+'\n')
if __name__=='__main__':main()
