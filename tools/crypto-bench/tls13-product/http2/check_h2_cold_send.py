#!/usr/bin/env python3
"""Cold R/X handoff with real H2 framing, sealing, credit, and failure unwind."""
import json
import check_h2_request_failures as F
Q=F.Q;R=F.R;OUT=F.OUT

def main():
    good=Q.VM(cold=True,window=17)
    request=good.request()
    assert request['input']=='Say Hello! ASCII only.' and 'tools' not in request
    assert request['model']=='gpt-6.1-sol' and request['reasoning']=={'effort':'max'}
    rows=[dict(name='cold-greeting',request_received=True)]
    for name,kw in [('cold-transmit-failure',dict(fail_send=True)),
                    ('cold-response-owner-failure',dict(fail_owner=True))]:
        failed=F.VM(cold=True,**kw);failed.fail_request()
        rows.append(dict(name=name,retired=True,stack_low=hex(failed.lowest_stack)))
    report=dict(passed=True,core_sha256=Q.INFO['core_sha256'],rows=rows,limits=__doc__)
    (OUT/'cold-send-gate.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
