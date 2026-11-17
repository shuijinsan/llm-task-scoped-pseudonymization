#!/usr/bin/env python3
"""Audit paired LLM experimental results (stdlib only). Does not call any API."""
import argparse,csv,json,collections,hashlib,math
from pathlib import Path

MODES=('raw','redaction','global_hmac','scoped_hmac','task_scoped')

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--predictions',default='results/llm_v4_full_predictions.jsonl')
    p.add_argument('--metrics',default='results/llm_v4_full_metrics.json')
    p.add_argument('--out-dir',default='results')
    a=p.parse_args(); out=Path(a.out_dir);out.mkdir(parents=True,exist_ok=True)
    data=[json.loads(s) for s in Path(a.predictions).read_text(encoding='utf-8').splitlines() if s.strip()]
    m=json.loads(Path(a.metrics).read_text(encoding='utf-8'))
    assert m['scope']=='full', 'Not full experiment'
    records={}; duplicates=[]; models=collections.Counter(); statuses=collections.Counter()
    for r in data:
        key=(r['mode'],r['pair_id']); statuses[(r['mode'],r['status'])]+=1
        if key in records: duplicates.append(key)
        records[key]=r
        models[r.get('response_model','UNKNOWN')]+=1
    if duplicates: raise ValueError(f'Duplicate (mode,pair_id) records: {duplicates[:5]}')
    ids=sorted({k[1] for k in records})
    assert len(ids)==100, f'Expected 100 unique pair IDs, found {len(ids)}'
    for id in ids:
        rr=[records.get((mode,id)) for mode in MODES]
        assert all(rr), f'Missing prediction for {id}'
        assert all(x['status']=='ok' and isinstance(x['prediction'],bool) for x in rr),f'Failed or invalid: {id}'
        assert len({x['label'] for x in rr})==1,f'Label mismatch {id}'
        assert len({x.get('prompt_sha256') for x in rr})==len(MODES),f'Check prompt hashes for {id}'
    rows=[];summary={}
    for id in ids:
        r=records[('raw',id)]; row={'pair_id':id,'label':int(r['label'])}
        for mode in MODES:
            v=records[(mode,id)];row[mode+'_correct']=int(v['prediction']==v['label']);row[mode+'_prediction']=int(v['prediction'])
        rows.append(row)
    b=sum(row['global_hmac_correct']==0 and row['task_scoped_correct']==1 for row in rows)
    c=sum(row['global_hmac_correct']==1 and row['task_scoped_correct']==0 for row in rows)
    n=b+c
    # Exact two-sided McNemar binomial test (under null P(B)=P(C)=1/2)
    pval=min(1.0,2*sum(math.comb(n,k) for k in range(min(b,c)+1))/2**n) if n else 1.0
    summary={'model_requested':m.get('model'),'models_reported':dict(models),'records':len(data),'unique_pairs':len(ids),'status_counts':{f'{mode}:{status}':v for (mode,status),v in statuses.items()},'paired_global_vs_task':{'global_wrong_task_right':b,'task_wrong_global_right':c,'both_wrong':sum(not row['global_hmac_correct'] and not row['task_scoped_correct'] for row in rows),'both_right':sum(row['global_hmac_correct'] and row['task_scoped_correct'] for row in rows),'exact_mcnemar_p_two_sided':round(pval,6),'note':'Exploratory only: alert pairs overlap and are not independent; this p-value is NOT confirmatory.'},'sha256_predictions':hashlib.sha256(Path(a.predictions).read_bytes()).hexdigest()}
    for mode in MODES:
        d=[r for r in data if r['mode']==mode]; pred=[r['prediction'] for r in d];truth=[r['label'] for r in d]
        tp=sum(x and y for x,y in zip(pred,truth));tn=sum(not x and not y for x,y in zip(pred,truth));fp=sum(x and not y for x,y in zip(pred,truth));fn=sum(not x and y for x,y in zip(pred,truth))
        assert all(m['modes'][mode][key]==val for key,val in [('TP',tp),('TN',tn),('FP',fp),('FN',fn)]),f'Metrics mismatch: {mode}'
    with (out/'llm_v5_paired_errors.csv').open('w',newline='',encoding='utf-8-sig') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0].keys()));writer.writeheader();writer.writerows(rows)
    (out/'llm_v5_audit.json').write_text(json.dumps(summary,indent=2,ensure_ascii=False),encoding='utf-8')
    print('Audit PASS: 500 valid predictions, 100 matched pairs, metrics consistent')
    print('Requested model:',summary['model_requested'],'| Returned:',summary['models_reported'])
    print('Global wrong / Task right:',b,'| Task wrong / Global right:',c)
    print('Exploratory exact McNemar p:',round(pval,6),'(invalid as confirmatory due to overlapping assets)')
    print('Saved:',out/'llm_v5_audit.json',out/'llm_v5_paired_errors.csv')
if __name__=='__main__':main()
