"""Step 3: verify five pseudonymization modes on the fixed matched-pair set.

Run from repository root:
    python scripts/verify_mechanism_v3.py

No API calls; standard library only. Uses a local random HMAC key, never exports it.
Metrics here are deterministic token-matching baselines, NOT LLM evaluation.
"""
import argparse
import csv
import hashlib
import json
import secrets
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from pseudonymizer import Pseudonymizer

MODES = ('raw', 'redaction', 'global_hmac', 'scoped_hmac', 'task_scoped')


def score(y, pred):
    tp = sum(a and p for a,p in zip(y,pred))
    tn = sum(not a and not p for a,p in zip(y,pred))
    fp = sum(not a and p for a,p in zip(y,pred))
    fn = sum(a and not p for a,p in zip(y,pred))
    assert tp + tn + fp + fn == len(y)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    return {'n': len(y), 'TP': tp, 'TN': tn, 'FP': fp, 'FN': fn,
            'precision': round(precision, 6), 'recall': round(recall, 6),
            'f1': round(2*precision*recall/(precision+recall), 6) if precision+recall else 0.0,
            'balanced_accuracy': round((recall+specificity)/2, 6),
            'accuracy': round((tp+tn)/len(y), 6) if y else 0.0}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pairs', type=Path, default=ROOT/'results/pairs_v2.jsonl')
    ap.add_argument('--summary', type=Path, default=ROOT/'results/pairs_v2_summary.json')
    ap.add_argument('--out', type=Path, default=ROOT/'results/mechanism_v3.json')
    ap.add_argument('--key', type=Path, default=ROOT/'.secrets/hmac.key')
    args = ap.parse_args()
    if not args.pairs.is_file() or not args.summary.is_file():
        ap.error('Missing Step 2 files. Run python scripts/build_pairs_v2.py first.')
    expected = json.loads(args.summary.read_text(encoding='utf-8'))
    actual_hash = hashlib.sha256(args.pairs.read_bytes()).hexdigest()
    if actual_hash != expected['output_sha256']:
        raise SystemExit('SHA256 mismatch: pairs_v2.jsonl differs from Step 2 summary.')
    pairs = [json.loads(line) for line in args.pairs.open(encoding='utf-8') if line.strip()]
    assert len(pairs) == expected['total_pairs'], 'Pair count mismatch'
    ids = [p['pair_id'] for p in pairs]
    assert len(ids) == len(set(ids)), 'Duplicate pair_id'
    assert sum(p['label'] is True for p in pairs) == expected['positive_pairs']
    assert sum(p['label'] is False for p in pairs) == expected['negative_pairs']
    for p in pairs:
        a, b = p['log1'], p['log2']
        assert a['window'] != b['window'], f"Not cross-window: {p['pair_id']}"
        assert (a['asset_id'] == b['asset_id']) is p['label'], f"Bad label: {p['pair_id']}"
    anchors = {}
    for p in pairs:
        group = p['pair_id'][1:]
        anchors.setdefault(group, []).append(p)
    for group, entries in anchors.items():
        assert len(entries) == 2 and {p['label'] for p in entries} == {False,True}, group
        assert entries[0]['log1']['row_id'] == entries[1]['log1']['row_id'], group
        assert entries[0]['log2']['window'] == entries[1]['log2']['window'], group

    if not args.key.exists():
        args.key.parent.mkdir(exist_ok=True, parents=True)
        args.key.write_bytes(secrets.token_bytes(32))
        print('Created private 32-byte HMAC key at', args.key)
    key = args.key.read_bytes()
    assert len(key) >= 16, 'HMAC key must contain at least 16 bytes'
    hosts = {l['hostname'] for p in pairs for l in (p['log1'],p['log2']) if l.get('hostname')}
    labels = [p['label'] for p in pairs]
    results = {}
    for mode in MODES:
        predictions = []
        mask_failures = []
        for idx,p in enumerate(pairs):
            a,b = p['log1'],p['log2']
            # Each individual sample pair is an independent investigation task.
            scope = f'investigation_{p["pair_id"]}'
            obj = Pseudonymizer(mode=mode, secret_key=key, hostnames=hosts, task_id=scope)
            ta = obj._token('IP',a['asset_id'],a['timestamp'])
            tb = obj._token('IP',b['asset_id'],b['timestamp'])
            masked_a = obj.mask_text(a['text'], a['timestamp'])
            masked_b = obj.mask_text(b['text'], b['timestamp'])
            if mode != 'raw' and (f'IP:{ta}' not in masked_a or f'IP:{tb}' not in masked_b):
                mask_failures.append(p['pair_id'])
            predictions.append(ta == tb)
        assert not mask_failures, f'{mode}: missing transformed asset tokens: {mask_failures[:5]}'
        results[mode] = score(labels,predictions)

    # This test deliberately observes ONLY a single asset-IP token, never full logs.
    probe_ip = pairs[0]['log1']['asset_id']
    ts1 = pairs[0]['log1']['timestamp']
    ts2 = pairs[0]['log2']['timestamp']
    cross_task = {}
    for mode in MODES:
        p1 = Pseudonymizer(mode=mode,secret_key=key,hostnames=hosts,task_id='independent_A')
        p2 = Pseudonymizer(mode=mode,secret_key=key,hostnames=hosts,task_id='independent_B')
        cross_task[mode] = {'same_ip_token_equal_across_tasks': p1._token('IP',probe_ip,ts1) == p2._token('IP',probe_ip,ts1),
                            'same_ip_token_equal_across_windows': p1._token('IP',probe_ip,ts1) == p1._token('IP',probe_ip,ts2)}
    assert results['raw']['f1'] == 1
    assert results['global_hmac']['f1'] == 1
    assert results['task_scoped']['f1'] == 1
    assert cross_task['task_scoped']['same_ip_token_equal_across_tasks'] is False
    assert cross_task['task_scoped']['same_ip_token_equal_across_windows'] is True
    assert cross_task['global_hmac']['same_ip_token_equal_across_tasks'] is True
    report = {'experiment':'deterministic identifier equality (NOT LLM results)',
              'source_pair_count':len(pairs),'pairs_sha256':actual_hash,
              'window_sec':expected['window_sec'],
              'key_material':'local file only; not exported',
              'method_note':'No confidence intervals: pairs share 10 source assets and are correlated.',
              'modes':results,'single_token_probe':cross_task}
    args.out.parent.mkdir(exist_ok=True,parents=True)
    args.out.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print('=== Step 3: Deterministic Mechanism Verification (NOT LLM) ===')
    print('Pairs:',len(pairs),'| SHA256:',actual_hash)
    print('Mode                 TP TN FP FN     F1     BA')
    for mode,r in results.items():
        print(f'{mode:20} {r["TP"]:2} {r["TN"]:2} {r["FP"]:2} {r["FN"]:2}  {r["f1"]:.3f}  {r["balanced_accuracy"]:.3f}')
    print('Cross-task IP token equality:',{k:v['same_ip_token_equal_across_tasks'] for k,v in cross_task.items()})
    print('Task-scoped cross-window equality:',cross_task['task_scoped']['same_ip_token_equal_across_windows'])
    print('Saved:',args.out)

if __name__ == '__main__':
    main()
