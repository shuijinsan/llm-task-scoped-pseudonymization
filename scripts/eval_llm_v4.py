"""Step 4: fixed-pair five-mode LLM utility comparison (DeepSeek API).

From repository root:
  python -m pip install openai
  python scripts/eval_llm_v4.py --dry-run
  python scripts/eval_llm_v4.py --pilot
  python scripts/eval_llm_v4.py --full

Writes incremental results, no raw prompt or HMAC key in output.
Requires DEEPSEEK_API_KEY in environment for non-dry runs.
"""
import argparse
import hashlib
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from pseudonymizer import Pseudonymizer

MODES = ('raw', 'redaction', 'global_hmac', 'scoped_hmac', 'task_scoped')
SYSTEM_PROMPT = ("You are a SOC analyst. Decide whether Alert 1 and Alert 2 originate from "
                 "the same monitored asset. Use only the provided alert text; do not assume "
                 "that two alerts share an asset merely because both have redacted fields. "
                 "Return a JSON object with exactly one required boolean property named "
                 "same_asset, and an optional short reason. No other text.")
MODEL = 'deepseek-chat'
BASE_URL = 'https://api.deepseek.com'


def load_pairs(path, summary_path):
    if not path.is_file() or not summary_path.is_file():
        raise SystemExit('Missing step 2 results. Run build_pairs_v2.py first.')
    summary = json.loads(summary_path.read_text(encoding='utf-8'))
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != summary['output_sha256']:
        raise SystemExit('Pair file hash mismatch. Do not evaluate changed data.')
    pairs = [json.loads(line) for line in path.open(encoding='utf-8') if line.strip()]
    if len(pairs) != summary['total_pairs'] or len({p['pair_id'] for p in pairs}) != len(pairs):
        raise SystemExit('Invalid sample count or pair ID duplication.')
    for p in pairs:
        a, b = p['log1'], p['log2']
        if a['window'] == b['window'] or (a['asset_id'] == b['asset_id']) is not p['label']:
            raise SystemExit(f'Invalid label or window: {p["pair_id"]}')
    return pairs, actual


def render(pair, mode, key, hosts):
    ps = Pseudonymizer(mode=mode, secret_key=key, hostnames=hosts,
                       task_id='investigation_' + pair['pair_id'])
    a, b = pair['log1'], pair['log2']
    t1 = ps.mask_text(a['text'], a['timestamp'])
    t2 = ps.mask_text(b['text'], b['timestamp'])
    if mode != 'raw':
        for log, masked in ((a, t1), (b, t2)):
            token = ps._token('IP', log['asset_id'], log['timestamp'])
            if 'IP:' + token not in masked:
                raise RuntimeError('Asset IP masking verification failed: ' + pair['pair_id'])
    return f'Alert 1:\n{t1}\n\nAlert 2:\n{t2}\n\nAre they from the same monitored asset?'


def call_model(client, prompt):
    # Retry transport / rate-limit errors; malformed JSON is recorded as a failure, not a prediction.
    last_err = None
    for attempt in range(3):
        try:
            response = client.chat.completions.create(
                model=MODEL, temperature=0, response_format={'type': 'json_object'},
                messages=[{'role': 'system', 'content': SYSTEM_PROMPT},
                          {'role': 'user', 'content': prompt}], timeout=60)
            content = response.choices[0].message.content or ''
            data = json.loads(content)
            prediction = data.get('same_asset')
            if type(prediction) is not bool:
                raise ValueError('same_asset is missing or is not JSON boolean')
            usage = getattr(response, 'usage', None)
            return {'status': 'ok', 'prediction': prediction,
                    'response_model': str(getattr(response, 'model', '')),
                    'reason': str(data.get('reason', ''))[:400],
                    'prompt_tokens': getattr(usage, 'prompt_tokens', None),
                    'completion_tokens': getattr(usage, 'completion_tokens', None)}
        except (ValueError, json.JSONDecodeError) as e:
            return {'status': 'bad_response', 'prediction': None, 'error': str(e)[:200]}
        except Exception as e:
            last_err = type(e).__name__ + ': ' + str(e)[:140]
            if attempt < 2:
                time.sleep(2 ** attempt)
    return {'status': 'api_error', 'prediction': None, 'error': last_err}


def score(records, expected_n):
    good = [r for r in records if r.get('status') == 'ok' and type(r.get('prediction')) is bool]
    c = Counter()
    for r in good:
        y, pred = r['label'], r['prediction']
        c['TP' if y and pred else 'TN' if not y and not pred else 'FP' if not y else 'FN'] += 1
    n = len(good)
    p = c['TP'] / (c['TP'] + c['FP']) if (c['TP'] + c['FP']) else 0
    rec = c['TP'] / (c['TP'] + c['FN']) if (c['TP'] + c['FN']) else 0
    spec = c['TN'] / (c['TN'] + c['FP']) if (c['TN'] + c['FP']) else 0
    # Do not present incomplete mode runs as final comparable outcomes.
    complete = n == expected_n
    return {'expected_n': expected_n, 'valid_n': n, 'failure_n': expected_n-n,
            'complete': complete, 'TP': c['TP'], 'TN': c['TN'], 'FP': c['FP'], 'FN': c['FN'],
            'precision': round(p, 6) if complete else None,
            'recall': round(rec, 6) if complete else None,
            'f1': round(2*p*rec/(p+rec), 6) if complete and (p+rec) else (0 if complete else None),
            'balanced_accuracy': round((rec+spec)/2, 6) if complete else None,
            'accuracy': round((c['TP']+c['TN'])/n, 6) if complete and n else None}


def main():
    parser = argparse.ArgumentParser()
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument('--dry-run', action='store_true', help='local validation only; no API')
    g.add_argument('--pilot', action='store_true', help='2 positive/negative groups = 4 pairs x 5 modes')
    g.add_argument('--full', action='store_true', help='all 100 pairs x 5 modes')
    args = parser.parse_args()
    pair_path = ROOT / 'results/pairs_v2.jsonl'
    pairs, hashval = load_pairs(pair_path, ROOT/'results/pairs_v2_summary.json')
    scope = 'full' if args.full else 'pilot'
    if not args.full:
        # P0001, N0001, P0002, N0002, preserving balanced paired design.
        pairs = [p for p in pairs if p['pair_id'] in ('P0001','N0001','P0002','N0002')]
        pairs.sort(key=lambda x: x['pair_id'])
        if len(pairs) != 4:
            raise SystemExit('Missing pilot sample IDs')
    keypath = ROOT/'.secrets/hmac.key'
    if not keypath.is_file():
        raise SystemExit('Missing HMAC key: run step 3 first')
    key = keypath.read_bytes()
    hosts = {x['hostname'] for p in pairs for x in (p['log1'],p['log2']) if x.get('hostname')}
    for mode in MODES:
        for pair in pairs:
            render(pair, mode, key, hosts)
    print('Verified input file SHA256:', hashval)
    print('Scope:', scope, '| pairs:', len(pairs), '| modes:', len(MODES),
          '| potential API calls:', len(pairs)*len(MODES), flush=True)
    if args.dry_run:
        print('DRY-RUN PASS: labels, windows, HMAC key, masking and prompts verified. No API calls.')
        return
    api_key = os.environ.get('DEEPSEEK_API_KEY', '').strip()
    if not api_key:
        raise SystemExit('DEEPSEEK_API_KEY is missing. Set it in the local PowerShell session.')
    try:
        from openai import OpenAI
    except ImportError:
        raise SystemExit('Install dependency: python -m pip install openai')
    client = OpenAI(api_key=api_key, base_url=BASE_URL, timeout=60, max_retries=0)
    out_dir = ROOT/'results'
    out_dir.mkdir(parents=True, exist_ok=True)
    outfile = out_dir / f'llm_v4_{scope}_predictions.jsonl'
    meta_file = out_dir / f'llm_v4_{scope}_manifest.json'
    manifest = {'input_sha256': hashval, 'scope': scope, 'model_requested': MODEL,
                'base_url': BASE_URL, 'temperature': 0, 'modes': list(MODES),
                'system_prompt_sha256': hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest(),
                'pair_ids': [p['pair_id'] for p in pairs]}
    if meta_file.exists():
        if json.loads(meta_file.read_text(encoding='utf-8')) != manifest:
            raise SystemExit('Manifest mismatch; refusing to mix different experiments.')
    else:
        meta_file.write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
    history = {}
    if outfile.exists():
        for line in outfile.open(encoding='utf-8'):
            if not line.strip(): continue
            rec = json.loads(line)
            history[(rec['mode'], rec['pair_id'])] = rec
    # If the previous call failed, retry and append a replacement; last record wins.
    remaining = sum(history.get((mode, p['pair_id']), {}).get('status') != 'ok'
                    for mode in MODES for p in pairs)
    print('Pending API calls:',remaining, flush=True)
    with outfile.open('a', encoding='utf-8') as f:
        for mode in MODES:
            for pair in pairs:
                ident = (mode, pair['pair_id'])
                if history.get(ident, {}).get('status') == 'ok':
                    continue
                prompt = render(pair, mode, key, hosts)
                result = call_model(client, prompt)
                rec = {'mode':mode, 'pair_id':pair['pair_id'], 'label':pair['label'],
                       'timestamp_utc':datetime.now(timezone.utc).isoformat(),
                       'prompt_sha256':hashlib.sha256(prompt.encode('utf-8')).hexdigest(), **result}
                f.write(json.dumps(rec, ensure_ascii=False)+'\n')
                f.flush()
                history[ident] = rec
                print(f"{mode:12} {pair['pair_id']:6} actual={int(pair['label'])} "
                      f"pred={result['prediction']} status={result['status']}", flush=True)
    results = {}
    for mode in MODES:
        mode_records = [history[(mode,p['pair_id'])] for p in pairs if (mode,p['pair_id']) in history]
        results[mode] = score(mode_records, len(pairs))
    report = {'experiment':'LLM same-asset association; not deterministic baseline',
              'scope':scope,'input_sha256':hashval,'model':MODEL,
              'note':'Only 10 unique assets in one scenario; pair-level observations correlated.',
              'modes':results}
    metricfile = out_dir / f'llm_v4_{scope}_metrics.json'
    metricfile.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print('\nMode            Valid/Total  TP TN FP FN   F1      BA')
    for mode, r in results.items():
        fm = f'{r["f1"]:.3f}' if r['f1'] is not None else 'INCOMPLETE'
        ba = f'{r["balanced_accuracy"]:.3f}' if r['balanced_accuracy'] is not None else '--'
        print(f'{mode:15} {r["valid_n"]:3}/{r["expected_n"]:<3}    {r["TP"]:2} {r["TN"]:2} {r["FP"]:2} {r["FN"]:2}  {fm:10} {ba}')
    print('Predictions:',outfile)
    print('Metrics:',metricfile)
    if any(not r['complete'] for r in results.values()):
        print('WARNING: incomplete runs. Resolve API failures, then re-run the same command to resume.')

if __name__ == '__main__':
    main()
