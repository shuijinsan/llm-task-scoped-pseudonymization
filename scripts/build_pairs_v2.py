"""Step 2: reproducible matched cross-window Wazuh alert pairs.
Run at repository root: python scripts/build_pairs_v2.py
Standard library only. Never calls an LLM or modifies raw data.
"""
import argparse
import hashlib
import json
import random
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

START = 1642993260.0
END = 1642999093.0
WINDOW_SEC = 1800


def epoch_of(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00')).timestamp()


def load_logs(path):
    logs = []
    counters = Counter()
    with path.open('r', encoding='utf-8') as f:
        for lineno, line in enumerate(f, 1):
            if not line.strip():
                continue
            counters['nonempty_rows'] += 1
            try:
                row = json.loads(line)
                ts = row['@timestamp']
                epoch = epoch_of(ts)
            except (KeyError, ValueError, TypeError, AttributeError):
                counters['malformed_rows'] += 1
                continue
            if not START <= epoch <= END:
                continue
            agent = row.get('agent')
            ip = agent.get('ip', '') if isinstance(agent, dict) else ''
            if not isinstance(ip, str) or not ip.strip():
                counters['missing_ip'] += 1
                continue
            ip = ip.strip()
            rule = row.get('rule') if isinstance(row.get('rule'), dict) else {}
            pre = row.get('predecoder') if isinstance(row.get('predecoder'), dict) else {}
            desc = str(rule.get('description') or '')
            host = str(pre.get('hostname') or '')
            raw = str(row.get('full_log') or '')
            text = f'[{ts}] IP:{ip} Host:{host} Event:{desc} Log:{raw}'
            logs.append({'row_id': lineno, 'timestamp': ts, 'epoch': epoch,
                         'window': int(epoch // WINDOW_SEC), 'asset_id': ip,
                         'hostname': host, 'text': text})
    return logs, counters


def make_pair(pos_anchor, pos_target, neg_target, ordinal):
    assert pos_anchor['asset_id'] == pos_target['asset_id']
    assert pos_anchor['asset_id'] != neg_target['asset_id']
    assert pos_anchor['window'] != pos_target['window']
    assert pos_target['window'] == neg_target['window']
    return [
        {'pair_id': f'P{ordinal:04d}', 'label': True,
         'log1': pos_anchor, 'log2': pos_target},
        {'pair_id': f'N{ordinal:04d}', 'label': False,
         'log1': pos_anchor, 'log2': neg_target},
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, default=Path('data/ait_ads/russellmitchell_wazuh.json'))
    parser.add_argument('--per-asset', type=int, default=10)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--output', type=Path, default=Path('results/pairs_v2.jsonl'))
    args = parser.parse_args()
    if args.per_asset < 1:
        parser.error('--per-asset must be >= 1')
    if not args.data.is_file():
        parser.error(f'Data file not found: {args.data}')
    rng = random.Random(args.seed)
    logs, source_stats = load_logs(args.data)
    by_asset_window = defaultdict(list)
    by_window = defaultdict(list)
    for x in logs:
        by_asset_window[(x['asset_id'], x['window'])].append(x)
        by_window[x['window']].append(x)
    asset_windows = defaultdict(list)
    for aid, w in sorted(by_asset_window):
        asset_windows[aid].append(w)
    eligible_assets = sorted(a for a, w in asset_windows.items() if len(w) >= 2)
    used_pos_pair = set()
    used_neg_pair = set()
    result = []
    per_asset = Counter()
    skipped_assets = []
    for aid in eligible_assets:
        # Eligible (anchor-window, target-window) directions with alternative asset
        combos = []
        windows = sorted(asset_windows[aid])
        for wa in windows:
            for wb in windows:
                if wa == wb:
                    continue
                other = [l for l in by_window[wb] if l['asset_id'] != aid]
                if other:
                    combos.append((wa, wb, other))
        if not combos:
            skipped_assets.append(aid)
            continue
        rng.shuffle(combos)
        used_anchor_ids = set()
        used_positive_target_ids = set()
        used_negative_target_ids = set()
        tries = 0
        while per_asset[aid] < args.per_asset and tries < max(500, args.per_asset * 100):
            tries += 1
            wa, wb, _ = combos[(tries - 1) % len(combos)]
            anchors = by_asset_window[(aid, wa)]
            positives = by_asset_window[(aid, wb)]
            negatives = [l for l in by_window[wb] if l['asset_id'] != aid]
            # Prioritize previously unused individual alerts. Reuse only if needed.
            if not anchors or not positives or not negatives:
                continue
            a_choices = [x for x in anchors if x['row_id'] not in used_anchor_ids] or anchors
            p_choices = [x for x in positives if x['row_id'] not in used_positive_target_ids] or positives
            n_choices = [x for x in negatives if x['row_id'] not in used_negative_target_ids] or negatives
            a = rng.choice(a_choices)
            p = rng.choice(p_choices)
            n = rng.choice(n_choices)
            pk = (a['row_id'], p['row_id'])
            nk = (a['row_id'], n['row_id'])
            if pk in used_pos_pair or nk in used_neg_pair:
                continue
            used_pos_pair.add(pk)
            used_neg_pair.add(nk)
            used_anchor_ids.add(a['row_id'])
            used_positive_target_ids.add(p['row_id'])
            used_negative_target_ids.add(n['row_id'])
            ordinal = len(result) // 2 + 1
            result.extend(make_pair(a, p, n, ordinal))
            per_asset[aid] += 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Preserve exact paired text for later evaluation; raw data remain local.
    with args.output.open('w', encoding='utf-8') as f:
        for pair in result:
            f.write(json.dumps(pair, ensure_ascii=False) + '\n')
    same_ids = Counter()
    for p in result:
        if p['log1']['row_id'] == p['log2']['row_id']:
            same_ids['identical_rows'] += 1
        if p['log1']['window'] == p['log2']['window']:
            same_ids['same_window'] += 1
        if (p['log1']['asset_id'] == p['log2']['asset_id']) != p['label']:
            same_ids['label_mismatch'] += 1
    assert not same_ids, f'Internal validation failed: {same_ids}'
    n_pos = sum(p['label'] for p in result)
    n_neg = len(result) - n_pos
    assert n_pos == n_neg
    summary = {
        'dataset': args.data.name,
        'time_range': [START, END], 'window_sec': WINDOW_SEC,
        'seed': args.seed, 'target_positive_pairs_per_eligible_asset': args.per_asset,
        'usable_wazuh_logs': len(logs), 'eligible_assets': len(eligible_assets),
        'positive_pairs': n_pos, 'negative_pairs': n_neg, 'total_pairs': len(result),
        'positive_per_asset': dict(sorted(per_asset.items())),
        'skipped_eligible_assets_no_matched_negative': skipped_assets,
        'paired_design': 'Each matched P/N uses the same anchor log; P and N targets share the same 30-minute time window.',
        'units_of_inference': 'Only 10 assets in a single scenario; alert pairs are correlated. Do not treat pair count as independent subjects.',
        'source_counters': dict(source_stats),
        'output_sha256': hashlib.sha256(args.output.read_bytes()).hexdigest(),
    }
    summary_path = args.output.with_name('pairs_v2_summary.json')
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print('=== Step 2: Matched Cross-Window Pair Construction ===')
    for k in ['usable_wazuh_logs', 'eligible_assets', 'positive_pairs', 'negative_pairs', 'total_pairs']:
        print(f'{k}: {summary[k]}')
    print('positive_per_asset:', dict(per_asset))
    print('Output:', args.output)
    print('Summary:', summary_path)
    print('SHA256:', summary['output_sha256'])
    if not result:
        print('[WARNING] No matched cross-window pairs found. Inspect asset/window coverage.')


if __name__ == '__main__':
    main()
