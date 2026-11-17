"""Step 1: audit the exact AIT-ADS/Wazuh data scope used in the original paper.
Run from the project root: python scripts/audit_dataset.py
No third-party libraries or model API credentials are required.
"""
import json
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict

START = 1642993260.0
END = 1642999093.0
WINDOW = 1800
DATA = Path('data/ait_ads/russellmitchell_wazuh.json')
OUTPUT = Path('results/dataset_audit.json')


def parse_ts(ts):
    return datetime.fromisoformat(ts.replace('Z', '+00:00')).timestamp()


def main():
    if not DATA.exists():
        print(f'[ERROR] Data file not found: {DATA.resolve()}')
        print('Put russellmitchell_wazuh.json in data/ait_ads/ and rerun.')
        return

    total = 0
    invalid_json = missing_time = invalid_time = outside = missing_ip = 0
    observed = []
    ip_windows = defaultdict(set)
    ip_counts = Counter()
    time_min = time_max = None
    with DATA.open('r', encoding='utf-8') as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue
            total += 1
            try:
                row = json.loads(line)
            except (ValueError, TypeError):
                invalid_json += 1
                continue
            ts = row.get('@timestamp')
            if not ts:
                missing_time += 1
                continue
            try:
                epoch = parse_ts(ts)
            except (ValueError, TypeError):
                invalid_time += 1
                continue
            if not START <= epoch <= END:
                outside += 1
                continue
            ip = row.get('agent', {}).get('ip', '') if isinstance(row.get('agent'), dict) else ''
            if not isinstance(ip, str) or not ip.strip():
                missing_ip += 1
                continue
            ip = ip.strip()
            w = int(epoch // WINDOW)
            ip_windows[ip].add(w)
            ip_counts[ip] += 1
            observed.append((ip, w))
            time_min = epoch if time_min is None else min(time_min, epoch)
            time_max = epoch if time_max is None else max(time_max, epoch)

    candidates = {ip: len(wins) for ip, wins in ip_windows.items() if len(wins) >= 2}
    pairs_per_asset = {ip: 0 for ip in candidates}
    per_asset_window_counts = defaultdict(Counter)
    for ip, window in observed:
        if ip in candidates:
            per_asset_window_counts[ip][window] += 1
    for ip, c in per_asset_window_counts.items():
        vals = list(c.values())
        pairs_per_asset[ip] = (sum(vals) ** 2 - sum(x*x for x in vals)) // 2

    result = {
        'dataset': DATA.name,
        'scope': {'start_epoch': START, 'end_epoch': END, 'window_seconds': WINDOW},
        'raw_nonempty_lines': total,
        'invalid_json': invalid_json,
        'missing_timestamp': missing_time,
        'invalid_timestamp': invalid_time,
        'outside_original_time_range': outside,
        'missing_asset_ip_in_range': missing_ip,
        'usable_wazuh_alerts_in_range': len(observed),
        'unique_asset_ips_in_range': len(ip_counts),
        'time_span_epoch': [time_min, time_max],
        'asset_count_with_two_or_more_windows': len(candidates),
        'unique_windows_in_range': len({w for _,w in observed}),
        'cross_window_positive_pair_candidates_total': sum(pairs_per_asset.values()),
        'asset_alert_count_distribution': dict(Counter(ip_counts.values()).most_common()),
        'asset_window_count_distribution': dict(Counter(map(len,ip_windows.values())).most_common()),
        'notes': 'Pair candidates are combinatorial, not statistically independent; no pair samples were generated.'
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print('=== AIT-ADS Dataset Audit (original paper time range) ===')
    for key in ('raw_nonempty_lines','usable_wazuh_alerts_in_range','unique_asset_ips_in_range','unique_windows_in_range','asset_count_with_two_or_more_windows','cross_window_positive_pair_candidates_total'):
        print(f'{key}: {result[key]}')
    print(f'Output: {OUTPUT}')

if __name__ == '__main__':
    main()
