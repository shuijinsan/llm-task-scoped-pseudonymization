"""Step 7: verify token scope properties using the project's Pseudonymizer.
No LLM/API calls. No HMAC key or raw IPs are written to output.
Run from repository root: .\\.venv-win\\Scripts\\python.exe scripts\\verify_privacy_v6.py
"""
import hashlib
import json
import itertools
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict
from pseudonymizer import Pseudonymizer

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'data' / 'ait_ads' / 'russellmitchell_wazuh.json'
KEY_FILE = ROOT / '.secrets' / 'hmac.key'
OUTPUT = ROOT / 'results' / 'privacy_v6.json'
START, END, WINDOW = 1642993260.0, 1642999093.0, 1800
N_TASKS = 12
MODES = ('raw', 'redaction', 'global_hmac', 'scoped_hmac', 'task_scoped')


def get_assets_and_windows():
    assets = set()
    windows = set()
    usable = 0
    with DATA.open('r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                t = entry.get('@timestamp', '')
                if not t:
                    continue
                dt = datetime.fromisoformat(t.replace('Z', '+00:00'))
                if dt.tzinfo is None:
                    continue
                ts = dt.timestamp()
                ip = entry.get('agent', {}).get('ip')
                if START <= ts <= END and isinstance(ip, str) and ip.strip():
                    # reuse native validation: skip invalid addresses
                    import ipaddress
                    try:
                        ip = str(ipaddress.IPv4Address(ip.strip()))
                    except ValueError:
                        continue
                    assets.add(ip)
                    windows.add(int(ts // WINDOW))
                    usable += 1
            except (ValueError, TypeError, json.JSONDecodeError):
                continue
    if not assets or len(windows) < 2:
        raise RuntimeError('No assets or fewer than 2 windows. Check dataset location and time range.')
    return sorted(assets), sorted(windows), usable


def timestamp_for_window(bucket):
    return datetime.fromtimestamp(bucket * WINDOW + 60, tz=timezone.utc).isoformat()


def metric(test_pairs):
    checks = len(test_pairs)
    equal = sum(a == b for a,b in test_pairs)
    return {'comparisons':checks, 'equal':equal, 'equality_rate':round(equal/checks, 8) if checks else None}


def main():
    if not DATA.is_file():
        raise FileNotFoundError(f'Wazuh file not found: {DATA}')
    if not KEY_FILE.is_file():
        raise FileNotFoundError(f'Private HMAC key not found: {KEY_FILE}. Run step 3 first.')
    key = KEY_FILE.read_bytes()
    if len(key) < 16:
        raise ValueError('HMAC key is too short')
    assets, windows, usable = get_assets_and_windows()
    tasks = [f'investigation_{i:03d}' for i in range(N_TASKS)]
    stamps = [timestamp_for_window(w) for w in windows]
    result = {
        'experiment': 'scope-level token equality verification (NOT comprehensive reidentification privacy)',
        'implementation': 'scripts/pseudonymizer.py::Pseudonymizer._token',
        'data_file': DATA.name,
        'time_range': [START, END],
        'window_sec': WINDOW,
        'usable_alerts_with_valid_ipv4': usable,
        'distinct_assets': len(assets),
        'observed_windows': len(windows),
        'independent_task_ids': N_TASKS,
        'key_material': 'read from .secrets/hmac.key; NEVER exported',
        'per_mode': {},
        'limitations': [
            'This test only measures direct equality of IP identifier tokens.',
            'No claim about full-log leakage, indirect inference, or reidentification risk.',
            'HMAC collision absence in finite sample is not a probabilistic security proof.',
            'Time-scoped comparison holds the time window constant across task IDs.'
        ]
    }
    for mode in MODES:
        tokens = {}
        for asset in assets:
            for task in tasks:
                p = Pseudonymizer(mode=mode, secret_key=key if mode not in ('raw','redaction') else None, window_size_sec=WINDOW, task_id=task)
                for w, timestamp in zip(windows,stamps):
                    tokens[asset,task,w] = p._token('IP',asset,timestamp)
        within = []
        cross = []
        distinct = []
        for asset in assets:
            for task in tasks:
                for wa,wb in itertools.combinations(windows,2):
                    within.append((tokens[asset,task,wa],tokens[asset,task,wb]))
            for ta,tb in itertools.combinations(tasks,2):
                for w in windows:
                    cross.append((tokens[asset,ta,w],tokens[asset,tb,w]))
        for ia, a in enumerate(assets):
            for b in assets[ia+1:]:
                for task in tasks:
                    for w in windows:
                        distinct.append((tokens[a,task,w],tokens[b,task,w]))
        result['per_mode'][mode] = {
            'same_asset_same_task_cross_window':metric(within),
            'same_asset_cross_task_same_window':metric(cross),
            'different_asset_same_task_same_window':metric(distinct),
        }
    task = result['per_mode']['task_scoped']
    assert task['same_asset_same_task_cross_window']['equality_rate'] == 1.0
    assert task['same_asset_cross_task_same_window']['equality_rate'] == 0.0
    assert task['different_asset_same_task_same_window']['equality_rate'] == 0.0
    assert result['per_mode']['global_hmac']['same_asset_cross_task_same_window']['equality_rate'] == 1.0
    assert result['per_mode']['scoped_hmac']['same_asset_same_task_cross_window']['equality_rate'] == 0.0
    OUTPUT.parent.mkdir(parents=True,exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
    print('=== Step 7: Token-Scope Privacy Verification ===')
    print(f'Assets: {len(assets)} | observed windows: {len(windows)} | simulated tasks: {N_TASKS}')
    print('Mode            Within-task cross-window   Cross-task same-window   Different-asset same-task')
    for mode, stats in result['per_mode'].items():
        x=stats['same_asset_same_task_cross_window']['equality_rate']
        y=stats['same_asset_cross_task_same_window']['equality_rate']
        z=stats['different_asset_same_task_same_window']['equality_rate']
        print(f'{mode:<16}{x:>9.3f}{y:>25.3f}{z:>28.3f}')
    print('Task-Scoped assertions: PASS')
    print(f'Saved: {OUTPUT}')

if __name__ == '__main__':
    main()
