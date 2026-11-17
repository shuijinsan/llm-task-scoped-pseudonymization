"""Step 8: publication figures from verified study JSON files.
Run at repository root: .\\.venv-win\\Scripts\\python.exe scripts\\plot_paper_v7.py
Requires matplotlib. No API requests, no modification of source results.
"""
from pathlib import Path
import csv
import json
import math

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / 'results'
OUT = RESULTS / 'figures'
MODES = ['raw', 'redaction', 'global_hmac', 'scoped_hmac', 'task_scoped']
LABELS = ['Raw', 'Redaction', 'Global-HMAC', 'Time-Scoped', 'Task-Scoped']


def read_json(name):
    path = RESULTS / name
    if not path.is_file():
        raise FileNotFoundError(f'Missing {path}. Please run the corresponding experiment first.')
    return json.loads(path.read_text(encoding='utf-8'))


def require_rate(x, name):
    if isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x) or not 0 <= x <= 1:
        raise ValueError(f'Invalid rate {name}={x!r}')
    return float(x)


def main():
    llm = read_json('llm_v4_full_metrics.json')
    det = read_json('mechanism_v3.json')
    privacy = read_json('privacy_v6.json')
    if llm.get('scope') != 'full':
        raise ValueError('Expected full LLM experiment, not pilot')
    if llm.get('input_sha256') != det.get('pairs_sha256'):
        raise ValueError('Input SHA256 mismatch between LLM and deterministic results')
    if any(not llm['modes'][m].get('complete') or llm['modes'][m].get('valid_n') != 100 for m in MODES):
        raise ValueError('Expected 100 valid LLM predictions per strategy')
    if privacy.get('distinct_assets') != 10 or privacy.get('independent_task_ids') != 12:
        raise ValueError('Privacy experiment metadata differs from audited setup')

    def values(obj, key, modes_key='modes'):
        return [require_rate(obj[modes_key][m][key], f'{m}.{key}') for m in MODES]

    llm_f1 = values(llm, 'f1')
    llm_ba = values(llm, 'balanced_accuracy')
    det_f1 = values(det, 'f1')
    within = [require_rate(privacy['per_mode'][m]['same_asset_same_task_cross_window']['equality_rate'], m+'.within') for m in MODES]
    cross = [require_rate(privacy['per_mode'][m]['same_asset_cross_task_same_window']['equality_rate'], m+'.cross') for m in MODES]
    diff = [require_rate(privacy['per_mode'][m]['different_asset_same_task_same_window']['equality_rate'], m+'.diff') for m in MODES]

    OUT.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({'font.size': 10, 'axes.spines.top': False, 'axes.spines.right': False, 'pdf.fonttype': 42})
    x = np.arange(len(MODES))
    width = 0.35

    fig, ax = plt.subplots(figsize=(9, 4.5))
    bars1 = ax.bar(x - width/2, llm_f1, width, label='F1', color='#286A86')
    bars2 = ax.bar(x + width/2, llm_ba, width, label='Balanced accuracy', color='#A6A6A6')
    ax.set_xticks(x, LABELS)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel('Score')
    ax.set_title('LLM same-asset correlation performance (100 pairs per strategy)')
    ax.legend(frameon=False, loc='upper right')
    for bars in [bars1, bars2]:
        ax.bar_label(bars, fmt='%.3f', padding=3, fontsize=8)
    fig.tight_layout()
    for suffix in ['png', 'pdf']:
        fig.savefig(OUT / f'figure_5_1_llm_performance.{suffix}', dpi=300, bbox_inches='tight')
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(9, 4.5))
    b1 = ax.bar(x-width/2, det_f1, width, label='Deterministic F1', color='#A6A6A6')
    b2 = ax.bar(x+width/2, llm_f1, width, label='LLM F1', color='#286A86')
    ax.set_xticks(x, LABELS)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel('F1')
    ax.set_title('Identifier-equality baseline vs. LLM correlation')
    ax.legend(frameon=False, loc='upper right')
    for bars in [b1, b2]:
        ax.bar_label(bars, fmt='%.3f', padding=3, fontsize=8)
    fig.tight_layout()
    for suffix in ['png', 'pdf']:
        fig.savefig(OUT / f'figure_5_2_baseline_comparison.{suffix}', dpi=300, bbox_inches='tight')
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(9, 4.5))
    b1 = ax.bar(x-width/2, within, width, label='Same task, cross-window', color='#286A86')
    b2 = ax.bar(x+width/2, cross, width, label='Cross-task, same window', color='#B9784B')
    ax.set_xticks(x, LABELS)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel('Token equality rate')
    ax.set_title('Scope-level identifier-token equality (not re-identification risk)')
    ax.legend(frameon=False, loc='upper right')
    for bars in [b1, b2]:
        ax.bar_label(bars, fmt='%.3f', padding=3, fontsize=8)
    fig.tight_layout()
    for suffix in ['png', 'pdf']:
        fig.savefig(OUT / f'figure_5_3_scope_equality.{suffix}', dpi=300, bbox_inches='tight')
    plt.close(fig)

    csvpath = OUT / 'paper_results_table.csv'
    with csvpath.open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(['method', 'LLM_F1', 'LLM_BA', 'deterministic_F1', 'within_task_cross_window_token_equality', 'cross_task_same_window_token_equality', 'different_asset_same_task_token_equality'])
        for i, mode in enumerate(MODES):
            writer.writerow([LABELS[i], llm_f1[i], llm_ba[i], det_f1[i], within[i], cross[i], diff[i]])
    print('INPUT CHECKS: PASS (full LLM + deterministic baseline + privacy verification)')
    print('Generated 3 figures in PNG and PDF, plus CSV:', OUT)
    print('Important: figure 5-3 measures token equality only, not comprehensive privacy.')

if __name__ == '__main__':
    main()
