# Task-Scoped Pseudonymization for LLM Security Alert Correlation

Reproducible scripts for evaluating **task-scoped HMAC pseudonymization** in an LLM-assisted, same-asset security alert correlation task. The method preserves stable asset tokens within a security investigation and separates tokens across independent tasks.

## Research question

Does binding pseudonym stability to investigation tasks preserve cross-window same-asset correlation utility while preventing **direct token-equality linkage** between tasks?

Five identifier representations are evaluated: `raw`, `redaction`, `global_hmac`, `scoped_hmac` (30-minute time window), and `task_scoped`.

## Data and evaluation scope

- Dataset: AIT-ADS, `russellmitchell` Wazuh scenario. Download from the original dataset provider and place `russellmitchell_wazuh.json` under `data/ait_ads/`.
- Original dataset record: <https://zenodo.org/records/8263181>
- Fixed experimental time interval (Unix seconds): `1642993260`–`1642999093`; window: 1800 seconds.
- 7,826 usable Wazuh alerts; 10 asset IPs; five assets appear in multiple time windows.
- Matched sample set: 50 positive and 50 negative cross-window alert pairs; seed `42`. Every matched positive/negative pair shares the anchor alert, and its second alert comes from the same target time window.
- Dataset labels in this study are **constructed from `agent.ip` equality**, not official multi-stage attack-chain labels.

## Setup (Windows PowerShell)

Create a Windows Python virtual environment (Python 3.10+):

```powershell
py -3.12 -m venv .venv-win
.\.venv-win\Scripts\python.exe -m pip install -r requirements.txt
```

Keep your DeepSeek API key **only** in a local environment variable. Never commit it:

```powershell
$env:DEEPSEEK_API_KEY = Read-Host "DeepSeek API Key" -AsSecureString | ConvertFrom-SecureString -AsPlainText
```

## Reproduction workflow

Run from the repository root, after downloading the dataset:

```powershell
$py = ".\.venv-win\Scripts\python.exe"
& $py scripts\audit_dataset.py
& $py scripts\build_pairs_v2.py
& $py scripts\verify_mechanism_v3.py
& $py scripts\eval_llm_v4.py --dry-run
& $py scripts\eval_llm_v4.py --pilot
& $py scripts\eval_llm_v4.py --full
& $py scripts\analyze_llm_v5.py
& $py scripts\verify_privacy_v6.py
& $py scripts\plot_paper_v7.py
```

Steps 4–6 use the DeepSeek API and can incur charges. The remaining steps run locally. The HMAC key is created under `.secrets/hmac.key` at the deterministic verification step and is **never** committed.

The archived model-request identifier is `deepseek-chat`; the server reported `deepseek-flash` in the recorded 500 responses. API-hosted models may change over time; the following values describe the observed run, not guaranteed future results.

## Results from the recorded run

| Strategy | LLM F1 | Balanced accuracy | Cross-task same-asset token equality |
|---|---:|---:|---:|
| Raw | 1.000 | 1.000 | 1.000 |
| Redaction | 0.214 | 0.560 | 1.000 |
| Global-HMAC | 0.901 | 0.910 | 1.000 |
| Time-scoped HMAC | 0.000 | 0.500 | 1.000 |
| **Task-scoped HMAC** | **0.925** | **0.930** | **0.000** |

The privacy metric above measures **direct token equality**, not resistance against every form of re-identification. The 100 alert pairs share a small number of assets, so pair-level results are not 100 independent observations.

See `results/llm_v4_full_metrics.json`, `results/mechanism_v3.json`, `results/privacy_v6.json` and `results/figures/` for the published summaries and manuscript figures.

## Repository layout

- `scripts/pseudonymizer.py` — five identifier-representation strategies.
- `scripts/audit_dataset.py`, `build_pairs_v2.py` — source audit and reproducible paired sampling.
- `scripts/verify_mechanism_v3.py` — deterministic identifier-equality baseline.
- `scripts/eval_llm_v4.py` — fixed-pair, API-based LLM evaluation with resumable records.
- `scripts/analyze_llm_v5.py` — prediction consistency and paired-error analysis.
- `scripts/verify_privacy_v6.py` — token-scope property checks.
- `scripts/plot_paper_v7.py` — three manuscript figures and a CSV summary.
- `results/` — reviewed summary metrics and figures; excludes raw logs, raw sampled pairs, API predictions, and keys.

The original prototype scripts (`eval_utility.py`, `privacy_audit.py`, `plot_tradeoff.py`) are retained for historical reference; use the versioned workflow above for the results reported here.
