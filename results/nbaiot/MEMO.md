# N-BaIoT Table V — rebuild memo (reviewer blocker B3)

**Goal.** Make the N-BaIoT per-device / per-attack table (paper Table V) reproducible from
committed code + located raw data. Previously nothing (no loader, no driver, no CSV) was in
the repo history.

## Inputs (real data, located on this Mac — read-only)

- **Raw dataset:** `~/dataset/N-BaIoT/` (UCI N-BaIoT download) — 9 devices, 115 AfterImage
  features + header, `<d>.benign.csv` + `<d>.{gafgyt,mirai}.<attack>.csv`, `device_info.csv`
  (DeviceID→name). Devices 3 (Ennio) and 7 (Samsung) are gafgyt-only (authentic).
- **Recovered prior output (provenance only):** `<external>/NBAIOT_RESULTS_ALL.csv`,
  the output of the original external driver `<external>/nbaio_tenko_eval.py`.
  That driver imports `KitNET.KitNET_improved`, which **no longer exists on disk**.

## Committed driver

`results/nbaiot/run_nbaiot_tableV.py` — self-contained, uses the repo's own
`KitNET/KitNET.py` (paper-style numpy dA). Protocol (identical to the original):
per device, first 90% of benign rows train KitNET with a **fixed contiguous 12×10 feature
map** (no FM-grace clustering); threshold = `mean+3σ` of KitNET RMSE over the train rows
(attack-free); every attack file scored, flagged if RMSE > threshold. Emits tn/fp/fn/tp,
TPR, FPR, precision, F1, accuracy, **AUC** (Mann-Whitney) and **EER** per (device, attack).

> Note: the repo `KitNET.__init__` has a latent ordering bug when a feature map is passed
> positionally (`__createAD__` runs before `ensembleLayer=[]`). The driver documents and
> works around it (`build_kitnet`), reproducing the intended fixed-ensemble behaviour that
> the missing `KitNET_improved` provided.

## Command

```
.venv/bin/python results/nbaiot/run_nbaiot_tableV.py \
    --dataset "~/dataset/N-BaIoT" --print-results \
    --output results/nbaiot/nbaiot_tableV_metrics.csv
```

Runtime ≈ **699 s (~11.7 min)**, ~7.06 M packets, single core. → **80 rows** (device × attack).

## Outputs

| File | What |
|---|---|
| `nbaiot_tableV_metrics.csv` | **Rebuilt Table V** from raw data with committed code (80 rows, incl. AUC/EER). |
| `nbaiot_verification_vs_recovered.csv` | Row-by-row rebuilt-vs-original comparison; carries the recovered external run (`NBAIOT_RESULTS_ALL.csv`) values as the `*_orig` columns, for provenance. |
| `run_full.log` | Full run log (per-device thresholds + per-attack METRIC lines). |

## Verification vs the recovered original

- **72 / 80 rows agree within 0.02 TPR.** Mean |ΔFPR| = 0.013 (max 0.020); the near-perfect
  detection structure (mirai + most gafgyt: TPR≈1.0, AUC≈1.0, EER≈0) reproduces cleanly.
- **8 rows diverge** — all `gafgyt.tcp` / `gafgyt.udp`, on devices **2, 5, 7, 9**. In every
  case the *original* reported detector collapse (TPR≈0, e.g. dev2 gafgyt.tcp AUC 0.003)
  while the *rebuild* detects them (TPR≈1.0, AUC≥0.87):

  | device | attack | TPR rebuilt | TPR orig | AUC rebuilt | AUC orig |
  |---|---|---|---|---|---|
  | 2 | gafgyt.tcp | 1.000 | 0.000 | 1.000 | 0.003 |
  | 2 | gafgyt.udp | 1.000 | 0.001 | 1.000 | 0.003 |
  | 5 | gafgyt.tcp | 1.000 | 0.001 | 0.990 | 0.949 |
  | 5 | gafgyt.udp | 1.000 | 0.001 | 0.990 | 0.949 |
  | 7 | gafgyt.tcp | 0.999 | 0.000 | 0.874 | 0.863 |
  | 7 | gafgyt.udp | 0.999 | 0.000 | 0.874 | 0.863 |
  | 9 | gafgyt.tcp | 1.000 | 0.000 | 0.981 | 0.929 |
  | 9 | gafgyt.udp | 1.000 | 0.000 | 0.981 | 0.929 |

**Cause & honesty note.** The divergence is attributable to the autoencoder variant: the
published numbers were generated with `KitNET_improved` (now missing), whereas this rebuild
uses the committed paper-style `KitNET`. The two agree everywhere except the pathological
gafgyt tcp/udp cases on 4 devices, where the original run collapsed to TPR≈0. The rebuilt
CSV is the defensible, fully-reproducible artifact; the recovered original is retained only
for provenance. Numbers were **run**, not transcribed — no fabrication.
