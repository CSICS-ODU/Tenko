# Tenko

Tenko is a streaming network intrusion detection system built on the Kitsune / KitNET per-packet autoencoder backbone. It adds per-source node scoring, a benign-calibrated tolerance layer, and weighted decision fusion so anomaly decisions are device-aware and trainable without attack labels.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
```

Tested with Python 3.14 and the pins in `requirements.txt`. Optional Cython fast path: see `setup_cython.py` / `fastpath/`.

## How to run

**Classic Kitsune-style demo** (edit paths inside the scripts as needed):

```bash
python example.py      # KitNET on a PCAP/TSV → RMSEs.pkl (stores tanh(RMSE))
python results.py      # pattern models + weighted fusion → metrics / plots
```

**Parameterized wrapper** (optional; less battle-tested than the two scripts above):

```bash
python workflow.py -i <input_pcap> -ip <tsv_file> -l <label_file> -o
# or with a saved RMSE pickle:
python workflow.py -r <saved_RMSE> -ip <tsv_file> -l <label_file> -b
```

**CICIoT2023 driver** (per-attack streams under `CIC_DATA_ROOT`, labels/metrics under `CIC_RESULTS_ROOT`):

```bash
python run_ciciot2023.py --attacks all
python run_ciciot2023.py --tanh double --use-cached-rmse   # committed pipeline (default)
python recalibrate_ciciot2023.py                          # benign-calibrated η from saved arrays
python recalibrate_ciciot2023_oos.py                      # out-of-sample η recalibration
```

Committed score arrays under `results/` can rebuild headline tables without re-downloading PCAPs (e.g. `results/CICIoT2023/build_table_ix_mixed.py`).

## Datasets

| Dataset | Role | Link / note |
|---|---|---|
| **Kitsune** (NDSS'18 / UCI) | Mirai-style demo & nine-attack table | [UCI ML Repository id=516](https://archive.ics.uci.edu/dataset/516/kitsune+network+attack+dataset); also [Kaggle mirror](https://www.kaggle.com/datasets/ymirsky/network-attack-dataset-kitsune) |
| **N-BaIoT** | Per-device / per-attack Table V | [UCI ML Repository id=442](https://archive.ics.uci.edu/dataset/442/detection_of_iot_botnet_attacks_n_baiot) — pass `--dataset` to `results/nbaiot/run_nbaiot_tableV.py` |
| **CICIoT2023** | Mixed-stream comparison & recalibration | [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/iotdataset-2023.html) (registration). Point the code with `CIC_DATA_ROOT` (default `./data/ciciot2023/pilot`) and optionally `CIC_RESULTS_ROOT` (default `./results/CICIoT2023`). |

## Configuration (key knobs)

Defaults below are what the committed CICIoT / Kitsune-style paths use. Call sites override function defaults in a few places — prefer the driver you actually run.

| Knob | Default (committed path) | Where |
|---|---|---|
| FM / AD grace | `FMgrace=5000`, `ADgrace=50000` | `example.py`, `run_ciciot2023.py`, `results.py` (`TRAIN_START = FM+AD+1`) |
| KitNET `maxAE` / lr / hidden ratio | `10` / `0.1` / `0.75` | `Kitsune.py` → `KitNET/KitNET.py` |
| Pattern train split | packets `[FM+AD+1 : benignLimit)` | `results.get_adversarial_IPs_weighted_pattern` |
| `benignLimit` | `100000` if unset; CIC streams use `n_lead=150000` from `stream_counts.csv` | `results.py`; `run_ciciot2023.py` |
| η_global / η_node (tol factors) | **50 / 20** | kwargs in `run_ciciot2023.py`; function defaults in `results.py` |
| Benign-calibrated η (orrule@2%) | mixed-stream **≈30.14 / 3.14** (re-derived from benign nd_g/nd_s) | `results/CICIoT2023/build_table_ix_mixed.py`; also `recalibrate_ciciot2023.py` |
| Fusion weights / threshold | `0.5 / 0.5`, τ=`0.5` | `run_ciciot2023.py` (note: `results.py` `main()` demo uses `0.3/0.7`) |
| Pattern window / segments | `100` / `10` | `run_ciciot2023.py` (`results.py` `main()` demo uses `30` / `5`) |
| Single vs double tanh | **double** = `tanh(tanh(raw))` (committed); `--tanh single` = one tanh | `example.py` stores `tanh(raw)`; `results.py` applies `tanh` again; CLI on `run_ciciot2023.py` |
| Kitsune Median+MAD | `median + 3 × 1.4826 × MAD` on post-grace benign | `run_ciciot2023.py` (`MAD_K=3.0`); same in mixed-table builder |
| Seeds | Core KitNET path is deterministic online SGD; latency wrapper uses `SEED=42`; t-SNE `--seed 42`; optional Torch AE hardcodes `42` | `workflow.py`, `results/CICIoT2023/figs/plot_tsne.py`, `KitNET/autoencoder.py` |

Hardcoded constants worth knowing (not CLI today): η 50/20 and pattern sizes in `run_ciciot2023.py`, `MAD_K`, and `benignLimit=100000` fallback in `results.py`. Override by editing the call or passing kwargs into `get_adversarial_IPs_weighted_pattern`.

## License / citation

Cite the Tenko paper and upstream Kitsune / KitNET as appropriate. Follow each dataset provider’s terms of use.
