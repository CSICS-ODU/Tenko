<div align="center">

<img src="https://gray-wdbj-prod.gtv-cdn.com/resizer/v2/2DFZHRYB3NMI7CGVOMXCPEVJII.jpg?auth=56763f06dc70d391d7bfba0b33a72480b3fa8dce8372a725d52b426441e3245d&width=800&height=450&smart=true" alt="Virginia Tech" width="320" />

# ⚠️ PATENT APPLIED FOR ⚠️

### Virginia Tech has applied for a patent covering the invention(s) described in this repository.

</div>

# Tenko

Tenko is a streaming network intrusion detection system built on the Kitsune / KitNET per-packet autoencoder backbone. It adds per-source node scoring, a benign-calibrated tolerance layer, and weighted decision fusion.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python results/CICIoT2023/build_table_ix_mixed.py --check
```

Tested with Python 3.14 and the pins in `requirements.txt`. Optional Cython fast path: `setup_cython.py` / `fastpath/`. Measured latency lives under `results/latency/` (`measure_all_latency.py`).

## How to run

```bash
python example.py      # KitNET on a PCAP/TSV → RMSEs.pkl
python results.py      # pattern models + weighted fusion → metrics / plots
```

Optional wrapper:

```bash
python workflow.py -i <input_pcap> -ip <tsv_file> -l <label_file> -o
# or with a saved RMSE pickle:
python workflow.py -r <saved_RMSE> -ip <tsv_file> -l <label_file> -b
```

CICIoT2023 drivers (`CIC_DATA_ROOT` / `CIC_RESULTS_ROOT`):

```bash
python run_ciciot2023.py --attacks all
python run_ciciot2023.py --tanh single --use-cached-rmse
```

## Datasets

| Dataset | Link |
|---|---|
| Kitsune | [UCI id=516](https://archive.ics.uci.edu/dataset/516/kitsune+network+attack+dataset) |
| N-BaIoT | [UCI id=442](https://archive.ics.uci.edu/dataset/442/detection_of_iot_botnet_attacks_n_baiot) |
| CICIoT2023 | [UNB CIC](https://www.unb.ca/cic/datasets/iotdataset-2023.html) |

## Configuration

| Knob | Default | Where |
|---|---|---|
| FM / AD grace | 5000 / 50000 | `example.py`, `run_ciciot2023.py` |
| `benignLimit` | 100000 (CIC mixed: 60000) | `results.py` / drivers |
| η_global / η_node | 50 / 20 | `run_ciciot2023.py` |
| Table X OR-rule | train-prefix ~2% FPR | `results/CICIoT2023/build_table_ix_mixed.py` |
| tanh | `single` (`--tanh double` available) | `run_ciciot2023.py`; mixed path is single |
| Pattern window / segments | 100 / 10 | drivers |
| `memorySize` | 60 (fixed before evaluation) | drivers |

## License / citation

Cite the Tenko paper and upstream Kitsune / KitNET as appropriate. Follow each dataset provider’s terms of use.
