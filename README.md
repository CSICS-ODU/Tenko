<div align="center">

<img src="https://gray-wdbj-prod.gtv-cdn.com/resizer/v2/2DFZHRYB3NMI7CGVOMXCPEVJII.jpg?auth=56763f06dc70d391d7bfba0b33a72480b3fa8dce8372a725d52b426441e3245d&width=800&height=450&smart=true" alt="Virginia Tech" width="320" />

# ⚠️ PATENT APPLIED FOR ⚠️

### Virginia Tech has applied for a patent covering the invention(s) described in this repository.

</div>

# Overview

Tenko is a streaming network intrusion detection system built on the Kitsune / KitNET per-packet autoencoder backbone. It adds per-source node scoring, a benign-calibrated tolerance layer, and weighted decision fusion.

The codebase consists of two primary scripts:

1. `example.py`: Runs KitNET on a PCAP/TSV and writes intermediate RMSE scores (`RMSEs.pkl`).
2. `results.py`: Consumes those scores (with TSV/labels) to build pattern models, fuse decisions, and report metrics / plots.

For further details, please refer to the main paper.

# Pre-requisites and requirements

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Tested with Python 3.14 and the pins in `requirements.txt`. Optional Cython fast path: `setup_cython.py` / `fastpath/`.

# How to Use

## Running Tenko

```bash
python example.py
python results.py
```

Edit input paths inside the scripts for your PCAP, TSV, and label files.

Optional parameterized wrapper:

```bash
python workflow.py -i <input_pcap> -ip <tsv_file> -l <label_file> -o
# or with a saved RMSE pickle:
python workflow.py -r <saved_RMSE> -ip <tsv_file> -l <label_file> -b
```

CICIoT2023 driver:

```bash
python run_ciciot2023.py --attacks all
```

Figure reproduction scripts live under `reproducibility/plots/` (outputs stay under `results/.../figs/`). See `reproducibility/figure_manifest.csv` for Fig5–Fig7 / Table X paths. Rebuild Table X with `python results/CICIoT2023/build_table_ix_mixed.py --check`.

Regenerate CICIoT2023 RMSE timeline plots from committed CSVs:

```bash
python reproducibility/plots/plot_rmse_from_csv_ciciot.py
```

Regenerate Kitsune-dataset (OS Scan / SSDP) RMSE timelines from committed CSVs:

```bash
python reproducibility/plots/plot_rmse_from_csv_kitsune.py
```

CICIoT2023 t-SNE (requires committed feature matrices under `results/CICIoT2023/baselines/features/`):

```bash
MPLBACKEND=Agg python reproducibility/plots/plot_tsne.py
```

OS Scan Adjusted Anomaly Scores (`results.py` path) and Kitsune anomaly scores (`example.py` / `plot_loss`):

```bash
MPLBACKEND=Agg python reproducibility/plots/plot_os_scan_adjusted_anomaly.py
MPLBACKEND=Agg python reproducibility/plots/plot_os_scan_example_anomaly.py
```

# Datasets

Organize downloaded data under this repository, then point the scripts at your local paths.

- **Kitsune** (and mixed Kitsune-style streams): [UCI ML Repository id=516](https://archive.ics.uci.edu/dataset/516/kitsune+network+attack+dataset). Dataset / evaluation-setup reference for Kitsune and mixed Kitsune streams follows [Mateen’s README](https://github.com/ICL-ml4csec/Mateen/blob/main/README.md).
- **N-BaIoT**: [UCI ML Repository id=442](https://archive.ics.uci.edu/dataset/442/detection_of_iot_botnet_attacks_n_baiot)
- **CICIoT2023**: [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/iotdataset-2023.html)

# Citation

Cite the Tenko paper and upstream Kitsune / KitNET as appropriate. Follow each dataset provider’s terms of use.
