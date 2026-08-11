"""
Extract the 100-dim AfterImage/Kitsune feature vectors (the exact input that
Tenko's KitNET consumes) from each CICIoT2023 stream TSV, so that Mateen and
VAEESDD can be run on the same packet-level representation.

Outputs, per stream <name>, into results/CICIoT2023/baselines/features/:
    X_<name>.npy      float32 (N, 100)   AfterImage features, per packet
    y_<name>.npy      int8    (N,)       0=benign, 1=attack

Run from the Tenko repo root with the base venv:
    .venv/bin/python results/CICIoT2023/baselines/extract_features.py
"""
import os
import sys
import numpy as np

# Ensure repo root on path so `import FeatureExtractor` / `netStat` resolve.
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, REPO_ROOT)

from FeatureExtractor import FE  # noqa: E402

OUT_DIR = os.path.join(REPO_ROOT, "results", "CICIoT2023", "baselines", "features")

# (name, tsv_path, label_csv_path)
STREAMS = [
    ("mixed",
     "results/CICIoT2023/mixed/stream_mixed.pcap.tsv",
     "results/CICIoT2023/mixed/labels_mixed.csv"),
]
for atk in ["DDoS-UDP_Flood", "DoS-SYN_Flood", "Recon-OSScan",
            "MITM-ArpSpoofing", "Mirai-greeth_flood", "DictionaryBruteForce"]:
    STREAMS.append((
        f"indep_{atk}",
        f"results/CICIoT2023/indep/stream_{atk}.pcap.tsv",
        f"results/CICIoT2023/indep/labels_{atk}.csv",
    ))


def load_labels(path):
    # header line "x" then one int per row
    with open(path) as f:
        rows = f.read().split()
    if rows and not rows[0].lstrip("-").isdigit():
        rows = rows[1:]
    return np.asarray([int(v) for v in rows], dtype=np.int8)


def extract_stream(name, tsv_path, label_path):
    tsv_abs = os.path.join(REPO_ROOT, tsv_path)
    x_out = os.path.join(OUT_DIR, f"X_{name}.npy")
    y_out = os.path.join(OUT_DIR, f"y_{name}.npy")
    if os.path.exists(x_out) and os.path.exists(y_out):
        print(f"[skip] {name}: already extracted -> {x_out}")
        return

    print(f"\n=== Extracting {name} from {tsv_path} ===")
    fe = FE(tsv_abs)
    n_pkts = int(fe.limit)
    feat_dim = None
    feats = []
    for _ in range(n_pkts):
        row = fe.get_next_vector()
        if len(row) == 0:
            # A rare mid-stream parse error also returns []; keep index
            # alignment with the label file by inserting a zero vector.
            feats.append(None)
            continue
        v = np.asarray(row[0], dtype=np.float32)
        feat_dim = v.shape[0]
        feats.append(v)
        if len(feats) % 20000 == 0:
            print(f"  {name}: {len(feats)} packets")

    if feat_dim is None:
        raise RuntimeError(f"{name}: no features extracted")
    zero = np.zeros(feat_dim, dtype=np.float32)
    n_missing = sum(1 for f in feats if f is None)
    if n_missing:
        print(f"  [warn] {name}: {n_missing} packets failed to parse; zero-filled")
    X = np.vstack([f if f is not None else zero for f in feats]).astype(np.float32)
    y = load_labels(os.path.join(REPO_ROOT, label_path))
    n = min(len(X), len(y))
    if len(X) != len(y):
        print(f"  [warn] {name}: feat rows={len(X)} label rows={len(y)}; "
              f"truncating to {n}")
    X, y = X[:n], y[:n]

    np.save(x_out, X)
    np.save(y_out, y)
    print(f"  saved X{X.shape} dtype={X.dtype}, y{y.shape} pos={int(y.sum())}")


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    for name, tsv, lab in STREAMS:
        extract_stream(name, tsv, lab)
    print("\nAll streams extracted.")


if __name__ == "__main__":
    main()
