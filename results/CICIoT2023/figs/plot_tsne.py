#!/usr/bin/env python3
"""
t-SNE of the CICIoT2023 feature space used by Tenko (Fig. 6 support).

WHAT FEATURE SPACE IS THIS?
    The vectors are the 100-dim AfterImage/Kitsune per-packet feature vectors
    produced by Tenko's own `FeatureExtractor`/`netStat` (see
    results/CICIoT2023/baselines/extract_features.py). This is the *exact input*
    that Tenko's KitNET consumes -- i.e. the detector's input feature space, at
    per-packet granularity. It is NOT a KitNET latent/reconstruction space and it
    is NOT the node-level aggregated view Tenko forms internally; those internal
    representations are not committed as feature matrices, so we honestly
    visualize the committed detector-input space. This caveat is stated in the
    figure caption and in tsne_analysis.md.

DATA (committed, not fabricated):
    results/CICIoT2023/baselines/features/
        X_mixed.npy  (420000,100) / y_mixed.npy  (0=benign 120000, 1=attack 300000)
        X_indep_<family>.npy (170000,100) / y_indep_<family>.npy
            (0=benign 120000, 1=attack 50000)  -- one file per attack family.

    The mixed stream's labels are binary (0/1) only and carry NO per-row family
    id, and per-row family cannot be recovered reliably from the mixed matrix
    (attempted exact-row matching covered only ~150k/300k attack rows because of
    float de-duplication). So family identity is taken from the per-family
    `X_indep_<family>` captures (family = attack of that capture), combined with
    the shared benign pool (benign rows of X_mixed, which are byte-identical to
    the indep benign rows). This visualizes the same feature population that
    composes the mixed stream, with trustworthy family labels.

OUTPUTS:
    results/CICIoT2023/figs/tsne_mixed.png / .pdf          -- 2-panel figure
    results/CICIoT2023/figs/data/tsne_mixed.csv            -- raw embedding
        columns: x, y, label, family, sampled_index, source
    results/CICIoT2023/figs/data/tsne_separation_stats.csv -- measured stats

RUN (from repo root):
    MPLBACKEND=Agg .venv/bin/python results/CICIoT2023/figs/plot_tsne.py
"""
import os
import sys
import argparse

os.environ.setdefault("MPLBACKEND", "Agg")
# Keep matplotlib from choking on a non-writable HOME cache in the sandbox.
os.environ.setdefault(
    "MPLCONFIGDIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), ".mplcache")
)

import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from sklearn.metrics import silhouette_score
from sklearn.neighbors import NearestNeighbors

HERE = os.path.dirname(os.path.abspath(__file__))
FEATURE_DIR = os.path.join(HERE, "..", "baselines", "features")
DATA_DIR = os.path.join(HERE, "data")

# Attack family -> coarse behavioural category (for interpretation).
FAMILIES = [
    ("DDoS-UDP_Flood", "volumetric flood"),
    ("DoS-SYN_Flood", "volumetric flood"),
    ("Mirai-greeth_flood", "volumetric flood (botnet)"),
    ("MITM-ArpSpoofing", "spoofing / MITM"),
    ("Recon-OSScan", "reconnaissance"),
    ("DictionaryBruteForce", "brute force"),
]

# Fixed, colour-blind-friendly palette (one per family + benign).
FAMILY_COLORS = {
    "Benign": "#9e9e9e",
    "DDoS-UDP_Flood": "#1f77b4",
    "DoS-SYN_Flood": "#17becf",
    "Mirai-greeth_flood": "#2ca02c",
    "MITM-ArpSpoofing": "#d62728",
    "Recon-OSScan": "#9467bd",
    "DictionaryBruteForce": "#ff7f0e",
}


def _load(name):
    return np.load(os.path.join(FEATURE_DIR, name), mmap_mode="r")


def build_dataset(n_benign, n_per_family, seed):
    """Subsample a fixed, reproducible benign+per-family matrix.

    Returns X (float32), label (0/1), family (str), src_index (int into the
    source .npy), source (str filename stem).
    """
    rng = np.random.default_rng(seed)

    Xm = _load("X_mixed.npy")
    ym = np.load(os.path.join(FEATURE_DIR, "y_mixed.npy"))
    benign_idx = np.flatnonzero(ym == 0)
    take = min(n_benign, benign_idx.size)
    b_sel = np.sort(rng.choice(benign_idx, size=take, replace=False))
    Xb = np.asarray(Xm[b_sel], dtype=np.float32)

    X_parts = [Xb]
    label = [np.zeros(take, dtype=np.int64)]
    family = [np.array(["Benign"] * take)]
    src_index = [b_sel.astype(np.int64)]
    source = [np.array(["X_mixed"] * take)]

    for fam, _cat in FAMILIES:
        Xf = _load(f"X_indep_{fam}.npy")
        yf = np.load(os.path.join(FEATURE_DIR, f"y_indep_{fam}.npy"))
        atk_idx = np.flatnonzero(yf == 1)
        k = min(n_per_family, atk_idx.size)
        sel = np.sort(rng.choice(atk_idx, size=k, replace=False))
        X_parts.append(np.asarray(Xf[sel], dtype=np.float32))
        label.append(np.ones(k, dtype=np.int64))
        family.append(np.array([fam] * k))
        src_index.append(sel.astype(np.int64))
        source.append(np.array([f"X_indep_{fam}"] * k))

    X = np.vstack(X_parts).astype(np.float32)
    label = np.concatenate(label)
    family = np.concatenate(family)
    src_index = np.concatenate(src_index)
    source = np.concatenate(source)
    return X, label, family, src_index, source


def run_tsne(X, seed, perplexity, pca_dim):
    """Standardize -> PCA (denoise/speed) -> t-SNE(2D). Scaler+PCA fit on the
    subsample itself (documented). Returns 2D embedding and the # PCA dims."""
    Xs = StandardScaler().fit_transform(X)
    d = min(pca_dim, Xs.shape[1], Xs.shape[0] - 1)
    Xp = PCA(n_components=d, random_state=seed).fit_transform(Xs)
    tsne = TSNE(
        n_components=2,
        perplexity=perplexity,
        init="pca",
        learning_rate="auto",
        max_iter=1000,
        metric="euclidean",
        random_state=seed,
        n_jobs=-1,
        verbose=1,
    )
    emb = tsne.fit_transform(Xp)
    return emb, d, Xs


def separation_stats(emb, Xs, label, family, seed):
    """Quantify how separable each family is from benign, in the 2D embedding
    (what the plot shows) and in the standardized 100-D input space."""
    rows = []
    benign_mask = label == 0
    benign_emb = emb[benign_mask]
    benign_centroid = benign_emb.mean(axis=0)
    benign_spread = np.median(np.linalg.norm(benign_emb - benign_centroid, axis=1))

    # Overall benign-vs-attack silhouette in 2D.
    overall_sil2d = silhouette_score(emb, (label != 0).astype(int))
    rows.append(
        dict(
            family="ALL_ATTACK",
            category="(benign vs any attack)",
            n=int((label != 0).sum()),
            silhouette_2d=round(float(overall_sil2d), 4),
            silhouette_hi=round(
                float(silhouette_score(Xs, (label != 0).astype(int))), 4
            ),
            centroid_dist_norm=np.nan,
            benign_knn_overlap=np.nan,
        )
    )

    cat_of = {f: c for f, c in FAMILIES}
    for fam, _cat in FAMILIES:
        fam_mask = family == fam
        fe = emb[fam_mask]
        # Pairwise benign-vs-this-family silhouette (2D and high-D).
        sub = benign_mask | fam_mask
        lab2 = fam_mask[sub].astype(int)  # 1 = family, 0 = benign
        sil2d = silhouette_score(emb[sub], lab2)
        silhi = silhouette_score(Xs[sub], lab2)
        # Centroid distance normalized by benign spread (embedding units).
        cdist = float(np.linalg.norm(fe.mean(axis=0) - benign_centroid))
        cdist_norm = cdist / (benign_spread + 1e-9)
        # kNN "same-family purity": for each family point, fraction of its k
        # nearest neighbours (within benign+family) that are also this family.
        # 1.0 = perfectly separated island; ~family_ratio = fully mixed w/ benign.
        k = 10
        nn = NearestNeighbors(n_neighbors=k + 1).fit(emb[sub])
        _, idx = nn.kneighbors(emb[fam_mask])
        neigh_is_fam = lab2[idx[:, 1:]]  # drop self
        purity = float(neigh_is_fam.mean())
        rows.append(
            dict(
                family=fam,
                category=cat_of[fam],
                n=int(fam_mask.sum()),
                silhouette_2d=round(float(sil2d), 4),
                silhouette_hi=round(float(silhi), 4),
                centroid_dist_norm=round(cdist_norm, 3),
                benign_knn_overlap=round(1.0 - purity, 3),
            )
        )
    return rows


def save_csv(path, emb, label, family, src_index, source):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("x,y,label,family,sampled_index,source\n")
        for i in range(emb.shape[0]):
            f.write(
                f"{emb[i,0]:.6f},{emb[i,1]:.6f},{int(label[i])},"
                f"{family[i]},{int(src_index[i])},{source[i]}\n"
            )


def save_stats_csv(path, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    cols = [
        "family",
        "category",
        "n",
        "silhouette_2d",
        "silhouette_hi",
        "centroid_dist_norm",
        "benign_knn_overlap",
    ]
    with open(path, "w") as f:
        f.write(",".join(cols) + "\n")
        for r in rows:
            f.write(",".join(str(r[c]) for c in cols) + "\n")


def plot(emb, label, family, out_png, out_pdf, meta):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 7))

    # Panel A: benign vs attack (binary).
    for lab, name, color in [(0, "Benign", "#9e9e9e"), (1, "Attack", "#d62728")]:
        m = label == lab
        ax1.scatter(
            emb[m, 0], emb[m, 1], s=4, c=color, alpha=0.45, linewidths=0, label=name
        )
    ax1.set_title("(a) Benign vs. Attack", fontsize=13)
    ax1.legend(markerscale=3, loc="best", framealpha=0.9)

    # Panel B: by attack family (benign underneath, faint).
    mb = family == "Benign"
    ax2.scatter(emb[mb, 0], emb[mb, 1], s=4, c=FAMILY_COLORS["Benign"], alpha=0.3,
                linewidths=0, label="Benign")
    for fam, _cat in FAMILIES:
        m = family == fam
        ax2.scatter(emb[m, 0], emb[m, 1], s=5, c=FAMILY_COLORS[fam], alpha=0.6,
                    linewidths=0, label=fam)
    ax2.set_title("(b) By attack family", fontsize=13)
    ax2.legend(markerscale=3, loc="best", fontsize=8, framealpha=0.9)

    for ax in (ax1, ax2):
        ax.set_xlabel("t-SNE-1")
        ax.set_ylabel("t-SNE-2")
        ax.set_xticks([])
        ax.set_yticks([])

    fig.suptitle(
        "t-SNE of Tenko's 100-D AfterImage/KitNET input features (CICIoT2023)\n"
        + meta,
        fontsize=12,
    )
    fig.tight_layout(rect=[0, 0, 1, 0.94])
    fig.savefig(out_png, dpi=200)
    fig.savefig(out_pdf)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--n-benign", type=int, default=8000)
    ap.add_argument("--n-per-family", type=int, default=2500)
    ap.add_argument("--perplexity", type=float, default=40.0)
    ap.add_argument("--pca-dim", type=int, default=50)
    args = ap.parse_args()

    print(
        f"[cfg] seed={args.seed} n_benign={args.n_benign} "
        f"n_per_family={args.n_per_family} perplexity={args.perplexity} "
        f"pca_dim={args.pca_dim}"
    )
    X, label, family, src_index, source = build_dataset(
        args.n_benign, args.n_per_family, args.seed
    )
    print(f"[data] X={X.shape} benign={(label==0).sum()} attack={(label==1).sum()}")
    for fam, _c in FAMILIES:
        print(f"        {fam}: {(family==fam).sum()}")

    emb, pca_d, Xs = run_tsne(X, args.seed, args.perplexity, args.pca_dim)
    print(f"[tsne] embedding={emb.shape} (PCA pre-reduction dims={pca_d})")

    stats = separation_stats(emb, Xs, label, family, args.seed)
    print("[stats] family separation (embedding + high-D):")
    for r in stats:
        print(
            f"  {r['family']:>22} sil2d={r['silhouette_2d']:>7} "
            f"silHi={r['silhouette_hi']:>7} cdist={r['centroid_dist_norm']} "
            f"benignOverlap={r['benign_knn_overlap']}"
        )

    csv_path = os.path.join(DATA_DIR, "tsne_mixed.csv")
    stats_path = os.path.join(DATA_DIR, "tsne_separation_stats.csv")
    png_path = os.path.join(HERE, "tsne_mixed.png")
    pdf_path = os.path.join(HERE, "tsne_mixed.pdf")

    save_csv(csv_path, emb, label, family, src_index, source)
    save_stats_csv(stats_path, stats)
    meta = (
        f"seed={args.seed}, benign={int((label==0).sum())}, "
        f"attack/family={args.n_per_family}, perplexity={args.perplexity:g}, "
        f"PCA->{pca_d}D->t-SNE | per-packet detector-input space"
    )
    plot(emb, label, family, png_path, pdf_path, meta)

    print("[out]", csv_path)
    print("[out]", stats_path)
    print("[out]", png_path)
    print("[out]", pdf_path)


if __name__ == "__main__":
    main()
