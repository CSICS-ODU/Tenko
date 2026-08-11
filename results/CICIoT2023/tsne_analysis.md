# t-SNE of the CICIoT2023 feature space (Fig. 6 — deepened analysis)

This note accompanies **Fig. 6** and answers two reviewer requests:

- **Reviewer #7 (blocker B4):** the raw data and the exact script behind the
  figure are now committed (paths below), so the embedding is reproducible.
- **Reviewer #5:** the t-SNE discussion is deepened from a generic "attacks
  cluster" statement into a *measured*, streaming-aware interpretation.

## Artifacts

| Artifact | Path |
|---|---|
| Script (reproducible) | `results/CICIoT2023/figs/plot_tsne.py` |
| Figure | `results/CICIoT2023/figs/tsne_mixed.png` / `.pdf` |
| Raw embedding (raw data reviewers asked for) | `results/CICIoT2023/figs/data/tsne_mixed.csv` |
| Measured separation stats | `results/CICIoT2023/figs/data/tsne_separation_stats.csv` |

Reproduce (from repo root):

```bash
MPLBACKEND=Agg .venv/bin/python results/CICIoT2023/figs/plot_tsne.py
```

## What feature space is this? (honest caveat)

The points are the **100-dimensional AfterImage/Kitsune per-packet feature
vectors** produced by Tenko's own `FeatureExtractor`/`netStat`
(`results/CICIoT2023/baselines/extract_features.py`). This is the **exact input
that Tenko's KitNET consumes** — i.e. the detector's *input* feature space, at
per-packet granularity. Two honest caveats:

1. It is **not** a KitNET latent/reconstruction-error space, and it is **not**
   the **node-level aggregated** view Tenko forms internally. Those internal
   representations are not committed as feature matrices, so we visualize the
   committed detector-input space rather than invent features. The consequence
   of that aggregation for separability is discussed in §4.
2. **Family labels.** The mixed stream's committed labels are binary (0/1) with
   no per-row family id, and per-row family cannot be reliably recovered from
   `X_mixed` (exact-row matching against the per-family captures covered only
   ~150k/300k attack rows because of float de-duplication). We therefore take
   family identity from the per-family independent captures
   (`X_indep_<family>`, family = the attack in that capture) and combine them
   with the shared benign pool (the benign rows of `X_mixed`, which are
   byte-identical to the indep benign rows). This visualizes the same feature
   population that composes the mixed stream, with trustworthy family labels.

## Subsampling (fixed, documented)

`seed = 42`; **8,000 benign** (sampled from the 120k shared benign pool) and
**2,500 attack packets per family** (sampled from each family's 50k attack
packets), for **23,000 points** total. Pipeline: `StandardScaler` → `PCA→50D`
(denoise/speed) → `t-SNE(perplexity=40, init="pca", learning_rate="auto",
max_iter=1000, random_state=42)`. Scaler and PCA are fit on the subsample
itself. All counts and the seed are CLI-overridable and echoed at run time.

## Measured separation (this is what the plot *actually* shows)

Two silhouette scores are reported per family for a benign-vs-family split:
`silhouette_2d` on the plotted embedding and `silhouette_hi` on the standardized
100-D input. `centroid_dist_norm` is the benign→family centroid distance in the
embedding, normalized by the benign cloud's median radius (>1 ⇒ the family
centre sits outside the benign cloud). `benign_knn_overlap` is the fraction of a
family's points whose 10 nearest neighbours are *benign rather than same-family*
(0 = clean island, high = buried in benign).

| Family | Category | silhouette 2-D | silhouette 100-D | centroid dist (norm) | benign kNN overlap |
|---|---|--:|--:|--:|--:|
| DoS-SYN_Flood | volumetric flood | **0.473** | 0.544 | 2.34 | **0.006** |
| MITM-ArpSpoofing | spoofing / MITM | 0.371 | 0.512 | 1.90 | 0.055 |
| DDoS-UDP_Flood | volumetric flood | 0.369 | 0.239 | 1.80 | 0.029 |
| Mirai-greeth_flood | volumetric flood (botnet) | 0.305 | 0.444 | 1.64 | 0.029 |
| Recon-OSScan | reconnaissance | 0.109 | 0.143 | 0.48 | 0.184 |
| DictionaryBruteForce | brute force | **-0.027** | 0.077 | 0.19 | **0.370** |
| *(benign vs. any attack)* | — | 0.117 | 0.036 | — | — |

## Interpretation

### 1. Class separability is attack-dependent, not uniform
The three **volumetric floods (DoS-SYN, DDoS-UDP, Mirai)** and **MITM-ArpSpoofing**
form distinct islands well outside the benign cloud (centroid distances
1.6–2.3× the benign radius; benign-kNN overlap ≤ 5.5%). These attacks drive the
AfterImage rate/jitter/size channels far from their benign operating point, so
they are near-linearly separable even in the *input* space — consistent with the
near-ceiling detection Tenko reports for them. In sharp contrast,
**Recon-OSScan** (silhouette 0.11, 18% benign overlap) and especially
**DictionaryBruteForce** (silhouette ≈ 0, 37% benign overlap, centroid only
0.19× the benign radius) sit *inside* the benign manifold. This is the crucial,
non-generic point: the aggregate "benign vs. any attack" silhouette is only 0.12
(2-D) / 0.04 (100-D) precisely because these low-rate, benign-mimicking families
pull the global score down even though the floods are trivially separable.

### 2. Why the stealthy families overlap benign
Recon and dictionary brute-force are **low-and-slow**: they emit few packets at
near-benign rates and sizes, so their per-packet AfterImage statistics differ
from benign only in subtle, host-correlated ways (which destination, which port
sequence) that a single packet vector barely encodes. The t-SNE shows the direct
consequence — their points are interleaved with benign rather than segregated.
Per-packet thresholding on this space cannot cleanly cut them off without also
flagging benign traffic, which is exactly the regime where per-packet detectors
lose precision.

### 3. Concept drift and feature evolution over the stream
The benign region is not a single tight blob: it is a set of elongated,
fragmented filaments (visible in panel (a)). That geometry is the visual
signature of the **benign non-stationarity** we document elsewhere — as the
stream progresses, benign host/flow mixes shift, so the AfterImage decay-window
statistics *evolve* and benign traces out a moving, multi-modal region rather
than a fixed cluster. This matters for detection: a static per-packet boundary
calibrated on early benign will drift relative to later benign, and the stealthy
families (§2) live right on top of that moving region. It is the combination of
(a) benign drift and (b) benign-mimicking attacks that makes a fixed per-packet
rule brittle, and it motivates Tenko's design rather than a static threshold.

### 4. Why Tenko separates where per-packet fails
This figure is the *input* space, so it shows the problem Tenko is built to
solve, and it explains Tenko's mechanism concretely:

- **Node-level aggregation.** Tenko scores hosts/nodes by pooling many packets,
  not one packet at a time. Aggregation averages out the per-packet variance
  that makes Recon/Dict points overlap benign here: even a small, persistent
  per-packet shift (the 0.19–0.48× centroid offset above) accumulates into a
  reliably separable node-level signal, while benign per-packet noise cancels.
  A stealthy family that is invisible in one packet becomes visible once its
  packets are summed over a node.
- **Tolerance / hysteresis.** Because benign drifts (§3), Tenko does not commit
  on a single border-line packet; its tolerance band absorbs transient benign
  excursions and only escalates on *sustained* node-level deviation. This
  directly targets the overlap the embedding exposes: it suppresses the
  false positives a fixed per-packet cut would incur on the drifting benign
  filaments, while still catching the low-rate families once their evidence
  persists.

In short, the embedding is honest about the hard cases — floods are separable
even per-packet, but Recon and dictionary brute-force are not — and that
residual overlap is exactly what Tenko's node-level aggregation plus tolerance
converts into separable, drift-robust detections.

## Caveats (restated)

- Feature space is the **per-packet detector-input** representation, not Tenko's
  internal node-level/latent view; node-level separability is therefore expected
  to be **better** than what a per-packet t-SNE can show.
- Coordinates are a t-SNE embedding: **distances/densities are qualitative**;
  the silhouette / centroid / kNN statistics above are the quantitative claims.
- Family identity comes from the per-family captures (see §caveat 2), not from
  per-row mixed-stream labels. Subsampling is fixed (`seed=42`) and fully
  documented; re-running the script reproduces the CSV and figure.
