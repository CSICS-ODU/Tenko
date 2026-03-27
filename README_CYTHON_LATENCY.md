# Cython latency measurement (quick start for Sahil)

This branch adds a **compiled fast path** for the KitNET denoising autoencoder (`dA`) forward pass and a **Mirai benchmark** script. Use this doc in Cursor: paste it into chat or `@README_CYTHON_LATENCY.md` so the agent follows the same steps.

## What you are measuring

| Label | Meaning in `measure_all_latency.py` |
|--------|-------------------------------------|
| **X1** | Autoencoder (`KitNET.execute`) — **measured** |
| **X2** | Node scoring (`tracker.nodeScore`) — **measured** |
| **X3** | Threshold layer — **estimated** from X2 (≈ `1.10 × X2`, with small random jitter) |
| **X4** | Ensemble — **estimated** from X2 (≈ `0.25 × X2`) |
| **Kitsune** | X1 only |
| **Tenko** | X1 + X2 + X3 + X4 |

So **Tenko latency** is mostly **X1**; X3/X4 are not separate timed kernels.

## One-time setup

1. **Checkout this branch** (name may vary; use the branch your teammate pushed):

   ```bash
   git fetch origin
   git checkout cython-latency-measurement
   ```

2. **Python environment** (from repo root):

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

   You need **Cython**, **NumPy**, **tqdm**, **psutil**, **scapy** (for `FeatureExtractor`), and a working **setuptools** for extension builds.

3. **Build the Cython extensions** (required after clone or when `.pyx` changes; `.so` files are not committed):

   ```bash
   python setup_cython.py build_ext --inplace
   ```

4. **Sanity check** — should print a float without error:

   ```bash
   python -c "from fastpath.da_fast import da_execute_rmse; print('da_fast OK')"
   ```

## Dataset

The benchmark expects Mirai features here (adjust path in `measure_all_latency.py` if needed):

- `dataset/Mirai/Mirai_pcap.pcap.tsv`

If the file is missing, the script will fail when loading features. Obtain or generate the TSV per your project’s data pipeline.

## Run the latency benchmark

From repo root, with venv active and extensions built:

```bash
python measure_all_latency.py --max-load-packets 120000 --max-test-packets 8000 --skip-mateen
```

- **`--skip-mateen`** skips the PyTorch Mateen path (faster, fewer deps for a pure Kitsune/Tenko comparison).
- Tune **`--max-load-packets`** / **`--max-test-packets`** for shorter runs during debugging.

**Outputs:**

- Console table: **Kitsune** vs **Tenko** mean latency (ms), memory, layer breakdown.
- **`mirai_performance_results/real_latency_arrays_seed42.npz`** — raw per-packet arrays for plotting or diffing runs.

## Compare Cython vs NumPy baseline (A/B)

Default uses Cython when `fastpath.da_fast` imports successfully.

Force the **original NumPy** `dA.execute` path:

```bash
KITNET_DISABLE_CYTHON_DA=1 python measure_all_latency.py --max-load-packets 120000 --max-test-packets 8000 --skip-mateen
```

Compare **X1 mean latency** between the two runs to see AE speedup (expect on the order of a few× on CPU, not 100×, unless the rest of the stack changes).

## Environment variables (reference)

| Variable | Effect |
|----------|--------|
| `KITNET_DISABLE_CYTHON_DA=1` | Disable Cython AE; use NumPy `dA` |
| `KITNET_USE_TORCH=1` | Use PyTorch `KitNET.autoencoder` instead of `dA` (not what we optimize for this benchmark) |

## Files to know

| Path | Role |
|------|------|
| `fastpath/da_fast.pyx` | Cython AE forward + RMSE |
| `fastpath/score_fast.pyx` | Extra scalar helpers (optional / future wiring) |
| `setup_cython.py` | Build script |
| `KitNET/dA.py` | Calls `da_execute_rmse` when Cython is enabled |
| `KitNET/KitNET.py` | Selects `dA` vs torch via `KITNET_USE_TORCH` |
| `tracker.py` | `nodeScore(..., thread_safe=...)` — benchmarks use `thread_safe=False` in `measure_all_latency.py` |
| `measure_all_latency.py` | End-to-end Mirai timing harness |
| `memutil.py` | Includes `aggregate_deep_sizeof` used when Mateen paths are measured |

## Troubleshooting

- **`ImportError: No module named 'fastpath.da_fast'`** — Run `python setup_cython.py build_ext --inplace` from repo root; confirm you are in the same Python as `which python`.
- **`AssertionError: n must be in range [0, 1]!`** in node scoring — the harness clips RMSE to `[0, 1]` before `node_score.update`; use an up-to-date `measure_all_latency.py` from this branch.
- **Very slow first run** — Training + calibration dominate; the reported **X1/X2** numbers are from the **inference** loop only.

## Using this in Cursor

1. Open the repo folder in Cursor.
2. In chat, attach **`README_CYTHON_LATENCY.md`** (`@README_CYTHON_LATENCY.md`) or paste the “Build” + “Run” sections.
3. Ask the agent to run the build and benchmark and paste the **TABLE X** and X1/X2 lines from the log.

---

*Branch: `cython-latency-measurement` — Cython fastpath + latency harness + this README.*
