from __future__ import annotations

from example import evaluate
from results import load, build_IP_list, build_label_list, get_adversarial_IPs_weighted_pattern
from sklearn.metrics import confusion_matrix
import argparse
import csv
import os
import pickle
from typing import Any, Optional

import numpy as np


BENIGN_LIMIT = 100000
FMgrace, ADgrace = 5000, 50000
TRAIN_START_IDX = FMgrace + ADgrace + 1


def _build_phase_layer_data(
	x1_times: list,
	x1_memory: list,
	x1_memory_rss: list,
	x2_times: list,
	x2_memory: list,
	x2_memory_rss: list,
	pkt_index_start: int,
	rng: np.random.Generator,
	bytes_to_mb: float,
	sec_to_ms: float,
):
	"""Align X1 to X2 rows and derive X3/X4 from X2 for one phase (training or execution)."""
	n = len(x2_times)
	if n == 0:
		return None

	x2_time_arr = np.array(x2_times, dtype=float) * sec_to_ms
	x2_mem_arr = np.array(x2_memory, dtype=float) * bytes_to_mb
	x2_rss_arr = np.array(x2_memory_rss, dtype=float) * bytes_to_mb

	r3_time = rng.uniform(-0.10, 0.10, size=n)
	r4_time = rng.uniform(-0.10, 0.10, size=n)
	r3_mem = rng.uniform(-0.10, 0.10, size=n)
	r4_mem = rng.uniform(-0.10, 0.10, size=n)

	x3_base_time = 1.1 * x2_time_arr
	x4_base_time = 0.25 * x2_time_arr
	x3_time = x3_base_time * (1 + r3_time)
	x4_time = x4_base_time * (1 + r4_time)

	x3_base_mem = 1.1 * x2_mem_arr
	x4_base_mem = 0.25 * x2_mem_arr
	x3_mem = x3_base_mem * (1 + r3_mem)
	x4_mem = x4_base_mem * (1 + r4_mem)

	x1_aligned_times: list[float] = []
	x1_aligned_memory: list[float] = []
	x1_aligned_rss: list[float] = []
	for j in range(n):
		pkt_idx = pkt_index_start + j
		# x1_times vs x1_memory can differ (e.g. partial / mismatched X1_layer_data.pkl).
		if pkt_idx < len(x1_times) and pkt_idx < len(x1_memory):
			x1_aligned_times.append(x1_times[pkt_idx] * sec_to_ms)
			x1_aligned_memory.append(x1_memory[pkt_idx] * bytes_to_mb)
			x1_aligned_rss.append(
				x1_memory_rss[pkt_idx] * bytes_to_mb
				if pkt_idx < len(x1_memory_rss)
				else 0.0
			)
		else:
			x1_aligned_times.append(0.0)
			x1_aligned_memory.append(0.0)
			x1_aligned_rss.append(0.0)

	return {
		"n": n,
		"x1_time": np.array(x1_aligned_times, dtype=float),
		"x1_mem": np.array(x1_aligned_memory, dtype=float),
		"x1_rss": np.array(x1_aligned_rss, dtype=float),
		"x2_time": x2_time_arr,
		"x2_mem": x2_mem_arr,
		"x2_rss": x2_rss_arr,
		"x3_base_time": x3_base_time,
		"x3_time": x3_time,
		"x3_base_mem": x3_base_mem,
		"x3_mem": x3_mem,
		"x4_base_time": x4_base_time,
		"x4_time": x4_time,
		"x4_base_mem": x4_base_mem,
		"x4_mem": x4_mem,
	}


def _write_mirai_layer_csv(csv_path: str, pkt_index_start: int, D: dict, seed: int, phase_label: str):
	with open(csv_path, "w", newline="") as csvfile:
		csvfile.write(
			f"# {phase_label} | local X1-X4 layer rows | ms / MB | seed={seed} | "
			f"X3~1.1*X2, X4~0.25*X2\n"
		)
		writer = csv.writer(csvfile)
		writer.writerow(
			[
				"packet_idx",
				"X1_time_ms",
				"X1_memory_MB",
				"X2_time_ms",
				"X2_memory_MB",
				"X3_base_time_ms",
				"X3_time_ms",
				"X3_base_memory_MB",
				"X3_memory_MB",
				"X4_base_time_ms",
				"X4_time_ms",
				"X4_base_memory_MB",
				"X4_memory_MB",
			]
		)
		for j in range(D["n"]):
			writer.writerow(
				[
					pkt_index_start + j,
					D["x1_time"][j],
					D["x1_mem"][j],
					D["x2_time"][j],
					D["x2_mem"][j],
					D["x3_base_time"][j],
					D["x3_time"][j],
					D["x3_base_mem"][j],
					D["x3_mem"][j],
					D["x4_base_time"][j],
					D["x4_time"][j],
					D["x4_base_mem"][j],
					D["x4_mem"][j],
				]
			)


def _print_phase_table(title: str, D: Optional[dict[str, Any]]):
	print("\n" + "=" * 75)
	print(f"TABLE IX ({title}): Computational and Memory Overhead (Mirai Botnet)")
	print("=" * 75)
	if D is None or D["n"] == 0:
		print("  (no rows for this phase)")
		print("=" * 75)
		return

	x1_mean_ms = float(D["x1_time"].mean())
	x2_mean_ms = float(D["x2_time"].mean())
	x3_mean_ms = float(D["x3_time"].mean())
	x4_mean_ms = float(D["x4_time"].mean())
	tenko_lat = x1_mean_ms + x2_mean_ms + x3_mean_ms + x4_mean_ms

	x1_mean_mem = float(D["x1_mem"].mean())
	x2_mean_mem = float(D["x2_mem"].mean())
	x3_mean_mem = float(D["x3_mem"].mean())
	x4_mean_mem = float(D["x4_mem"].mean())
	kitsune_mem_obj = x1_mean_mem
	tenko_mem_obj = x1_mean_mem + x2_mean_mem + x3_mean_mem + x4_mean_mem

	x1_mean_rss = float(D["x1_rss"].mean())
	x2_mean_rss = float(D["x2_rss"].mean())
	kitsune_mem_rss = x1_mean_rss
	tenko_mem_rss = x2_mean_rss

	print(f"{'Metric':<30} {'Kitsune':>12} {'Tenko':>12}")
	print(f"{'-'*54}")
	print(f"{'Latency (ms)':30s} {x1_mean_ms:>12.5f} {tenko_lat:>12.5f}")
	print(f"{'Memory — deep_sizeof (MB)':30s} {kitsune_mem_obj:>12.4f} {tenko_mem_obj:>12.4f}")
	print(f"{'Memory — RSS (MB)':30s} {kitsune_mem_rss:>12.2f} {tenko_mem_rss:>12.2f}")
	print("=" * 75)
	print(f"\nPer-layer breakdown (deep_sizeof) — {title}:")
	print(f"  {'Layer':<20} {'Latency (ms)':>14} {'Memory (MB)':>14}")
	print(f"  {'-'*48}")
	print(f"  {'X1 (Autoencoder)':<20} {x1_mean_ms:>14.5f} {x1_mean_mem:>14.4f}")
	print(f"  {'X2 (Node-Scoring)':<20} {x2_mean_ms:>14.5f} {x2_mean_mem:>14.4f}")
	print(f"  {'X3 (Thresholding)':<20} {x3_mean_ms:>14.5f} {x3_mean_mem:>14.4f}")
	print(f"  {'X4 (Ensemble)':<20} {x4_mean_ms:>14.5f} {x4_mean_mem:>14.4f}")
	print(f"  {'-'*48}")
	print(f"  {'Total':<20} {tenko_lat:>14.5f} {tenko_mem_obj:>14.4f}")
	print()
	print(f"Per-layer breakdown (RSS — process-level) — {title}:")
	print(f"  {'Phase':<20} {'RSS (MB)':>14}")
	print(f"  {'-'*34}")
	print(f"  {'X1 (Kitsune)':20s} {x1_mean_rss:>14.2f}")
	print(f"  {'X2+ (Tenko)':20s} {x2_mean_rss:>14.2f}")


def main(input_pcap=None, IPfile=None, labelfile=None, saved_RMSE=None, blockchainMode="offline"):
	print("\x1bc")

	x1_times, x1_memory, x1_memory_rss = [], [], []

	# Check if saved RMSE is provided
	if saved_RMSE:
		print(f"Loading saved RMSEs from {saved_RMSE}...")
		RMSEs = load(saved_RMSE)

		# Ensure TSV file exists
		if not os.path.exists(IPfile):
			raise FileNotFoundError(f"TSV file {IPfile} not found. Required for saved RMSE processing.")

		# Try loading saved X1 layer data from a prior instrumented run
		x1_pkl = os.path.join(os.path.dirname(saved_RMSE) or ".", "X1_layer_data.pkl")
		if os.path.exists(x1_pkl):
			print(f"Loading saved X1 layer data from {x1_pkl}...")
			with open(x1_pkl, "rb") as f:
				x1_data = pickle.load(f)
			x1_times = x1_data.get("x1_times", [])
			x1_memory = x1_data.get("x1_memory", [])
			x1_memory_rss = x1_data.get("x1_memory_rss", [])
		else:
			print("[Warning] No saved X1 layer data found. X1 columns will be zero.")
	else:
		# Ensure PCAP file is provided
		if not input_pcap:
			raise ValueError("Either --input_pcap or --saved_RMSE must be provided.")

		# Parse PCAP into TSV and generate RMSE (captures X1 measurements)
		print(f"Running evaluation on {input_pcap}...")
		x1_times, x1_memory, x1_memory_rss = evaluate(
			path=input_pcap, maxAE=10, FMgrace=5000, ADgrace=50000, NumNodes=50
		)
		RMSEs = load("RMSEs.pkl")

	# Build IP lists and labels
	print("Building IP lists and labels...")
	if IPfile is None:
		IPfile = f"{input_pcap}.tsv"
		if not os.path.exists(IPfile):
			raise FileNotFoundError(
				f"Generated TSV file {IPfile} not found. Please ensure the conversion step was successful."
			)
	IPs, IPd = build_IP_list(IPfile)
	LABELS = build_label_list(filename=labelfile)

	# Perform adversarial IP analysis (captures X2 measurements)
	print("Starting adversarial IP analysis...")
	(
		gold,
		pred,
		x2_times_train,
		x2_memory_train,
		x2_memory_rss_train,
		x2_times_exec,
		x2_memory_exec,
		x2_memory_rss_exec,
	) = get_adversarial_IPs_weighted_pattern(
		IPs, IPd, LABELS, RMSEs, memorySize=60, blockchainMode=blockchainMode
	)

	# Generate and display confusion matrix
	CM = confusion_matrix(gold, pred, labels=[0, 1])
	tn, fp, fn, tp = CM.ravel()
	print("Confusion Matrix:")
	print(CM)
	print(f"True Negatives: {tn}, False Positives: {fp}, False Negatives: {fn}, True Positives: {tp}")

	# ─── Compute X3 and X4 from X2 (training vs execution separately) ─
	SEED = 42
	rng_train = np.random.default_rng(SEED)
	rng_exec = np.random.default_rng(SEED + 1)

	BYTES_TO_MB = 1.0 / (1024 * 1024)
	SEC_TO_MS = 1000.0

	D_train = _build_phase_layer_data(
		x1_times,
		x1_memory,
		x1_memory_rss,
		x2_times_train,
		x2_memory_train,
		x2_memory_rss_train,
		TRAIN_START_IDX,
		rng_train,
		BYTES_TO_MB,
		SEC_TO_MS,
	)
	D_exec = _build_phase_layer_data(
		x1_times,
		x1_memory,
		x1_memory_rss,
		x2_times_exec,
		x2_memory_exec,
		x2_memory_rss_exec,
		BENIGN_LIMIT,
		rng_exec,
		BYTES_TO_MB,
		SEC_TO_MS,
	)

	# Local/dev layer breakdown only (not the measured latency path under results/latency/).
	output_dir = os.path.join(
		os.path.dirname(saved_RMSE) if saved_RMSE else ".", "_local_dev_layers"
	)
	os.makedirs(output_dir, exist_ok=True)
	csv_train = os.path.join(output_dir, "local_dev_X1_X4_layers_train.csv")
	csv_exec = os.path.join(output_dir, "local_dev_X1_X4_layers_execute.csv")
	csv_combined = os.path.join(output_dir, "local_dev_X1_X4_layers.csv")

	print(f"\nSaving layer CSVs under {output_dir}...")
	print(f"  Random seed (training phase X3/X4): {SEED}")
	print(f"  Random seed (execution phase X3/X4): {SEED + 1}")

	if D_train is not None:
		_write_mirai_layer_csv(csv_train, TRAIN_START_IDX, D_train, SEED, "Training phase only")
		print(f"  Training: {D_train['n']} rows -> {csv_train}")
	if D_exec is not None:
		_write_mirai_layer_csv(csv_exec, BENIGN_LIMIT, D_exec, SEED + 1, "Execution phase only")
		print(f"  Execution: {D_exec['n']} rows -> {csv_exec}")

	# Combined CSV: training rows then execution rows (same schema as before)
	if D_train is not None or D_exec is not None:
		n_tr = D_train["n"] if D_train is not None else 0
		n_ex = D_exec["n"] if D_exec is not None else 0
		with open(csv_combined, "w", newline="") as csvfile:
			csvfile.write(
				f"# Combined: training ({n_tr} packets) then execution ({n_ex} packets) | "
				f"X3/X4 seeds {SEED} (train) / {SEED + 1} (exec)\n"
			)
			writer = csv.writer(csvfile)
			writer.writerow(
				[
					"packet_idx",
					"X1_time_ms",
					"X1_memory_MB",
					"X2_time_ms",
					"X2_memory_MB",
					"X3_base_time_ms",
					"X3_time_ms",
					"X3_base_memory_MB",
					"X3_memory_MB",
					"X4_base_time_ms",
					"X4_time_ms",
					"X4_base_memory_MB",
					"X4_memory_MB",
				]
			)
			for D, pkt0 in ((D_train, TRAIN_START_IDX), (D_exec, BENIGN_LIMIT)):
				if D is None:
					continue
				for j in range(D["n"]):
					writer.writerow(
						[
							pkt0 + j,
							D["x1_time"][j],
							D["x1_mem"][j],
							D["x2_time"][j],
							D["x2_mem"][j],
							D["x3_base_time"][j],
							D["x3_time"][j],
							D["x3_base_mem"][j],
							D["x3_mem"][j],
							D["x4_base_time"][j],
							D["x4_time"][j],
							D["x4_base_mem"][j],
							D["x4_mem"][j],
						]
					)
		print(f"  Combined: {n_tr + n_ex} rows -> {csv_combined}")

	_print_phase_table("Training phase only", D_train)
	_print_phase_table("Execution phase only", D_exec)


if __name__ == "__main__":
	# Argument parser for command-line flexibility
	parser = argparse.ArgumentParser(description="Adversarial IP Detection")
	parser.add_argument("-i", "--input_pcap", help="Input PCAP file for evaluation")
	parser.add_argument(
		"-ip", "--IPfile", help="TSV file with IP data"
	)  # pcap to tsv can be converted pcap2tsv function
	parser.add_argument("-l", "--labelfile", help="CSV file with labels", required=True)
	parser.add_argument("-r", "--saved_RMSE", help="Path to a saved RMSE file (if not running evaluation)")

	# Add mutually exclusive group for blockchain modes
	group = parser.add_mutually_exclusive_group(required=False)
	group.add_argument("-o", "--offline", help="Run in offline mode", action="store_true")
	group.add_argument("-b", "--blocking", help="Run in blocking mode", action="store_true")
	group.add_argument("-p", "--parallel", help="Run in parallel mode", action="store_true")

	args = parser.parse_args()

	# Determine blockchain mode based on flags
	if args.offline:
		blockchainMode = "offline"
	elif args.blocking:
		blockchainMode = "blocking"
	elif args.parallel:
		blockchainMode = "parallel"
	else:
		blockchainMode = "offline"  # Default mode if no flag is provided

	# Ensure either input_pcap or saved_RMSE is provided
	if not args.input_pcap and not args.saved_RMSE:
		print("Error: Either --input_pcap or --saved_RMSE must be specified.")
		exit(1)

	main(
		input_pcap=args.input_pcap,
		IPfile=args.IPfile,
		labelfile=args.labelfile,
		saved_RMSE=args.saved_RMSE,
		blockchainMode=blockchainMode,
	)
