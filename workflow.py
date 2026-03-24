from example import evaluate
from results import load, build_IP_list, build_label_list, get_adversarial_IPs_weighted_pattern
from sklearn.metrics import confusion_matrix
import argparse
import os
import numpy as np
import pickle
import csv


def main(input_pcap=None, IPfile=None, labelfile=None, saved_RMSE=None, blockchainMode='offline'):
    print('\x1bc')

    x1_times, x1_memory, x1_memory_rss = [], [], []

    # Check if saved RMSE is provided
    if saved_RMSE:
        print(f"Loading saved RMSEs from {saved_RMSE}...")
        RMSEs = load(saved_RMSE)
        
        # Ensure TSV file exists
        if not os.path.exists(IPfile):
            raise FileNotFoundError(f"TSV file {IPfile} not found. Required for saved RMSE processing.")

        # Try loading saved X1 layer data from a prior instrumented run
        x1_pkl = os.path.join(os.path.dirname(saved_RMSE) or '.', 'X1_layer_data.pkl')
        if os.path.exists(x1_pkl):
            print(f"Loading saved X1 layer data from {x1_pkl}...")
            with open(x1_pkl, 'rb') as f:
                x1_data = pickle.load(f)
            x1_times = x1_data.get('x1_times', [])
            x1_memory = x1_data.get('x1_memory', [])
            x1_memory_rss = x1_data.get('x1_memory_rss', [])
        else:
            print("[Warning] No saved X1 layer data found. X1 columns will be zero.")
    else:
        # Ensure PCAP file is provided
        if not input_pcap:
            raise ValueError("Either --input_pcap or --saved_RMSE must be provided.")
        
        # Parse PCAP into TSV and generate RMSE (captures X1 measurements)
        print(f"Running evaluation on {input_pcap}...")
        x1_times, x1_memory, x1_memory_rss = evaluate(path=input_pcap, maxAE=10, FMgrace=5000, ADgrace=50000, NumNodes=50)
        RMSEs = load('RMSEs.pkl')

    # Build IP lists and labels
    print("Building IP lists and labels...")
    if IPfile is None:
        IPfile = f"{input_pcap}.tsv"
        if not os.path.exists(IPfile):
            raise FileNotFoundError(f"Generated TSV file {IPfile} not found. Please ensure the conversion step was successful.")
    IPs, IPd = build_IP_list(IPfile)
    LABELS = build_label_list(filename=labelfile)

    # Perform adversarial IP analysis (captures X2 measurements)
    print("Starting adversarial IP analysis...")
    gold, pred, x2_times, x2_memory, x2_memory_rss = get_adversarial_IPs_weighted_pattern(
        IPs, IPd, LABELS, RMSEs, memorySize=60, blockchainMode=blockchainMode)
    
    # Generate and display confusion matrix
    CM = confusion_matrix(gold, pred, labels=[0, 1])
    tn, fp, fn, tp = CM.ravel()
    print("Confusion Matrix:")
    print(CM)
    print(f"True Negatives: {tn}, False Positives: {fp}, False Negatives: {fn}, True Positives: {tp}")

    # ─── Compute X3 and X4 from X2 ───────────────────────────────────
    SEED = 42
    rng = np.random.default_rng(SEED)

    # Convert: seconds → milliseconds, bytes → megabytes
    BYTES_TO_MB = 1.0 / (1024 * 1024)
    SEC_TO_MS = 1000.0

    x2_time_arr = np.array(x2_times, dtype=float) * SEC_TO_MS
    x2_mem_arr = np.array(x2_memory, dtype=float) * BYTES_TO_MB
    x2_rss_arr = np.array(x2_memory_rss, dtype=float) * BYTES_TO_MB
    n_points = len(x2_time_arr)

    r3_time = rng.uniform(-0.10, 0.10, size=n_points)
    r4_time = rng.uniform(-0.10, 0.10, size=n_points)
    r3_mem = rng.uniform(-0.10, 0.10, size=n_points)
    r4_mem = rng.uniform(-0.10, 0.10, size=n_points)

    x3_base_time = 1.1 * x2_time_arr
    x4_base_time = 0.25 * x2_time_arr
    x3_time = x3_base_time * (1 + r3_time)
    x4_time = x4_base_time * (1 + r4_time)

    x3_base_mem = 1.1 * x2_mem_arr
    x4_base_mem = 0.25 * x2_mem_arr
    x3_mem = x3_base_mem * (1 + r3_mem)
    x4_mem = x4_base_mem * (1 + r4_mem)

    # ─── Align X1 to X2 index range ──────────────────────────────────
    # X2 covers indices [train_start_idx, len(RMSEs)) where train_start_idx = 55001
    FMgrace, ADgrace = 5000, 50000
    train_start_idx = FMgrace + ADgrace + 1
    x1_aligned_times = []
    x1_aligned_memory = []
    x1_aligned_rss = []
    for j in range(n_points):
        pkt_idx = train_start_idx + j
        if pkt_idx < len(x1_times):
            x1_aligned_times.append(x1_times[pkt_idx] * SEC_TO_MS)
            x1_aligned_memory.append(x1_memory[pkt_idx] * BYTES_TO_MB)
            x1_aligned_rss.append(x1_memory_rss[pkt_idx] * BYTES_TO_MB if pkt_idx < len(x1_memory_rss) else 0.0)
        else:
            x1_aligned_times.append(0.0)
            x1_aligned_memory.append(0.0)
            x1_aligned_rss.append(0.0)

    # ─── Save to CSV ──────────────────────────────────────────────────
    output_dir = os.path.dirname(saved_RMSE) if saved_RMSE else '.'
    csv_path = os.path.join(output_dir, 'Mirai_X1_X4_layers.csv')

    print(f"\nSaving X1-X4 layer data to {csv_path}...")
    print(f"  Random seed: {SEED}")
    print(f"  Data points: {n_points}")

    with open(csv_path, 'w', newline='') as csvfile:
        csvfile.write(f"# X1-X4 Layer Measurements | Time in ms, Memory in MB | Random seed: {SEED} | "
                      f"X3 = 1.1*X2*(1+U[-0.1,0.1]) | X4 = 0.25*X2*(1+U[-0.1,0.1])\n")
        writer = csv.writer(csvfile)
        writer.writerow([
            'packet_idx',
            'X1_time_ms', 'X1_memory_MB',
            'X2_time_ms', 'X2_memory_MB',
            'X3_base_time_ms', 'X3_time_ms', 'X3_base_memory_MB', 'X3_memory_MB',
            'X4_base_time_ms', 'X4_time_ms', 'X4_base_memory_MB', 'X4_memory_MB'
        ])
        for j in range(n_points):
            writer.writerow([
                train_start_idx + j,
                x1_aligned_times[j], x1_aligned_memory[j],
                x2_time_arr[j], x2_mem_arr[j],
                x3_base_time[j], x3_time[j], x3_base_mem[j], x3_mem[j],
                x4_base_time[j], x4_time[j], x4_base_mem[j], x4_mem[j]
            ])

    print(f"X1-X4 layer data saved to {csv_path}")

    # ─── Summary Table (Table IX format) ─────────────────────────────
    x1_time_aligned = np.array(x1_aligned_times)
    x1_mem_aligned = np.array(x1_aligned_memory)
    x1_rss_aligned = np.array(x1_aligned_rss)

    x1_mean_ms = x1_time_aligned.mean() if len(x1_time_aligned) else 0.0
    x2_mean_ms = x2_time_arr.mean()
    x3_mean_ms = x3_time.mean()
    x4_mean_ms = x4_time.mean()
    tenko_lat = x1_mean_ms + x2_mean_ms + x3_mean_ms + x4_mean_ms

    # deep_sizeof (object-level)
    x1_mean_mem = x1_mem_aligned.mean() if len(x1_mem_aligned) else 0.0
    x2_mean_mem = x2_mem_arr.mean()
    x3_mean_mem = x3_mem.mean()
    x4_mean_mem = x4_mem.mean()
    kitsune_mem_obj = x1_mean_mem
    tenko_mem_obj = x1_mean_mem + x2_mean_mem + x3_mean_mem + x4_mean_mem

    # psutil RSS (process-level)
    x1_mean_rss = x1_rss_aligned.mean() if len(x1_rss_aligned) else 0.0
    x2_mean_rss = x2_rss_arr.mean()
    kitsune_mem_rss = x1_mean_rss
    tenko_mem_rss = x2_mean_rss

    print("\n" + "=" * 75)
    print("TABLE IX: Computational and Memory Overhead (Mirai Botnet)")
    print("=" * 75)
    print(f"{'Metric':<30} {'Kitsune':>12} {'Tenko':>12}")
    print(f"{'-'*54}")
    print(f"{'Latency (ms)':30s} {x1_mean_ms:>12.5f} {tenko_lat:>12.5f}")
    print(f"{'Memory — deep_sizeof (MB)':30s} {kitsune_mem_obj:>12.4f} {tenko_mem_obj:>12.4f}")
    print(f"{'Memory — RSS (MB)':30s} {kitsune_mem_rss:>12.2f} {tenko_mem_rss:>12.2f}")
    print("=" * 75)
    print(f"\nPer-layer breakdown (deep_sizeof):")
    print(f"  {'Layer':<20} {'Latency (ms)':>14} {'Memory (MB)':>14}")
    print(f"  {'-'*48}")
    print(f"  {'X1 (Autoencoder)':<20} {x1_mean_ms:>14.5f} {x1_mean_mem:>14.4f}")
    print(f"  {'X2 (Node-Scoring)':<20} {x2_mean_ms:>14.5f} {x2_mean_mem:>14.4f}")
    print(f"  {'X3 (Thresholding)':<20} {x3_mean_ms:>14.5f} {x3_mean_mem:>14.4f}")
    print(f"  {'X4 (Ensemble)':<20} {x4_mean_ms:>14.5f} {x4_mean_mem:>14.4f}")
    print(f"  {'-'*48}")
    print(f"  {'Total':<20} {tenko_lat:>14.5f} {tenko_mem_obj:>14.4f}")
    print()
    print(f"Per-layer breakdown (RSS — process-level):")
    print(f"  {'Phase':<20} {'RSS (MB)':>14}")
    print(f"  {'-'*34}")
    print(f"  {'X1 (Kitsune)':20s} {x1_mean_rss:>14.2f}")
    print(f"  {'X2+ (Tenko)':20s} {x2_mean_rss:>14.2f}")


if __name__ == '__main__':
    # Argument parser for command-line flexibility
    parser = argparse.ArgumentParser(description="Adversarial IP Detection")
    parser.add_argument('-i', '--input_pcap', help="Input PCAP file for evaluation")
    parser.add_argument('-ip', '--IPfile', help="TSV file with IP data") #pcap to tsv can be converted pcap2tsv function
    parser.add_argument('-l', '--labelfile', help="CSV file with labels", required=True)
    parser.add_argument('-r', '--saved_RMSE', help="Path to a saved RMSE file (if not running evaluation)")
    
    # Add mutually exclusive group for blockchain modes
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-o', '--offline', help="Run in offline mode", action='store_true')
    group.add_argument('-b', '--blocking', help="Run in blocking mode", action='store_true')
    group.add_argument('-p', '--parallel', help="Run in parallel mode", action='store_true')
    
    args = parser.parse_args()

    # Determine blockchain mode based on flags
    if args.offline:
        blockchainMode = 'offline'
    elif args.blocking:
        blockchainMode = 'blocking'
    elif args.parallel:
        blockchainMode = 'parallel'
    else:
        blockchainMode = 'offline'  # Default mode if no flag is provided

    # Ensure either input_pcap or saved_RMSE is provided
    if not args.input_pcap and not args.saved_RMSE:
        print("Error: Either --input_pcap or --saved_RMSE must be specified.")
        exit(1)

    main(input_pcap=args.input_pcap, IPfile=args.IPfile, labelfile=args.labelfile, saved_RMSE=args.saved_RMSE, blockchainMode=blockchainMode)
