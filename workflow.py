from example import evaluate
from results import load, build_IP_list, build_label_list, get_adversarial_IPs
from sklearn.metrics import confusion_matrix
import argparse
import os


def main(input_pcap=None, IPfile=None, labelfile=None, saved_RMSE=None, blockchainMode='offline'):
    print('\x1bc')

    # Check if saved RMSE is provided
    if saved_RMSE:
        print(f"Loading saved RMSEs from {saved_RMSE}...")
        RMSEs = load(saved_RMSE)
        
        # Ensure TSV file exists
        if not os.path.exists(IPfile):
            raise FileNotFoundError(f"TSV file {IPfile} not found. Required for saved RMSE processing.")
    else:
        # Ensure PCAP file is provided
        if not input_pcap:
            raise ValueError("Either --input_pcap or --saved_RMSE must be provided.")
        
        # Parse PCAP into TSV and generate RMSE
        print(f"Running evaluation on {input_pcap}...")
        evaluate(path=input_pcap, maxAE=10, FMgrace=5000, ADgrace=50000, NumNodes=50)
        RMSEs = load('RMSEs.pkl')  # Default output from evaluate

    # Build IP lists and labels
    print("Building IP lists and labels...")
    IPs, IPd = build_IP_list(IPfile)
    LABELS = build_label_list(filename=labelfile)

    # Perform adversarial IP analysis
    print("Starting adversarial IP analysis...")
    gold, pred = get_adversarial_IPs(IPs, IPd, LABELS, RMSEs, interval=1, memorySize=3, blockchainMode=blockchainMode)
    
    # Generate and display confusion matrix
    CM = confusion_matrix(gold, pred, labels=[0, 1])
    tn, fp, fn, tp = CM.ravel()
    print("Confusion Matrix:")
    print(CM)
    print(f"True Negatives: {tn}, False Positives: {fp}, False Negatives: {fn}, True Positives: {tp}")


if __name__ == '__main__':
    # Argument parser for command-line flexibility
    parser = argparse.ArgumentParser(description="Adversarial IP Detection")
    parser.add_argument('-i', '--input_pcap', help="Input PCAP file for evaluation", required=True)
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
