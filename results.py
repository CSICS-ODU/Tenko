# from matplotlib import pyplot as plt
# from matplotlib import cm, colors
# import numpy as np
# from scipy.stats import norm, mode
# import pickle
# import pandas as pd
# import csv
# from tqdm import tqdm
# import pdb, traceback
# from tracker import nodeScore
# from sklearn.metrics import confusion_matrix
# from collections import deque

# ##############################################
# # Enhanced RMSE Pattern Recognizer (Distance) #
# ##############################################
# class RMSEPatternRecognizerDist:
#     """Pattern recognizer using Euclidean distance threshold instead of exact hashes."""
#     def __init__(self, window_size: int = 100, segments: int = 10, tol_factor: float = 1.1):
#         self.window_size = window_size
#         self.segments = segments
#         self.window = deque(maxlen=window_size)
#         self.training_vectors = []
#         self.tol = None
#         self.centroid = None
#         self.tol_factor = tol_factor

#     def update(self, value: float):
#         self.window.append(value)

#     def learn_current_pattern(self):
#         vec = self._current_vector()
#         if vec is not None:
#             self.training_vectors.append(vec)

#     def finalize_training(self):
#         if not self.training_vectors:
#             return
#         arr = np.stack(self.training_vectors, axis=0)
#         self.centroid = np.mean(arr, axis=0)
#         dists = np.linalg.norm(arr - self.centroid, axis=1)
#         self.tol = np.max(dists) * self.tol_factor

#     def is_known(self) -> bool:
#         vec = self._current_vector()
#         if vec is None or self.tol is None:
#             return True
#         dist = np.linalg.norm(vec - self.centroid)
#         return dist <= self.tol

#     def _current_vector(self):
#         if len(self.window) < self.window_size:
#             return None
#         seg_len = max(1, self.window_size // self.segments)
#         vec = np.array([
#             float(np.mean(list(self.window)[i*seg_len:(i+1)*seg_len]))
#             for i in range(self.segments)
#         ])
#         return vec

# #############################################
# # Existing utilities (unchanged)             #
# #############################################

# def load(filename='RMSEs_orig.pkl'):
#     try:
#         with open(filename, 'rb') as f:
#             RMSEs = pickle.load(f)
#     except FileNotFoundError:
#         print(filename + ' not found')
#         RMSEs = []
#     return RMSEs

# def build_IP_list(filename='mirai.pcap.tsv'):
#     num_lines = sum(1 for _ in open(filename)) - 1
#     tsvinfile = open(filename, 'rt', encoding="utf8")
#     tsvin = csv.reader(tsvinfile, delimiter='\t')
#     _ = next(tsvin)
#     IPsrc, IPdest = [], []
#     for _ in tqdm(range(num_lines)):
#         try:
#             row = next(tsvin)
#             srcIP = dstIP = ''
#             if row[4] != '':
#                 srcIP, dstIP = row[4], row[5]
#             elif row[17] != '':
#                 srcIP, dstIP = row[17], row[18]
#             IPsrc.append(srcIP)
#             IPdest.append(dstIP)
#         except Exception:
#             traceback.print_exc()
#             pdb.set_trace()
#     return IPsrc, IPdest

# def build_label_list(filename='OS_Scan_labels.csv'):
#     try:
#         CSV = pd.read_csv(filename)
#         LABELS = CSV['x'].tolist()
#     except FileNotFoundError:
#         print(filename + ' not found')
#         LABELS = []
#     return LABELS

# #######################################################
# # Core detection function using distance recognizer    #
# #######################################################

# def get_adversarial_IPs(
#     IPs,
#     IPd,
#     LABELS,
#     RMSEs,
#     interval=1000,
#     memorySize=50,
#     blockchainMode='offline',
#     saveFile='results.csv',
#     n_window=100000,
#     quantile=0.5,
#     rolling_window_size=500,
#     smoothing_factor=0.9,
#     pattern_window_size=100,
#     pattern_segments=10,
#     tol_factor=1.1
# ):

#     benignLimit = 100000
#     FMgrace, ADgrace = 5000, 50000

#     print(f"[DEBUG] Raw RMSEs type: {type(RMSEs)} | Length: {len(RMSEs)}")
#     if len(RMSEs) == 0:
#         raise ValueError("Loaded RMSEs list is empty.")

#     # Apply tanh normalization
#     RMSEs = np.tanh(RMSEs)
#     benignSample = RMSEs[FMgrace + ADgrace + 1:benignLimit]
#     train_max = np.max(benignSample) #np.mean you can do and then calcualte how it i,proves set static threshodl and see how it comapres
#     std = np.std(benignSample)
#     threshold = train_max + 3 * std
#     print('Initial threshold:', threshold)

#     node_score = nodeScore(memorySize, mode=blockchainMode)
#     scores = np.zeros((100, int((len(RMSEs) - benignLimit) / interval) + 1))
# #Old OG experiment
#     # gold = LABELS[benignLimit:]
#     # pred = []
#     # FPFNx, FPFNy = [], []
#     # rolling_window = []
# #New experiment
#     gold = LABELS[benignLimit:]
#     # 🆕 Predictions for the 4 experiments
#     pred_unknown   = []   # 1️⃣ unknown pattern only
#     pred_static    = []   # 2️⃣ score > static threshold
#     pred_combined  = []   # 3️⃣ unknown OR static
#     pred_dynamic   = []   # 4️⃣ score > dynamic threshold (your current baseline)
#     FPFNx, FPFNy = [], []
#     rolling_window = []

#     # 🆕 Compute STATIC threshold once, right here
#     static_threshold = train_max + 3 * std

#     # Use distance-based pattern recognizer
#     pattern_rec = RMSEPatternRecognizerDist(
#         window_size=pattern_window_size,
#         segments=pattern_segments,
#         tol_factor=tol_factor
#     )

#     # Training phase: collect patterns
#     for i in range(FMgrace + ADgrace + 1, benignLimit):
#         rmse = RMSEs[i]
#         node_score.update(IPs[i], i, rmse)
#         # compute node_score if needed but skip predictions
#         try:
#             score = node_score.scores[IPs[i]].get_score()
#         except:
#             score = rmse
#         pattern_rec.update(score)
#         pattern_rec.learn_current_pattern()
#     # finalize tolerance
#     pattern_rec.finalize_training()
#     print('Pattern tolerance set to:', pattern_rec.tol)

#     # Testing phase
#     for i in tqdm(range(benignLimit, len(RMSEs))):
#         rmse = RMSEs[i]
#         ip = IPs[i]

#         node_score.update(ip, i, rmse)
#         try:
#             score = node_score.scores[ip].get_score()
#         except:
#             score = rmse

#         rolling_window.append(score)
#         if len(rolling_window) > rolling_window_size:
#             rolling_window = rolling_window[-rolling_window_size:]
#         pattern_rec.update(score)

#         # dynamic threshold
#         if (i - benignLimit) % (interval * n_window) == 0 and rolling_window:
#             new_thr = np.quantile(rolling_window, quantile)
#             threshold = max(train_max + 3*std,
#                             smoothing_factor*threshold + (1-smoothing_factor)*new_thr)

#         # distance-based decision
#         # unknown_pattern = not pattern_rec.is_known()
#         # if score >= threshold or unknown_pattern: #Caclulate the metric if only compare by unknown pattern instead or score > threshold just check in unknon pattern, 
#         #     #compare this with just score>threshold 
#         #     #where you keep threshold where you keep threshold as men + 3*std dev., Dynamic omment out and threshold at the start that I have kept keep that
#         #     #unknown, static, score > threshold and unknown pattern, score > threshold or Unkwon pattern, consufion metricxs print.
#         #     flag = 1
#         # else:
#         #     flag = 0

#         # if LABELS[i] != flag:
#         #     if ip != '192.168.2.1':
#         #         FPFNx.append(i - benignLimit)
#         #         FPFNy.append(score)
#         # pred.append(flag)
# #New experiment
# # ---------- 4 parallel decision rules ----------
#         unknown_pattern      = not pattern_rec.is_known()
#         static_alarm         = score > static_threshold      # fixed thresh
#         dynamic_alarm        = score > threshold             # moving thresh

#         # 1️⃣ unknown only
#         pred_unknown.append(1 if unknown_pattern else 0)

#         # 2️⃣ static threshold only
#         pred_static.append(1 if static_alarm else 0)

#         # 3️⃣ unknown OR static threshold
#         pred_combined.append(1 if (unknown_pattern or static_alarm) else 0)

#         # 4️⃣ dynamic threshold (baseline)
#         pred_dynamic.append(1 if dynamic_alarm else 0)
#         # -----------------------------------------------

#         if i % 100000 == 0:
#             node_score.finalize()
#         if i % interval == 0:
#             j = int((i - benignLimit) / interval)
#             for k, key in enumerate(node_score.scores.keys()):
#                 if key == ip:
#                     scores[k, j] = score
#             scores[-1, j] = rmse

#     def show_confusion(title, y_true, y_pred):
#         cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
#         tn, fp, fn, tp = cm.ravel()
#         print(f"\\n—— {title} ——")
#         print(cm)
#         print(f"TPR {tp/(tp+fn):.4f}  FPR {fp/(fp+tn):.4f}  Precision {tp/(tp+fp):.4f}  F1 {2*tp/(2*tp+fp+fn):.4f}")

#     show_confusion("1️⃣ Unknown pattern only",        gold, pred_unknown)
#     show_confusion("2️⃣ Static threshold only",       gold, pred_static)
#     show_confusion("3️⃣ Unknown OR static",           gold, pred_combined)
#     show_confusion("4️⃣ Dynamic threshold (baseline)", gold, pred_dynamic)
#     return gold, pred_dynamic

#     # # visualize
#     # scores[scores == 0] = np.nan
#     # plt.axhline(y=threshold, color='g', ls='--', label='dynamic threshold')
#     # plt.axhline(y=train_max, color='r', ls='--', label='train max')
#     # plt.axvline(x=benignLimit/interval, color='k', ls='--', label='train/test split')
#     # plt.scatter(range(len(scores[-1,:])), scores[-1,:], s=1, marker='x', c='k', label='RMSE')
#     # for k, key in enumerate(node_score.scores.keys()):
#     #     plt.scatter(range(len(scores[k,:])), scores[k,:], s=1, marker='.', label=key)
#     # plt.scatter(FPFNx, FPFNy, s=3, c='r', marker='o', label='FP/FN')
#     # plt.title('Adjusted Anomaly & Pattern Scores')
#     # plt.ylabel('Scores')
#     # plt.xlabel('Time (interval units)')
#     # plt.legend(loc='upper right', fontsize='x-small')
#     # plt.show()

#     # return gold, pred

# ######################################################
# # Driver (example)                                    #
# ######################################################

# def main():
#     print('\x1bc')
#     RMSEs = load('RMSEs_OS_scan.pkl')
#     IPs, IPd = build_IP_list('OS_Scan_pcap.pcapng.tsv')
#     LABELS = build_label_list(filename='OS_Scan_labels.csv')
#     gold, pred = get_adversarial_IPs(
#         IPs,
#         IPd,
#         LABELS,
#         RMSEs,
#         interval=1,
#         memorySize=6,
#         blockchainMode='blocking',  # 'offline', 'blocking', 'parallel'
#         pattern_window_size=100,
#         pattern_segments=10,
#     )
#     CM = confusion_matrix(gold, pred, labels=[0, 1])
#     tn, fp, fn, tp = CM.ravel()
#     print('Confusion Matrix:\n', CM)
#     print('TN, FP, FN, TP ->', tn, fp, fn, tp)

# if __name__ == '__main__':
#     main()
from matplotlib import pyplot as plt
from matplotlib import cm, colors
import numpy as np
from scipy.stats import norm, mode
import pickle
import pandas as pd
import csv
from tqdm import tqdm
import pdb, traceback
from tracker import nodeScore
from sklearn.metrics import confusion_matrix
from collections import deque

##############################################
# Enhanced RMSE Pattern Recognizer (Distance) #
##############################################
class RMSEPatternRecognizerDist:
    """Pattern recognizer using Euclidean distance threshold instead of exact hashes."""
    def __init__(self, window_size: int = 100, segments: int = 10, tol_factor: float = 1.1):
        self.window_size = window_size
        self.segments = segments
        self.window = deque(maxlen=window_size)
        self.training_vectors = []
        self.tol = None
        self.centroid = None
        self.tol_factor = tol_factor

    def update(self, value: float):
        self.window.append(value)

    def learn_current_pattern(self):
        vec = self._current_vector()
        if vec is not None:
            self.training_vectors.append(vec)

    def finalize_training(self):
        if not self.training_vectors:
            return
        arr = np.stack(self.training_vectors, axis=0)
        self.centroid = np.mean(arr, axis=0)
        dists = np.linalg.norm(arr - self.centroid, axis=1)
        self.tol = np.max(dists) * self.tol_factor

    def is_known(self) -> bool:
        vec = self._current_vector()
        if vec is None or self.tol is None:
            return True
        dist = np.linalg.norm(vec - self.centroid)
        return dist <= self.tol

    def _current_vector(self):
        if len(self.window) < self.window_size:
            return None
        seg_len = max(1, self.window_size // self.segments)
        vec = np.array([
            float(np.mean(list(self.window)[i*seg_len:(i+1)*seg_len]))
            for i in range(self.segments)
        ])
        return vec

#############################################
# Existing utilities (unchanged)             #
#############################################

def load(filename='RMSEs_orig.pkl'):
    try:
        with open(filename, 'rb') as f:
            RMSEs = pickle.load(f)
    except FileNotFoundError:
        print(filename + ' not found')
        RMSEs = []
    return RMSEs

def build_IP_list(filename='mirai.pcap.tsv'):
    num_lines = sum(1 for _ in open(filename)) - 1
    tsvinfile = open(filename, 'rt', encoding="utf8")
    tsvin = csv.reader(tsvinfile, delimiter='\t')
    _ = next(tsvin)
    IPsrc, IPdest = [], []
    for _ in tqdm(range(num_lines)):
        try:
            row = next(tsvin)
            srcIP = dstIP = ''
            if row[4] != '':
                srcIP, dstIP = row[4], row[5]
            elif row[17] != '':
                srcIP, dstIP = row[17], row[18]
            IPsrc.append(srcIP)
            IPdest.append(dstIP)
        except Exception:
            traceback.print_exc()
            pdb.set_trace()
    return IPsrc, IPdest

def build_label_list(filename='OS_Scan_labels.csv'):
    try:
        CSV = pd.read_csv(filename)
        LABELS = CSV['x'].tolist()
    except FileNotFoundError:
        print(filename + ' not found')
        LABELS = []
    return LABELS

#######################################################
# Core detection function using distance recognizer    #
#######################################################

def get_adversarial_IPs(
    IPs,
    IPd,
    LABELS,
    RMSEs,
    interval=1000,
    memorySize=50,
    blockchainMode='offline',
    saveFile='results.csv',
    n_window=100000,
    quantile=0.5,
    rolling_window_size=500,
    smoothing_factor=0.9,
    pattern_window_size=100,
    pattern_segments=10,
    tol_factor=0.05
):

    benignLimit = 100000
    FMgrace, ADgrace = 5000, 50000

    print(f"[DEBUG] Raw RMSEs type: {type(RMSEs)} | Length: {len(RMSEs)}")
    if len(RMSEs) == 0:
        raise ValueError("Loaded RMSEs list is empty.")

    # Apply tanh normalization
    RMSEs = np.tanh(RMSEs)
    benignSample = RMSEs[FMgrace + ADgrace + 1:benignLimit]
    train_max = np.max(benignSample) #np.mean you can do and then calcualte how it i,proves set static threshodl and see how it comapres
    std = np.std(benignSample)
    threshold = train_max + 3 * std
    print('Initial threshold:', threshold)

    node_score = nodeScore(memorySize, mode=blockchainMode)
    scores = np.zeros((100, int((len(RMSEs) - benignLimit) / interval) + 1))
#Old OG experiment
    # gold = LABELS[benignLimit:]
    # pred = []
    # FPFNx, FPFNy = [], []
    # rolling_window = []
#New experiment
    gold = LABELS[benignLimit:]
    # 🆕 Predictions for the 4 experiments
    pred_unknown   = []   # 1️⃣ unknown pattern only
    pred_static    = []   # 2️⃣ score > static threshold
    pred_combined  = []   # 3️⃣ unknown OR static
    pred_dynamic   = []   # 4️⃣ score > dynamic threshold (your current baseline)
    FPFNx, FPFNy = [], []
    rolling_window = []

    # 🆕 Compute STATIC threshold once, right here
    static_threshold = train_max + 3 * std

    # Use distance-based pattern recognizer
    pattern_rec = RMSEPatternRecognizerDist(
        window_size=pattern_window_size,
        segments=pattern_segments,
        tol_factor=tol_factor
    )

    # Training phase: collect patterns
    for i in range(FMgrace + ADgrace + 1, benignLimit):
        rmse = RMSEs[i]
        node_score.update(IPs[i], i, rmse)
        # compute node_score if needed but skip predictions
        try:
            score = node_score.scores[IPs[i]].get_score()
        except:
            score = rmse
        pattern_rec.update(score)
        pattern_rec.learn_current_pattern()
    # finalize tolerance
    pattern_rec.finalize_training()
    print('Pattern tolerance set to:', pattern_rec.tol)

    # Testing phase
    for i in tqdm(range(benignLimit, len(RMSEs))):
        rmse = RMSEs[i]
        ip = IPs[i]

        node_score.update(ip, i, rmse)
        try:
            score = node_score.scores[ip].get_score()
        except:
            score = rmse

        rolling_window.append(score)
        if len(rolling_window) > rolling_window_size:
            rolling_window = rolling_window[-rolling_window_size:]
        pattern_rec.update(score)

        # dynamic threshold
        if (i - benignLimit) % (interval * n_window) == 0 and rolling_window:
            new_thr = np.quantile(rolling_window, quantile)
            threshold = max(train_max + 3*std,
                            smoothing_factor*threshold + (1-smoothing_factor)*new_thr)

        # distance-based decision
        # unknown_pattern = not pattern_rec.is_known()
        # if score >= threshold or unknown_pattern: #Caclulate the metric if only compare by unknown pattern instead or score > threshold just check in unknon pattern, 
        #     #compare this with just score>threshold 
        #     #where you keep threshold where you keep threshold as men + 3*std dev., Dynamic omment out and threshold at the start that I have kept keep that
        #     #unknown, static, score > threshold and unknown pattern, score > threshold or Unkwon pattern, consufion metricxs print.
        #     flag = 1
        # else:
        #     flag = 0

        # if LABELS[i] != flag:
        #     if ip != '192.168.2.1':
        #         FPFNx.append(i - benignLimit)
        #         FPFNy.append(score)
        # pred.append(flag)
#New experiment
# ---------- 4 parallel decision rules ----------
        unknown_pattern      = not pattern_rec.is_known()
        static_alarm         = score > static_threshold      # fixed thresh
        dynamic_alarm        = score > threshold             # moving thresh

        # 1️⃣ unknown only
        pred_unknown.append(1 if unknown_pattern else 0)

        # 2️⃣ static threshold only
        pred_static.append(1 if static_alarm else 0)

        # 3️⃣ unknown OR static threshold
        pred_combined.append(1 if (unknown_pattern or static_alarm) else 0)

        # 4️⃣ dynamic threshold (baseline)
        pred_dynamic.append(1 if dynamic_alarm else 0)
        # -----------------------------------------------

        if i % 100000 == 0:
            node_score.finalize()
        if i % interval == 0:
            j = int((i - benignLimit) / interval)
            for k, key in enumerate(node_score.scores.keys()):
                if key == ip:
                    scores[k, j] = score
            scores[-1, j] = rmse

    def show_confusion(title, y_true, y_pred):
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        print(f"\\n—— {title} ——")
        print(cm)
        print(f"TPR {tp/(tp+fn):.4f}  FPR {fp/(fp+tn):.4f}  Precision {tp/(tp+fp):.4f}  F1 {2*tp/(2*tp+fp+fn):.4f}")

    show_confusion("1️⃣ Unknown pattern only",        gold, pred_unknown)
    show_confusion("2️⃣ Static threshold only",       gold, pred_static)
    show_confusion("3️⃣ Unknown OR static",           gold, pred_combined)
    show_confusion("4️⃣ Dynamic threshold (baseline)", gold, pred_dynamic)
    return gold, pred_dynamic

    # # visualize
    # scores[scores == 0] = np.nan
    # plt.axhline(y=threshold, color='g', ls='--', label='dynamic threshold')
    # plt.axhline(y=train_max, color='r', ls='--', label='train max')
    # plt.axvline(x=benignLimit/interval, color='k', ls='--', label='train/test split')
    # plt.scatter(range(len(scores[-1,:])), scores[-1,:], s=1, marker='x', c='k', label='RMSE')
    # for k, key in enumerate(node_score.scores.keys()):
    #     plt.scatter(range(len(scores[k,:])), scores[k,:], s=1, marker='.', label=key)
    # plt.scatter(FPFNx, FPFNy, s=3, c='r', marker='o', label='FP/FN')
    # plt.title('Adjusted Anomaly & Pattern Scores')
    # plt.ylabel('Scores')
    # plt.xlabel('Time (interval units)')
    # plt.legend(loc='upper right', fontsize='x-small')
    # plt.show()

    # return gold, pred

######################################################
# Driver (example)                                    #
######################################################

def main():
    print('\x1bc')
    RMSEs = load('RMSEs_OS_scan.pkl')
    IPs, IPd = build_IP_list('OS_Scan_pcap.pcapng.tsv')
    LABELS = build_label_list(filename='OS_Scan_labels.csv')
    gold, pred = get_adversarial_IPs(
        IPs,
        IPd,
        LABELS,
        RMSEs,
        interval=1,
        memorySize=6,
        blockchainMode='blocking',  # 'offline', 'blocking', 'parallel'
        pattern_window_size=100,
        pattern_segments=10,
    )
    CM = confusion_matrix(gold, pred, labels=[0, 1])
    tn, fp, fn, tp = CM.ravel()
    print('Confusion Matrix:\n', CM)
    print('TN, FP, FN, TP ->', tn, fp, fn, tp)

if __name__ == '__main__':
	main()