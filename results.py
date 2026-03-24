# #New code
# from matplotlib import pyplot as plt
# from matplotlib.colors import ListedColormap
# import numpy as np
# import pickle
# import pandas as pd
# import csv
# from tqdm import tqdm
# import pdb, traceback
# from tracker import nodeScore
# from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, roc_curve, roc_auc_score
# from collections import deque
# from typing import Optional
# from matplotlib.colors import ListedColormap

# ##############################################
# # Enhanced RMSE Pattern Recognizer (Distance) #
# ##############################################
# class RMSEPatternRecognizerDist:
# 	"""Pattern recognizer using Euclidean distance threshold instead of exact hashes."""
# 	def __init__(self, node_id: str, window_size: int = 100, segments: int = 10, tol_factor: float = 1.1):
# 		self.node_id = node_id
# 		self.window_size = window_size
# 		self.segments = segments
# 		self.window = deque(maxlen=window_size)
# 		self.training_vectors: list[np.ndarray] = []
# 		self.tol: Optional[float] = None
# 		self.centroid: Optional[np.ndarray] = None
# 		self.tol_factor = tol_factor

# 	def update(self, value: float):
# 		self.window.append(value)

# 	def learn_current_pattern(self):
# 		vec = self._current_vector()
# 		if vec is not None:
# 			self.training_vectors.append(vec)

# 	def finalize_training(self):
# 		if not self.training_vectors:
# 			return
# 		arr = np.stack(self.training_vectors, axis=0)
# 		self.centroid = np.mean(arr, axis=0)
# 		dists = np.linalg.norm(arr - self.centroid, axis=1)
# 		print("The max distance is", np.max(dists))
# 		self.tol = np.max(dists) * self.tol_factor

# 	def is_known(self) -> bool:
# 		vec = self._current_vector()
# 		if vec is None or self.tol is None or self.centroid is None:
# 			return True
# 		return np.linalg.norm(vec - self.centroid) <= self.tol

# 	def _current_vector(self) -> Optional[np.ndarray]:
# 		if len(self.window) < self.window_size:
# 			return None
# 		seg_len = max(1, self.window_size // self.segments)
# 		return np.array([
# 			float(np.mean(list(self.window)[i*seg_len:(i+1)*seg_len]))
# 			for i in range(self.segments)
# 		])

# #############################################
# # Data‐loading utilities                    #
# #############################################

# def load(filename: str = 'RMSEs_orig.pkl') -> list[float]:
# 	try:
# 		with open(filename, 'rb') as f:
# 			return pickle.load(f)
# 	except FileNotFoundError:
# 		print(f"[ERROR] {filename} not found")
# 		return []

# def build_IP_list(filename: str = 'mirai.pcap.tsv') -> tuple[list[str], list[str]]:
# 	num_lines = sum(1 for _ in open(filename)) - 1
# 	with open(filename, 'rt', encoding='utf8') as tsvfile:
# 		reader = csv.reader(tsvfile, delimiter='\t')
# 		next(reader)
# 		IPsrc, IPdest = [], []
# 		for _ in tqdm(range(num_lines), desc="Reading IPs"):
# 			try:
# 				row = next(reader)
# 				if row[4]:
# 					src, dst = row[4], row[5]
# 				else:
# 					src, dst = row[17], row[18]
# 				IPsrc.append(src)
# 				IPdest.append(dst)
# 			except Exception:
# 				traceback.print_exc()
# 				pdb.set_trace()
# 		return IPsrc, IPdest

# def build_label_list(filename: str = 'SSL_Renegotiation_labels.csv', label_col: str = 'x') -> list[int]:
# 	try:
# 		df = pd.read_csv(filename)
# 		return df[label_col].astype(int).tolist()
# 	except Exception as e:
# 		print(f"[ERROR] build_label_list: {e}")
# 		return []

# #######################################################
# # Core detection function using distance recognizer    #
# #######################################################
# def get_adversarial_IPs(
# 	IPs: list[str],
# 	IPd: list[str],
# 	LABELS: list[int],
# 	RMSEs: list[float],
# 	interval: int = 1000,
# 	memorySize: int = 50,
# 	blockchainMode: str = 'offline',
# 	n_window: int = 10000,
# 	quantile: float = 0.5,
# 	rolling_window_size: int = 500,
# 	smoothing_factor: float = 0.9,
# 	pattern_window_size: int = 100,
# 	pattern_segments: int = 10,
# 	tol_factor: float = 5.0653
# ) -> tuple[list[int], list[int]]:
# 	benignLimit = 100000
# 	FMgrace, ADgrace = 5000, 50000

# 	# Normalize
# 	RMSEs = np.tanh(RMSEs)
# 	benignSample = RMSEs[FMgrace+ADgrace+1:benignLimit]
# 	train_max, std = np.max(benignSample), np.std(benignSample)
# 	threshold = train_max + 3*std
# 	print(f"[DEBUG] initial static threshold = {threshold:.4f}")

# 	# trackers & storage
# 	node_score = nodeScore(memorySize, mode=blockchainMode)
# 	pattern_recs: dict[str, RMSEPatternRecognizerDist] = {}

# 	# ─── Training phase ─────────────────────────────────
# 	for i in range(FMgrace+ADgrace+1, benignLimit):
# 		ip, rmse = IPs[i], RMSEs[i]
# 		if ip not in pattern_recs:
# 			pattern_recs[ip] = RMSEPatternRecognizerDist(ip, pattern_window_size, pattern_segments, tol_factor)
# 		node_score.update(ip, i, rmse)
# 		score = node_score.scores[ip].get_score() if ip in node_score.scores else rmse
# 		pr = pattern_recs[ip]
# 		pr.update(score)
# 		pr.learn_current_pattern()

# 	# ─── Finalize & pool centroids ─────────────────────
# 	centroid_pool = []
# 	tol_pool = []
# 	for ip, pr in pattern_recs.items():
# 		pr.finalize_training()
# 		print(f"{ip} → {len(pr.training_vectors)} vectors  tol={pr.tol}")
# 		# only keep those with a valid centroid & tol
# 		if pr.centroid is not None and pr.tol is not None:
# 			centroid_pool.append(pr.centroid)
# 			tol_pool.append(pr.tol)

# 	if not centroid_pool or not tol_pool:
# 		raise RuntimeError("No centroids collected for averaging")
# 	# compute global centroid _and_ a global tolerance
# 	global_centroid = np.mean(np.stack(centroid_pool, axis=0), axis=0)
# 	global_tol      = float(np.mean(tol_pool))
# 	print(f"[INFO] pooled {len(centroid_pool)} nodes → global centroid; global tol = {global_tol:.8f}")
# 	print(f"[GLOBAL] centroid = {global_centroid}")
# 	print(f"[GLOBAL] tol      = {global_tol}")
# 	# global_centroid = np.array([
# 	# 	0.05578797, 0.05579067, 0.05579001, 0.05579052, 0.05579144,
# 	# 	0.05579078, 0.05579264, 0.05579459, 0.05579328, 0.05579352
# 	# ], dtype=float)
	
# 	# overwrite every recognizer with the global values
# 	for pr in pattern_recs.values():
# 		pr.centroid = global_centroid.copy()
# 		pr.tol      = global_tol

# 	# Build fixed IP→row index map from training IPs only
# 	training_ips = list(pattern_recs.keys())
# 	ip_to_index = {ip: idx for idx, ip in enumerate(training_ips)}
# 	num_rows = len(training_ips) + 1    # +1 for raw RMSE row
# 	num_cols = (len(RMSEs) - benignLimit)//interval + 1
# 	scores = np.zeros((num_rows, num_cols))

# 	gold = LABELS[benignLimit:]
# 	pred_unknown = []; pred_static = []; pred_combined = []; pred_dynamic = []
# 	rolling_window: list[float] = []
# 	static_threshold = train_max + 3*std

# 	# ─── Testing phase ──────────────────────────────────
# 	for i in tqdm(range(benignLimit, len(RMSEs)), desc="Testing"):
# 		ip, rmse = IPs[i], RMSEs[i]
# 		if ip not in pattern_recs:
# 			# New IPs get a recognizer but we won't record their row in scores
# 			pattern_recs[ip] = RMSEPatternRecognizerDist(ip, pattern_window_size, pattern_segments, tol_factor)
# 			pattern_recs[ip].centroid = global_centroid.copy()

# 		node_score.update(ip, i, rmse)
# 		score = node_score.scores[ip].get_score() if ip in node_score.scores else rmse

# 		rolling_window.append(score)
# 		if len(rolling_window) > rolling_window_size:
# 			rolling_window = rolling_window[-rolling_window_size:]
# 		if (i - benignLimit) % (interval * n_window) == 0 and rolling_window:
# 			new_thr = np.quantile(rolling_window, quantile)
# 			threshold = max(train_max + 3*std,
# 							smoothing_factor*threshold + (1 - smoothing_factor)*new_thr)

# 		pr = pattern_recs[ip]
# 		pr.update(score)

# 		# Make predictions
# 		u = not pr.is_known()
# 		s = score > static_threshold
# 		d = score > threshold
# 		pred_unknown.append(int(u))
# 		pred_static.append(int(s))
# 		pred_combined.append(int(u or s))
# 		pred_dynamic.append(int(d))

# 		# Record into fixed-size scores matrix only if ip was in training
# 		if i % interval == 0:
# 			j = (i - benignLimit) // interval
# 			if ip in ip_to_index:
# 				k = ip_to_index[ip]
# 				scores[k, j]   = score
# 				scores[-1, j]  = rmse  # last row is raw RMSE

# 		if i % 100000 == 0:
# 			node_score.finalize()

# 	# ─── Reporting ───────────────────────────────────────
# # First, compute and store all four matrices
# 	cms = {}
# 	for name, y_pred in [
# 		("Unknown only",    pred_unknown),
# 		("Static only",     pred_static),
# 		("Unknown OR static", pred_combined),
# 		("Dynamic (base)",  pred_dynamic),
# 	]:
# 		cm = confusion_matrix(gold, y_pred, labels=[0,1])
# 		cms[name] = cm
# 		tn, fp, fn, tp = cm.ravel()
# 		print(f"\n—— {name} ——")
# 		print(cm)
# 		print(f"TPR {tp/(tp+fn):.4f}, FPR {fp/(fp+tn):.4f}, "
# 			f"Precision {tp/(tp+fp):.4f}, F1 {2*tp/(2*tp+fp+fn):.4f}")

# 	# Now plot them in a 2×2 figure
# 	fig, axes = plt.subplots(2, 2, figsize=(10, 8))
# 	axes = axes.flatten()

# 	for ax, (name, cm) in zip(axes, cms.items()):
# 		disp = ConfusionMatrixDisplay(confusion_matrix=cm,
# 									display_labels=["Benign", "Attack"])
# 		disp.plot(ax=ax, cmap=plt.cm.Blues, colorbar=False)
# 		ax.set_title(name)
# 		ax.grid(False)

# 	plt.tight_layout()
# 	plt.show()

# 	# show_confusion("Unknown pattern only", gold, pred_unknown)
# 	# show_confusion("Static threshold only", gold, pred_static)
# 	# show_confusion("Unknown OR static", gold, pred_combined)
# 	# show_confusion("Dynamic threshold (base)", gold, pred_dynamic)

# 	# ─── Visualization ──────────────────────────────────

# 	# … inside your visualization section …

# 	# 1. Choose a 2-color map: blue for benign, orange for attack
# 	cmap = ListedColormap(['white','orange'])

# 	# # 2. Plot RMSE *values* colored by LABELS
# 	plt.scatter(
# 		range(len(RMSEs)),
# 		RMSEs,
# 		s=0.8,
# 		c=LABELS,        # 0 or 1
# 		cmap=cmap,
# 		label='RMSE (white=benign, orange=attack)'
# 	)

# 	# 3. Overlay your thresholds & centroid
# 	plt.axhline(y=threshold,           color='g', ls='--', label='dynamic thr')
# 	plt.axhline(y=train_max,           color='r', ls='--', label='static thr')
# 	plt.axhline(y=np.mean(global_centroid), color='m', ls='--', label='global centroid')
# 	plt.axvline(x=benignLimit/interval, color='k', ls='--', label='train/test split')

# 	# 4. (Optional) still show per‐node adjusted scores if you like
# 	for ip, k in ip_to_index.items():
# 		plt.scatter(range(len(scores[k,:])), scores[k,:], s=1, marker='.', label=ip)

# 	# # 5. FP/FN overlay
# 	# if FPFNx:
# 	# 	plt.scatter(FPFNx, FPFNy, s=3, c='red', marker='x', label='FP/FN')

# 	plt.title("RMSE over Time (colored by true label)")
# 	plt.ylabel("Score (tanh(RMSE))")
# 	plt.xlabel("Time (interval units)")
# 	plt.legend(loc='upper right', fontsize='x-small')
# 	plt.tight_layout()
# 	plt.show()


# 	return gold, pred_dynamic

# ######################################################
# # Driver (example)                                    #
# ######################################################
# def main():
# 	print('\x1bc')
# 	RMSEs = load('RMSEs_OS_scan.pkl')
# 	IPs, IPd = build_IP_list('OS_Scan_pcap.pcapng.tsv')
# 	LABELS = build_label_list('SSL_Renegotiation_labels.csv')
# 	print(f"[DEBUG] Lengths — RMSEs: {len(RMSEs)}, IPs: {len(IPs)}, LABELS: {len(LABELS)}")
# 	print(f"[DEBUG] Label distribution:\n{pd.Series(LABELS).value_counts()}")
# 	assert len(LABELS) == len(RMSEs) == len(IPs), "[ERROR] Length mismatch"

# 	gold, pred = get_adversarial_IPs(
# 		IPs, IPd, LABELS, RMSEs,
# 		interval=100,
# 		memorySize=40,
# 		blockchainMode='blocking',
# 		pattern_window_size=30,
# 		pattern_segments=5,
# 		tol_factor=0.2
# 	)

# 	cm = confusion_matrix(gold, pred, labels=[0,1])
# 	tn, fp, fn, tp = cm.ravel()
# 	print('Final Confusion Matrix:\n', cm)
# 	print('TN, FP, FN, TP ->', tn, fp, fn, tp)

# if __name__ == '__main__':
# 	main()




# #Old CODE

# # from matplotlib import pyplot as plt
# # from matplotlib import cm, colors
# # import numpy as np
# # from scipy.stats import norm, mode
# # import pickle
# # import pandas as pd
# # import csv
# # from tqdm import tqdm
# # import pdb, traceback
# # from tracker import nodeScore
# # from sklearn.metrics import confusion_matrix
# # from collections import deque

# # ##############################################
# # # Enhanced RMSE Pattern Recognizer (Distance) #
# # ##############################################
# # class RMSEPatternRecognizerDist:
# #     """Pattern recognizer using Euclidean distance threshold instead of exact hashes."""
# #     def __init__(self, window_size: int = 100, segments: int = 10, tol_factor: float = 1.1):
# #         self.window_size = window_size
# #         self.segments = segments
# #         self.window = deque(maxlen=window_size)
# #         self.training_vectors = []
# #         self.tol = None
# #         self.centroid = None
# #         self.tol_factor = tol_factor

# #     def update(self, value: float):
# #         self.window.append(value)

# #     def learn_current_pattern(self):
# #         vec = self._current_vector()
# #         if vec is not None:
# #             self.training_vectors.append(vec)

# #     def finalize_training(self):
# #         if not self.training_vectors:
# #             return
# #         arr = np.stack(self.training_vectors, axis=0)
# #         self.centroid = np.mean(arr, axis=0)
# #         dists = np.linalg.norm(arr - self.centroid, axis=1)
# #         self.tol = np.max(dists) * self.tol_factor

# #     def is_known(self) -> bool:
# #         vec = self._current_vector()
# #         if vec is None or self.tol is None:
# #             return True
# #         dist = np.linalg.norm(vec - self.centroid)
# #         return dist <= self.tol

# #     def _current_vector(self):
# #         if len(self.window) < self.window_size:
# #             return None
# #         seg_len = max(1, self.window_size // self.segments)
# #         vec = np.array([
# #             float(np.mean(list(self.window)[i*seg_len:(i+1)*seg_len]))
# #             for i in range(self.segments)
# #         ])
# #         return vec

# # #############################################
# # # Existing utilities (unchanged)             #
# # #############################################

# # def load(filename='RMSEs_orig.pkl'):
# #     try:
# #         with open(filename, 'rb') as f:
# #             RMSEs = pickle.load(f)
# #     except FileNotFoundError:
# #         print(filename + ' not found')
# #         RMSEs = []
# #     return RMSEs

# # def build_IP_list(filename='mirai.pcap.tsv'):
# #     num_lines = sum(1 for _ in open(filename)) - 1
# #     tsvinfile = open(filename, 'rt', encoding="utf8")
# #     tsvin = csv.reader(tsvinfile, delimiter='\t')
# #     _ = next(tsvin)
# #     IPsrc, IPdest = [], []
# #     for _ in tqdm(range(num_lines)):
# #         try:
# #             row = next(tsvin)
# #             srcIP = dstIP = ''
# #             if row[4] != '':
# #                 srcIP, dstIP = row[4], row[5]
# #             elif row[17] != '':
# #                 srcIP, dstIP = row[17], row[18]
# #             IPsrc.append(srcIP)
# #             IPdest.append(dstIP)
# #         except Exception:
# #             traceback.print_exc()
# #             pdb.set_trace()
# #     return IPsrc, IPdest

# # def build_label_list(filename='OS_Scan_labels.csv'):
# #     try:
# #         CSV = pd.read_csv(filename)
# #         LABELS = CSV['x'].tolist()
# #     except FileNotFoundError:
# #         print(filename + ' not found')
# #         LABELS = []
# #     return LABELS

# # #######################################################
# # # Core detection function using distance recognizer    #
# # #######################################################

# # def get_adversarial_IPs(
# #     IPs,
# #     IPd,
# #     LABELS,
# #     RMSEs,
# #     interval=1000,
# #     memorySize=50,
# #     blockchainMode='offline',
# #     saveFile='results.csv',
# #     n_window=100000,
# #     quantile=0.5,
# #     rolling_window_size=500,
# #     smoothing_factor=0.9,
# #     pattern_window_size=100,
# #     pattern_segments=10,
# #     tol_factor=1.1
# # ):

# #     benignLimit = 100000
# #     FMgrace, ADgrace = 5000, 50000

# #     print(f"[DEBUG] Raw RMSEs type: {type(RMSEs)} | Length: {len(RMSEs)}")
# #     if len(RMSEs) == 0:
# #         raise ValueError("Loaded RMSEs list is empty.")

# #     # Apply tanh normalization
# #     RMSEs = np.tanh(RMSEs)
# #     benignSample = RMSEs[FMgrace + ADgrace + 1:benignLimit]
# #     train_max = np.max(benignSample) #np.mean you can do and then calcualte how it i,proves set static threshodl and see how it comapres
# #     std = np.std(benignSample)
# #     threshold = train_max + 3 * std
# #     print('Initial threshold:', threshold)

# #     node_score = nodeScore(memorySize, mode=blockchainMode)
# #     scores = np.zeros((100, int((len(RMSEs) - benignLimit) / interval) + 1))
# # #Old OG experiment
# #     # gold = LABELS[benignLimit:]
# #     # pred = []
# #     # FPFNx, FPFNy = [], []
# #     # rolling_window = []
# # #New experiment
# #     gold = LABELS[benignLimit:]
# #     # 🆕 Predictions for the 4 experiments
# #     pred_unknown   = []   # 1️⃣ unknown pattern only
# #     pred_static    = []   # 2️⃣ score > static threshold
# #     pred_combined  = []   # 3️⃣ unknown OR static
# #     pred_dynamic   = []   # 4️⃣ score > dynamic threshold (your current baseline)
# #     FPFNx, FPFNy = [], []
# #     rolling_window = []

# #     # 🆕 Compute STATIC threshold once, right here
# #     static_threshold = train_max + 3 * std

# #     # Use distance-based pattern recognizer
# #     pattern_rec = RMSEPatternRecognizerDist(
# #         window_size=pattern_window_size,
# #         segments=pattern_segments,
# #         tol_factor=tol_factor
# #     )

# #     # Training phase: collect patterns
# #     for i in range(FMgrace + ADgrace + 1, benignLimit):
# #         rmse = RMSEs[i]
# #         node_score.update(IPs[i], i, rmse)
# #         # compute node_score if needed but skip predictions
# #         try:
# #             score = node_score.scores[IPs[i]].get_score()
# #         except:
# #             score = rmse
# #         pattern_rec.update(score)
# #         pattern_rec.learn_current_pattern()
# #     # finalize tolerance
# #     pattern_rec.finalize_training()
# #     print("[OLD] one-node centroid =", pattern_rec.centroid)
# #     print("[OLD] one-node tol      =", pattern_rec.tol)

# #     print('Pattern tolerance set to:', pattern_rec.tol)

# #     # Testing phase
# #     for i in tqdm(range(benignLimit, len(RMSEs))):
# #         rmse = RMSEs[i]
# #         ip = IPs[i]

# #         node_score.update(ip, i, rmse)
# #         try:
# #             score = node_score.scores[ip].get_score()
# #         except:
# #             score = rmse

# #         rolling_window.append(score)
# #         if len(rolling_window) > rolling_window_size:
# #             rolling_window = rolling_window[-rolling_window_size:]
# #         pattern_rec.update(score)

# #         # dynamic threshold
# #         if (i - benignLimit) % (interval * n_window) == 0 and rolling_window:
# #             new_thr = np.quantile(rolling_window, quantile)
# #             threshold = max(train_max + 3*std,
# #                             smoothing_factor*threshold + (1-smoothing_factor)*new_thr)

# #         # distance-based decision
# #         # unknown_pattern = not pattern_rec.is_known()
# #         # if score >= threshold or unknown_pattern: #Caclulate the metric if only compare by unknown pattern instead or score > threshold just check in unknon pattern, 
# #         #     #compare this with just score>threshold 
# #         #     #where you keep threshold where you keep threshold as men + 3*std dev., Dynamic omment out and threshold at the start that I have kept keep that
# #         #     #unknown, static, score > threshold and unknown pattern, score > threshold or Unkwon pattern, consufion metricxs print.
# #         #     flag = 1
# #         # else:
# #         #     flag = 0

# #         # if LABELS[i] != flag:
# #         #     if ip != '192.168.2.1':
# #         #         FPFNx.append(i - benignLimit)
# #         #         FPFNy.append(score)
# #         # pred.append(flag)
# # #New experiment
# # # ---------- 4 parallel decision rules ----------
# #         unknown_pattern      = not pattern_rec.is_known()
# #         static_alarm         = score > static_threshold      # fixed thresh
# #         dynamic_alarm        = score > threshold             # moving thresh

# #         # 1️⃣ unknown only
# #         pred_unknown.append(1 if unknown_pattern else 0)

# #         # 2️⃣ static threshold only
# #         pred_static.append(1 if static_alarm else 0)

# #         # 3️⃣ unknown OR static threshold
# #         pred_combined.append(1 if (unknown_pattern or static_alarm) else 0)

# #         # 4️⃣ dynamic threshold (baseline)
# #         pred_dynamic.append(1 if dynamic_alarm else 0)
# #         # -----------------------------------------------

# #         if i % 100000 == 0:
# #             node_score.finalize()
# #         if i % interval == 0:
# #             j = int((i - benignLimit) / interval)
# #             for k, key in enumerate(node_score.scores.keys()):
# #                 if key == ip:
# #                     scores[k, j] = score
# #             scores[-1, j] = rmse

# #     def show_confusion(title, y_true, y_pred):
# #         cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
# #         tn, fp, fn, tp = cm.ravel()
# #         print(f"\\n—— {title} ——")
# #         print(cm)
# #         print(f"TPR {tp/(tp+fn):.4f}  FPR {fp/(fp+tn):.4f}  Precision {tp/(tp+fp):.4f}  F1 {2*tp/(2*tp+fp+fn):.4f}")

# #     show_confusion("1️⃣ Unknown pattern only",        gold, pred_unknown)
# #     show_confusion("2️⃣ Static threshold only",       gold, pred_static)
# #     show_confusion("3️⃣ Unknown OR static",           gold, pred_combined)
# #     show_confusion("4️⃣ Dynamic threshold (baseline)", gold, pred_dynamic)
# #     return gold, pred_dynamic

# #     # # visualize
# #     # scores[scores == 0] = np.nan
# #     # plt.axhline(y=threshold, color='g', ls='--', label='dynamic threshold')
# #     # plt.axhline(y=train_max, color='r', ls='--', label='train max')
# #     # plt.axvline(x=benignLimit/interval, color='k', ls='--', label='train/test split')
# #     # plt.scatter(range(len(scores[-1,:])), scores[-1,:], s=1, marker='x', c='k', label='RMSE')
# #     # for k, key in enumerate(node_score.scores.keys()):
# #     #     plt.scatter(range(len(scores[k,:])), scores[k,:], s=1, marker='.', label=key)
# #     # plt.scatter(FPFNx, FPFNy, s=3, c='r', marker='o', label='FP/FN')
# #     # plt.title('Adjusted Anomaly & Pattern Scores')
# #     # plt.ylabel('Scores')
# #     # plt.xlabel('Time (interval units)')
# #     # plt.legend(loc='upper right', fontsize='x-small')
# #     # plt.show()

# #     # return gold, pred

# # ######################################################
# # # Driver (example)                                    #
# # ######################################################

# # def main():
# #     print('\x1bc')
# #     RMSEs = load('RMSEs_OS_scan.pkl')
# #     IPs, IPd = build_IP_list('OS_Scan_pcap.pcapng.tsv')
# #     LABELS = build_label_list(filename='OS_Scan_labels.csv')
# #     gold, pred = get_adversarial_IPs(
# #         IPs,
# #         IPd,
# #         LABELS,
# #         RMSEs,
# #         interval=1,
# #         memorySize=6,
# #         blockchainMode='blocking',  # 'offline', 'blocking', 'parallel'
# #         pattern_window_size=100,
# #         pattern_segments=10,
# #     )
# #     CM = confusion_matrix(gold, pred, labels=[0, 1])
# #     tn, fp, fn, tp = CM.ravel()
# #     print('Confusion Matrix:\n', CM)
# #     print('TN, FP, FN, TP ->', tn, fp, fn, tp)

# # if __name__ == '__main__':
# #     main()

# Consolidated Code focusing ONLY on Centroid-Based Pattern Recognition Methods

# Consolidated Code with Weighted Average Ensemble for Pattern Methods

from matplotlib import pyplot as plt
from matplotlib.colors import ListedColormap
import numpy as np
import pickle
import pandas as pd
import csv
import time
from tqdm import tqdm
from memutil import deep_sizeof
import pdb, traceback
from tracker import nodeScore
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
from sklearn.metrics import roc_curve, auc
from collections import deque
from typing import Optional, Tuple, List, Dict

##############################################
# Enhanced RMSE Pattern Recognizer (Distance) #
# (Unchanged class definition)               #
##############################################
class RMSEPatternRecognizerDist:
	"""Pattern recognizer using Euclidean distance threshold instead of exact hashes."""
	def __init__(self, node_id: str, window_size: int = 100, segments: int = 10, tol_factor: float = 1.1):
		self.node_id = node_id
		self.window_size = window_size
		self.segments = segments
		self.window = deque(maxlen=window_size)
		self.training_vectors: list[np.ndarray] = []
		self.tol: Optional[float] = None
		self.centroid: Optional[np.ndarray] = None
		self.pattern_tol_factor = tol_factor # Renamed from tol_factor

	def update(self, value: float):
		self.window.append(value)

	def learn_current_pattern(self):
		vec = self._current_vector()
		if vec is not None:
			self.training_vectors.append(vec)

	def finalize_training(self):
		if not self.training_vectors:
			self.centroid = None; self.tol = None; return
		try:
			arr = np.stack(self.training_vectors, axis=0)
			self.centroid = np.mean(arr, axis=0)
			if arr.shape[0] > 1:
				dists = np.linalg.norm(arr - self.centroid, axis=1)
				self.tol = np.max(dists) * self.pattern_tol_factor if len(dists) > 0 else 0.0
			else: self.tol = 0.0
		except Exception as e: print(f"[ERROR] Rec {self.node_id}: Finalize failed: {e}"); self.centroid=None; self.tol=None

	def is_known(self) -> bool:
		if self.tol is None or self.centroid is None: return True
		vec = self._current_vector()
		if vec is None: return True
		try:
			dist = np.linalg.norm(vec - self.centroid)
			return dist <= self.tol
		except Exception as e: print(f"[ERROR] Rec {self.node_id}: is_known failed: {e}"); return True

	def _current_vector(self) -> Optional[np.ndarray]:
		if self.window_size <= 0 or self.segments <= 0: return None
		if len(self.window) < self.window_size: return None
		effective_segments = min(self.segments, self.window_size)
		seg_len = max(1, self.window_size // effective_segments)
		vec_list = [float(np.mean(list(self.window)[i*seg_len:min((i+1)*seg_len, self.window_size)]))
					for i in range(effective_segments)
					if list(self.window)[i*seg_len:min((i+1)*seg_len, self.window_size)]] # Ensure segment not empty
		return np.array(vec_list) if vec_list else None

#############################################
# Data‐loading utilities (Unchanged)       #
#############################################
def load(filename: str = 'RMSEs_orig.pkl') -> list[float]:
	try:
		with open(filename, 'rb') as f: data = pickle.load(f)
		if isinstance(data, np.ndarray): data = data.tolist()
		if not isinstance(data, list) or not all(isinstance(x, (int, float)) for x in data): raise ValueError("Loaded data type error.")
		return [float(x) for x in data]
	except FileNotFoundError: print(f"[ERROR] {filename} not found"); return []
	except Exception as e: print(f"[ERROR] Loading {filename} failed: {e}"); return []

def build_IP_list(filename: str = 'mirai.pcap.tsv') -> tuple[list[str], list[str]]:
	IPsrc, IPdest = [], []
	try:
		with open(filename, 'rt', encoding='utf8') as f: num_lines = sum(1 for line in f if line.strip()) - 1
		if num_lines <= 0: print(f"[Warning] TSV {filename} empty/header only."); return [], []
		with open(filename, 'rt', encoding='utf8') as tsvfile:
			reader = csv.reader(tsvfile, delimiter='\t'); next(reader)
			for row in tqdm(reader, total=num_lines, desc="Reading IPs"):
				src, dst = '', ''
				if len(row) > 5 and row[4] and row[5]: src, dst = row[4], row[5]
				elif len(row) > 18 and row[17] and row[18]: src, dst = row[17], row[18]
				IPsrc.append(src); IPdest.append(dst)
	except FileNotFoundError: print(f"[ERROR] TSV {filename} not found."); return [], []
	except Exception as e: print(f"[ERROR] Failed reading TSV {filename}: {e}"); traceback.print_exc(); return [], []
	return IPsrc, IPdest

def build_label_list(filename: str = 'SSL_Renegotiation_labels.csv', label_col: str = 'x') -> list[int]:
	try:
		df = pd.read_csv(filename); labels = df[label_col].astype(int).tolist()
		# if not all(l in [0, 1] for l in labels): print(f"[Warning] Labels non-binary.") # Optional check
		return labels
	except FileNotFoundError: print(f"[ERROR] Label file {filename} not found."); return []
	except Exception as e: print(f"[ERROR] Failed reading labels from {filename}: {e}"); return []

####################################################################
# Core detection function using WEIGHTED CENTROID-BASED PATTERNS   #
####################################################################
def get_adversarial_IPs_weighted_pattern(
	IPs: list[str],
	IPd: list[str],
	LABELS: list[int],
	RMSEs: list[float],
	memorySize: int = 3,
	blockchainMode: str = 'offline',
	pattern_window_size: int = 100,
	pattern_segments: int = 10,
	# --- Pattern Model Params ---
	global_pool_tol_factor: float = 50,
	single_agg_tol_factor: float = 20,
	# --- Weighted Ensemble Params ---
	weight_global: float = 0.5,       # Weight for the global pooled model's prediction
	weight_single: float = 0.5,       # Weight for the single aggregate model's prediction
	ensemble_threshold: float = 0.5   # Threshold for the final weighted prediction
) -> tuple[list[int], list[int]]:

	benignLimit = 100000
	FMgrace, ADgrace = 5000, 50000

	# --- Input Validation ---
	if len(RMSEs) <= benignLimit: raise ValueError("Not enough RMSE data.")
	if len(IPs) != len(RMSEs) or len(LABELS) != len(RMSEs): raise ValueError("Length mismatch.")
	if weight_global < 0 or weight_single < 0: print("[Warning] Ensemble weights should be non-negative.")
	# Optional: Check if weights sum to 1? Not strictly required but common.
	# if not np.isclose(weight_global + weight_single, 1.0):
	#     print("[Warning] Ensemble weights do not sum to 1. Threshold interpretation might differ.")

	print("--- Weighted Centroid-Based Pattern Recognition Mode ---")
	print(f"Parameters: win={pattern_window_size}, seg={pattern_segments}, global_tf={global_pool_tol_factor}, single_tf={single_agg_tol_factor}")
	print(f"Ensemble Params: w_global={weight_global}, w_single={weight_single}, threshold={ensemble_threshold}")

	# --- Normalization ---
	RMSEs_norm = np.tanh(np.array(RMSEs, dtype=float))
	train_start_idx = FMgrace + ADgrace + 1
	if train_start_idx >= benignLimit: raise ValueError("Invalid training indices.")

	# --- Initialize ---
	node_score = nodeScore(memorySize, mode=blockchainMode)
	per_ip_recognizers: Dict[str, RMSEPatternRecognizerDist] = {}
	single_aggregate_recognizer = RMSEPatternRecognizerDist(
		"SINGLE_AGGREGATE", pattern_window_size, pattern_segments, single_agg_tol_factor)

	x2_times: List[float] = []
	x2_memory: List[int] = []
	_last_x2_mem = 0

	# ─── Training Phase ───────────────────
	print("Starting Training Phase...")
	for i in tqdm(range(train_start_idx, benignLimit), desc="Training Pattern Models"):
		ip, rmse_norm = IPs[i], RMSEs_norm[i]
		_t0 = time.perf_counter()

		node_score.update(ip, i, rmse_norm)
		try: score = node_score.scores[ip].get_score()
		except KeyError: score = rmse_norm

		# Train Global Model's sources
		if ip not in per_ip_recognizers:
			per_ip_recognizers[ip] = RMSEPatternRecognizerDist(ip, pattern_window_size, pattern_segments, global_pool_tol_factor)
		per_ip_recognizers[ip].update(score); per_ip_recognizers[ip].learn_current_pattern()
		# Train Single Model
		single_aggregate_recognizer.update(score); single_aggregate_recognizer.learn_current_pattern()

		_t1 = time.perf_counter()
		x2_times.append(_t1 - _t0)
		if (i - train_start_idx) % 1000 == 0:
			_last_x2_mem = deep_sizeof(node_score) + deep_sizeof(per_ip_recognizers) + deep_sizeof(single_aggregate_recognizer)
		x2_memory.append(_last_x2_mem)

	# ─── Finalize Recognizers ──────────────────────────────────────────
	print("Finalizing Recognizers...")
	# 1. Finalize & Pool for Global Model
	valid_centroids, valid_tolerances = [], []
	for ip, pr in per_ip_recognizers.items():
		pr.finalize_training()
		if pr.centroid is not None and pr.tol is not None:
			if not valid_centroids or pr.centroid.shape == valid_centroids[0].shape:
				valid_centroids.append(pr.centroid); valid_tolerances.append(pr.tol)
	global_centroid, global_tol = None, None
	if valid_centroids:
		try:
			global_centroid = np.mean(np.stack(valid_centroids, axis=0), axis=0)
			global_tol = float(np.mean(valid_tolerances)) # Use average tolerance from contributors
			print(f"Global Pooled Model: Ready (Centroid {global_centroid.shape}, Tol {global_tol:.6f})")
		except Exception as e: print(f"[ERROR] Failed computing global model: {e}")
	else: print("[Warning] Global Pooled model disabled.")
	# 2. Finalize Single Aggregate Model
	single_aggregate_recognizer.finalize_training()
	if single_aggregate_recognizer.centroid is not None: print(f"Single Aggregate Model: Ready (Centroid {single_aggregate_recognizer.centroid.shape}, Tol {single_aggregate_recognizer.tol:.6f})")
	else: print("[Warning] Single aggregate model failed finalize.")

	# ─── Testing Phase ─────────────────────────────────────────────────
	print("Starting Testing Phase (Weighted Patterns)...")
	gold = LABELS[benignLimit:]
	pred_unknown_global = []
	pred_unknown_single = []
	pred_weighted = [] # Store results of weighted ensemble
	pred_scores = []    # Store the raw combined_score for ROC


	if len(RMSEs_norm) <= benignLimit: print("[ERROR] No data points for testing."); return gold, []

	for i in tqdm(range(benignLimit, len(RMSEs_norm)), desc="Testing Weighted Patterns"):
		ip, rmse_norm = IPs[i], RMSEs_norm[i]
		_t0 = time.perf_counter()

		node_score.update(ip, i, rmse_norm)
		try: score = node_score.scores[ip].get_score()
		except KeyError: score = rmse_norm

		# --- Get Individual Pattern Predictions ---
		# 1. Global Pooled Prediction
		unknown_global_flag = False
		if global_centroid is not None and global_tol is not None:
			if ip not in per_ip_recognizers: # Handle new IPs
				per_ip_recognizers[ip] = RMSEPatternRecognizerDist(ip, pattern_window_size, pattern_segments, global_pool_tol_factor)
				per_ip_recognizers[ip].centroid = global_centroid; per_ip_recognizers[ip].tol = global_tol
			else: # Ensure existing uses global params
				per_ip_recognizers[ip].centroid = global_centroid; per_ip_recognizers[ip].tol = global_tol
			current_pr = per_ip_recognizers[ip]; current_pr.update(score)
			if current_pr.centroid is not None and current_pr.tol is not None:
				unknown_global_flag = not current_pr.is_known()
		pred_unknown_global.append(int(unknown_global_flag))
		# 2. Single Aggregate Prediction
		unknown_single_flag = False
		if single_aggregate_recognizer.centroid is not None and single_aggregate_recognizer.tol is not None:
			single_aggregate_recognizer.update(score)
			unknown_single_flag = not single_aggregate_recognizer.is_known()
		pred_unknown_single.append(int(unknown_single_flag))

		# --- Calculate Weighted Ensemble Prediction ---
		combined_score = (weight_global * unknown_global_flag) + (weight_single * unknown_single_flag)
		pred_scores.append(combined_score)
		weighted_pred = 1 if combined_score >= ensemble_threshold else 0
		pred_weighted.append(weighted_pred)

		_t1 = time.perf_counter()
		x2_times.append(_t1 - _t0)
		if (i - benignLimit) % 1000 == 0:
			_last_x2_mem = deep_sizeof(node_score) + deep_sizeof(per_ip_recognizers) + deep_sizeof(single_aggregate_recognizer)
		x2_memory.append(_last_x2_mem)

		# Periodic finalization (if required by tracker)
		if (i - benignLimit + 1) % 100000 == 0:
			if hasattr(node_score, 'finalize') and callable(node_score.finalize): node_score.finalize()

	# ─── Reporting ─────────────────────────────────────────────────────
	print("\n--- Evaluation Results ---")
	results = {}

	def evaluate_and_print(name: str, y_true: list[int], y_pred: list[int]):
		# (Evaluation function remains the same)
		if not y_true or not y_pred or len(y_true) != len(y_pred): print(f"\n—— {name} ——\nSkipping eval."); results[name]=None; return
		try:
			cm=confusion_matrix(y_true, y_pred, labels=[0, 1]); tn, fp, fn, tp=cm.ravel()
			tpr=tp/(tp+fn) if (tp+fn)>0 else 0.0; fpr=fp/(fp+tn) if (fp+tn)>0 else 0.0
			precision=tp/(tp+fp) if (tp+fp)>0 else 0.0; f1=2*tp/(2*tp+fp+fn) if (2*tp+fp+fn)>0 else 0.0
			print(f"\n—— {name} ——")
			print(cm); print(f"TN={tn}, FP={fp}, FN={fn}, TP={tp}")
			print(f"TPR {tpr:.4f}, FPR {fpr:.4f}, Precision {precision:.4f}, F1 {f1:.4f}")
			results[name] = {'cm':cm, 'tpr':tpr, 'fpr':fpr, 'precision':precision, 'f1':f1}
		except Exception as e: print(f"\n—— {name} ——\nEval error: {e}"); results[name]=None

	# Evaluate individual components and the weighted ensemble
	evaluate_and_print("Unknown Pattern (Global Pooled)", gold, pred_unknown_global)
	evaluate_and_print("Unknown Pattern (Single Aggregate)", gold, pred_unknown_single)
	ensemble_name = f"Weighted Pattern Ensemble (wg={weight_global}, ws={weight_single}, T={ensemble_threshold})"
	evaluate_and_print(ensemble_name, gold, pred_weighted)

	# ─── Full ROC Analysis ─────────────────────────────────────────────
	print("\n--- Full ROC Curve Analysis ---")
	# gold: list of 0/1 labels, pred_scores: continuous anomaly scores
	fpr_arr, tpr_arr, thresholds = roc_curve(gold, pred_scores)
	roc_auc = auc(fpr_arr, tpr_arr)
	fnr_arr = 1 - tpr_arr
	eer_idx = np.nanargmin(np.abs(fpr_arr - fnr_arr))
	eer = fpr_arr[eer_idx]
	print(f"AUC = {roc_auc:.4f}, EER = {eer:.4f} (threshold ≈ {thresholds[eer_idx]:.4f})")

	# Optional: plot ROC
	plt.figure()
	plt.plot(fpr_arr, tpr_arr, lw=2, label=f"ROC (AUC = {roc_auc:.2f})")
	plt.plot([0,1],[0,1], linestyle='--', color='gray')
	plt.scatter(fpr_arr[eer_idx], tpr_arr[eer_idx], color='red',
				label=f"EER = {eer:.2f}")
	plt.xlabel("False Positive Rate")
	plt.ylabel("True Positive Rate")
	plt.title("ROC Curve for Weighted Ensemble")
	plt.legend(loc="lower right")
	plt.grid(True)
	plt.show()


	# --- Return Value ---
	# Return the result of the weighted ensemble by default
	final_pred_to_return = pred_weighted
	print(f"\nReturning '{ensemble_name}' as the final prediction.")

	# --- Optional Visualization (Simplified) ---
	# (Visualization code remains largely the same, update title if used)
	plot_results = False # Set to True to enable plotting
	if plot_results and gold and final_pred_to_return:
		try:
			print("Generating Plots...")
			cm_final = confusion_matrix(gold, final_pred_to_return, labels=[0,1])
			fig_cm, ax_cm = plt.subplots(1, 1, figsize=(5, 4))
			disp = ConfusionMatrixDisplay(confusion_matrix=cm_final, display_labels=["Benign", "Attack"])
			disp.plot(ax=ax_cm, cmap=plt.cm.Blues, colorbar=False); ax_cm.set_title(f"CM ({ensemble_name})")
			plt.tight_layout(); plt.show()
			# (Time series plot code omitted for brevity, but would use 'ensemble_name' in title)
		except Exception as e: print(f"[ERROR] Visualization failed: {e}")

	print(f"X2 layer data collected: {len(x2_times)} measurements")
	return gold, final_pred_to_return, x2_times, x2_memory

######################################################
# Driver (Updated Example for Weighted Patterns)     #
######################################################
def main():
	print('\x1bc') # Clear screen

	# --- Configuration ---
	pcap_file = 'OS_Scan_pcap.pcapng'; tsv_file = 'OS_Scan_pcap.pcapng.tsv'
	label_file = 'OS_Scan_labels.csv'; rmse_file = 'RMSEs_OS_scan.pkl'
	label_column = 'x'

	# --- Load Data ---
	print(f"Loading data: RMSEs='{rmse_file}', TSV='{tsv_file}', Labels='{label_file}'")
	RMSEs = load(rmse_file); IPs, IPd = build_IP_list(tsv_file); LABELS = build_label_list(label_file, label_col=label_column)
	if not RMSEs or not IPs or not LABELS: print("[FATAL] Failed loading data."); return
	print(f"Data Lengths — RMSEs: {len(RMSEs)}, IPs: {len(IPs)}, Labels: {len(LABELS)}")
	if not (len(RMSEs) == len(IPs) == len(LABELS)): print("[FATAL] Data length mismatch."); return
	print(f"Label distribution:\n{pd.Series(LABELS).value_counts(normalize=True)}")

	# --- Run Weighted Pattern Detection ---
	# ** NOTE: Choose weights and threshold based on validation results **
	# Using defaults (equal weight, 0.5 threshold) is equivalent to OR ensemble
	# Using weights favouring 'single' based on previous results:
	w_g = 0.3
	w_s = 0.7
	ens_T = 0.5 # Threshold still at 0.5, meaning if single fires (0.7*1=0.7), prediction is 1.

	gold, pred_weighted, _, _, _ = get_adversarial_IPs_weighted_pattern(
		IPs=IPs, IPd=IPd, LABELS=LABELS, RMSEs=RMSEs,
		memorySize=40, blockchainMode='blocking',
		pattern_window_size=30, pattern_segments=5,
		global_pool_tol_factor=50, # From previous 'new' main call
		single_agg_tol_factor=20,  # From previous 'old' default/main call
		# --- Ensemble Params to Tune ---
		weight_global=w_g,
		weight_single=w_s,
		ensemble_threshold=ens_T
	)

	# --- Final Evaluation ---
	if gold and pred_weighted:
		print("\n--- Final Confusion Matrix (Returned Weighted Prediction) ---")
		final_cm = confusion_matrix(gold, pred_weighted, labels=[0, 1])
		tn, fp, fn, tp = final_cm.ravel()
		print(final_cm); print(f"TN={tn}, FP={fp}, FN={fn}, TP={tp}")
		tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
		fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
		print(f"Final TPR (Weighted): {tpr:.4f}"); print(f"Final FPR (Weighted): {fpr:.4f}")
	else: print("Evaluation skipped.")

if __name__ == '__main__':
	main()