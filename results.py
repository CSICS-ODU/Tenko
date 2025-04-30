from matplotlib import pyplot as plt
from matplotlib.colors import ListedColormap
import numpy as np
import pickle
import pandas as pd
import csv
from tqdm import tqdm
import pdb, traceback
from tracker import nodeScore
from sklearn.metrics import confusion_matrix
from collections import deque
from typing import Optional

##############################################
# Configuration for global‐centroid pooling  #
##############################################
NUM_ABC = 3  # number of first‐seen nodes whose centroids we average

##############################################
# Enhanced RMSE Pattern Recognizer (Distance) #
##############################################
class RMSEPatternRecognizerDist:
	"""Pattern recognizer using Euclidean distance threshold instead of exact hashes."""
	def __init__(self, node_id: str, window_size: int = 100, segments: int = 10, tol_factor: float = 1.1):
		self.node_id = node_id
		self.window_size = window_size
		self.segments = segments
		self.window = deque(maxlen=window_size)
		self.training_vectors: list[np.ndarray] = []
		self.tol: Optional[np.ndarray] = None
		self.centroid: Optional[np.ndarray] = None
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
		if vec is None or self.tol is None or self.centroid is None:
			return True
		dist = np.linalg.norm(vec - self.centroid)
		return dist <= self.tol


	def _current_vector(self) -> Optional[np.ndarray]:
		if len(self.window) < self.window_size:
			return None
		seg_len = max(1, self.window_size // self.segments)
		return np.array([
			float(np.mean(list(self.window)[i*seg_len:(i+1)*seg_len]))
			for i in range(self.segments)
		])

#############################################
# Data‐loading utilities                    #
#############################################

def load(filename: str = 'RMSEs_orig.pkl') -> list[float]:
	try:
		with open(filename, 'rb') as f:
			return pickle.load(f)
	except FileNotFoundError:
		print(f"[ERROR] {filename} not found")
		return []

def build_IP_list(filename: str = 'mirai.pcap.tsv') -> tuple[list[str], list[str]]:
	num_lines = sum(1 for _ in open(filename)) - 1
	with open(filename, 'rt', encoding='utf8') as tsvfile:
		reader = csv.reader(tsvfile, delimiter='\t')
		next(reader)
		IPsrc, IPdest = [], []
		for _ in tqdm(range(num_lines), desc="Reading IPs"):
			try:
				row = next(reader)
				if row[4]:
					src, dst = row[4], row[5]
				else:
					src, dst = row[17], row[18]
				IPsrc.append(src)
				IPdest.append(dst)
			except Exception:
				traceback.print_exc()
				pdb.set_trace()
		return IPsrc, IPdest

# def build_label_list(filename: str = "SSL_Renegotiation_labels.csv",
# 					 label_col: str = "x") -> list[int]:
# 	try:
# 		df = pd.read_csv(filename)
# 		if label_col not in df.columns:
# 			raise KeyError(f"Column '{label_col}' not in {filename}")
# 		labels = df[label_col].astype(int).tolist()
# 		print(f"[DATA] Loaded {len(labels)} labels from {filename}")
# 		return labels
# 	except Exception as e:
# 		print(f"[ERROR] build_label_list: {e}")
# 		return []
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
	IPs: list[str],
	IPd: list[str],
	LABELS: list[int],
	RMSEs: list[float],
	interval: int = 1000,
	memorySize: int = 50,
	blockchainMode: str = 'offline',
	n_window: int = 100000,
	quantile: float = 0.5,
	rolling_window_size: int = 500,
	smoothing_factor: float = 0.9,
	pattern_window_size: int = 100,
	pattern_segments: int = 10,
	tol_factor: float = 1.1
) -> tuple[list[int], list[int]]:

	benignLimit = 100000
	FMgrace, ADgrace = 5000, 50000

	if not RMSEs:
		raise ValueError("Empty RMSEs")

	# Normalize
	RMSEs = np.tanh(RMSEs)
	benignSample = RMSEs[FMgrace+ADgrace+1:benignLimit]
	train_max, std = np.max(benignSample), np.std(benignSample)
	threshold = train_max + 3*std
	print(f"[DEBUG] initial static threshold = {threshold:.4f}")

	# trackers & storage
	node_score = nodeScore(memorySize, mode=blockchainMode)
	pattern_recs: dict[str, RMSEPatternRecognizerDist] = {}
	abc_ids: list[str] = []     # first NUM_ABC distinct IPs
	scores = np.zeros((100, (len(RMSEs)-benignLimit)//interval + 1))

	# build ground truth
	gold = LABELS[benignLimit:]
	# gold = LABELS  # use full label list, no slicing

	pred_unknown = []; pred_static = []; pred_combined = []; pred_dynamic = []
	rolling_window: list[float] = []

	# ─── Training phase ─────────────────────────────────────────────
	for i in range(FMgrace+ADgrace+1, benignLimit):
		ip, rmse = IPs[i], RMSEs[i]
		# instantiate per-IP recognizer
		if ip not in pattern_recs:
			pattern_recs[ip] = RMSEPatternRecognizerDist(
				node_id=ip,
				window_size=pattern_window_size,
				segments=pattern_segments,
				tol_factor=tol_factor
			)
			# collect up to NUM_ABC for centroid averaging
			if len(abc_ids) < NUM_ABC:
				abc_ids.append(ip)

		# update nodeScore and get score
		node_score.update(ip, i, rmse)
		try:
			score = node_score.scores[ip].get_score()
		except KeyError:
			score = rmse

		# feed into that IP’s recognizer
		pr = pattern_recs[ip]
		pr.update(score)
		pr.learn_current_pattern()

	# finalize all training, but pool only the abc_ids
	centroid_pool: list[np.ndarray] = []
	for ip in abc_ids:
		pr = pattern_recs[ip]
		pr.finalize_training()
		if pr.centroid is not None:
			centroid_pool.append(pr.centroid)
	if not centroid_pool:
		raise RuntimeError("No centroids collected for averaging")
	global_centroid = np.mean(np.stack(centroid_pool, axis=0), axis=0)
	print(f"[INFO] global centroid from {len(centroid_pool)} nodes")

	# inject global centroid into every recognizer
	for pr in pattern_recs.values():
		pr.centroid = global_centroid.copy()

	# ─── Testing phase ────────────────────────────────────────────────
	static_threshold = train_max + 3*std
	for i in tqdm(range(benignLimit, len(RMSEs)), desc="Testing"):
		ip, rmse = IPs[i], RMSEs[i]

		# if new IP, create recognizer that inherits global centroid
		if ip not in pattern_recs:
			pattern_recs[ip] = RMSEPatternRecognizerDist(
				node_id=ip,
				window_size=pattern_window_size,
				segments=pattern_segments,
				tol_factor=tol_factor
			)
			pattern_recs[ip].centroid = global_centroid.copy()

		# update nodeScore & score
		node_score.update(ip, i, rmse)
		try:
			score = node_score.scores[ip].get_score()
		except KeyError:
			score = rmse

		# dynamic threshold window
		rolling_window.append(score)
		if len(rolling_window) > rolling_window_size:
			rolling_window = rolling_window[-rolling_window_size:]
		if (i - benignLimit) % (interval * n_window) == 0 and rolling_window:
			new_thr = np.quantile(rolling_window, quantile)
			threshold = max(train_max + 3*std,
							smoothing_factor*threshold + (1-smoothing_factor)*new_thr)

		# feed into recognizer
		pr = pattern_recs[ip]
		pr.update(score)

		# four decision rules
		u = not pr.is_known()
		s = score > static_threshold
		d = score > threshold
		pred_unknown.append(int(u))
		pred_static.append(int(s))
		pred_combined.append(int(u or s))
		pred_dynamic.append(int(d))

		# optionally record scores for plotting
		if i % interval == 0:
			j = (i - benignLimit)//interval
			for k, key in enumerate(node_score.scores):
				if key == ip:
					scores[k, j] = score
			scores[-1, j] = rmse

		if i % 100000 == 0:
			node_score.finalize()

	# ─── Reporting ────────────────────────────────────────────────────
	def show_confusion(name, y_true, y_pred):
		cm = confusion_matrix(y_true, y_pred, labels=[0,1])
		tn, fp, fn, tp = cm.ravel()
		print(f"\n—— {name} ——")
		print(cm)
		print(f"TPR {tp/(tp+fn):.4f}, FPR {fp/(fp+tn):.4f}, Precision {tp/(tp+fp):.4f}, F1 {2*tp/(2*tp+fp+fn):.4f}")

	show_confusion("1️⃣ Unknown pattern only",    gold, pred_unknown)
	show_confusion("2️⃣ Static threshold only",   gold, pred_static)
	show_confusion("3️⃣ Unknown OR static",       gold, pred_combined)
	show_confusion("4️⃣ Dynamic threshold (base)", gold, pred_dynamic)

	# ─── Visualization ───────────────────────────────────────────────
	scores[scores == 0] = np.nan
	plt.axhline(y=threshold, color='g', ls='--', label='dynamic thr')
	plt.axhline(y=static_threshold, color='r', ls='--', label='static thr')
	plt.axhline(y=np.mean(global_centroid), color='m', ls='--', label='global centroid')
	plt.axvline(x=benignLimit/interval, color='k', ls='--', label='train/test split')
	cmap = ListedColormap(['blue','orange'])
	plt.scatter(range(len(LABELS)), LABELS, s=1, c=LABELS, marker='*', cmap=cmap, label='labels')
	plt.title("Adjusted Anomaly & Pattern Scores")
	plt.ylabel("Score")
	plt.xlabel("Time (interval units)")
	plt.legend(loc='upper right', fontsize='x-small')
	plt.show()

	return gold, pred_dynamic


######################################################
# Driver (example)                                    #
######################################################
def main():
	print('\x1bc')
	RMSEs = load('RMSEs_OS_scan.pkl')
	IPs, IPd = build_IP_list('OS_Scan_pcap.pcapng.tsv')
	LABELS = build_label_list('SSL_Renegotiation_labels.csv')
	print(f"[DEBUG] Lengths — RMSEs: {len(RMSEs)}, IPs: {len(IPs)}, LABELS: {len(LABELS)}")
	print(f"[DEBUG] Label distribution:\n{pd.Series(LABELS).value_counts()}")
	assert len(LABELS) == len(RMSEs) == len(IPs), "[ERROR] Length mismatch between LABELS, RMSEs, or IPs"
	gold, pred = get_adversarial_IPs(
		IPs, IPd, LABELS, RMSEs,
		interval=1,
		memorySize=6,
		blockchainMode='blocking',
		pattern_window_size=100,
		pattern_segments=10,
		tol_factor=1.1
	)
	cm = confusion_matrix(gold, pred, labels=[0,1])
	tn, fp, fn, tp = cm.ravel()
	print('Final Confusion Matrix:\n', cm)
	print('TN, FP, FN, TP ->', tn, fp, fn, tp)

if __name__ == '__main__':
	main()
