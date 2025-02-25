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

def load(filename='RMSEs_orig.pkl'):
	try:
		f = open(filename,'rb')
		RMSEs = pickle.load(f)
		f.close()
	except FileNotFoundError as e:
		print(filename+' not found')
		RMSEs = []
	return RMSEs

def build_IP_list(filename='mirai.pcap.tsv'):

	num_lines = sum(1 for line in open(filename))-1

	# print(num_lines)

	tsvinfile = open(filename, 'rt', encoding="utf8")
	tsvin = csv.reader(tsvinfile, delimiter='\t')
	row = tsvin.__next__() #move iterator past header
	IPsrc = []
	IPdest = []
	for row_id in tqdm(range(num_lines)):
		# print(IPsrc,row_id)
		try:
			row = tsvin.__next__()
			IPtype = np.nan
			timestamp = row[0]
			framelen = row[1]
			srcIP = ''
			dstIP = ''
			if row[4] != '':  # IPv4
				srcIP = row[4]
				dstIP = row[5]
				IPtype = 0
			elif row[17] != '':  # ipv6
				srcIP = row[17]
				dstIP = row[18]
				IPtype = 1
			srcproto = row[6] + row[8]  # UDP or TCP port: the concatenation of the two port strings will will results in an OR "[tcp|udp]"
			dstproto = row[7] + row[9]  # UDP or TCP port
			srcMAC = row[2]
			dstMAC = row[3]
			if srcproto == '':  # it's a L2/L1 level protocol
				if row[12] != '':  # is ARP
					srcproto = 'arp'
					dstproto = 'arp'
					srcIP = row[14]  # src IP (ARP)
					dstIP = row[16]  # dst IP (ARP)
					IPtype = 0
				elif row[10] != '':  # is ICMP
					srcproto = 'icmp'
					dstproto = 'icmp'
					IPtype = 0
				elif srcIP + srcproto + dstIP + dstproto == '':  # some other protocol
					srcIP = row[2]  # src MAC
					dstIP = row[3]  # dst MAC

				# save # IPtype, srcMAC, dstMAC, srcIP, srcproto, dstIP, dstproto, int(framelen), float(timestamp)
			IPsrc.append(srcIP)
			IPdest.append(dstIP)

			# print(IPsrc,row_id)

			assert len(IPsrc)==row_id+1

		except Exception as e:
			traceback.print_exc()
			pdb.set_trace()

	return IPsrc, IPdest

def build_label_list(filename='OS_Scan_labels.csv'):
	try:
		CSV = pd.read_csv(filename)
		LABELS = CSV['x'].tolist()
	except FileNotFoundError as e:
		print(filename+' not found')
		LABELS = []
	return LABELS





def get_adversarial_IPs(IPs, IPd, LABELS, RMSEs, interval = 1000, memorySize = 50, blockchainMode ='offline', saveFile= 'results.csv',n_window=100000, quantile=0.5, rolling_window_size=500, smoothing_factor=0.9):

	benignLimit=100000
	FMgrace = 5000
	ADgrace = 50000

	RMSEs =  np.tanh(RMSEs)

	benignSample = RMSEs[FMgrace+ADgrace+1:benignLimit]

	mean = np.mean(benignSample)
	std = np.std(benignSample)
	train_max = max(benignSample)

	threshold = train_max+3*std
	print(threshold)

	# mean = np.mean(benignSample)
	# std = np.std(benignSample)

	# train_max = max(benignSample)
	# threshold = mean+3*std

	# scale = train_max - threshold

	SUS_IPs = None #place holder
	SUS_IPs = dict()
	ALL_IPs = dict()
	first_occ = dict()
	last_occ = dict()

	target_IP = dict()

	node_score = nodeScore(memorySize, mode=blockchainMode) # 'offline', 'blocking', 'parallel'


	# RMSEsP  = []
	scores = np.zeros((100, int((len(RMSEs)-benignLimit)/interval)+1))

	# invert = True
	invert = False

	gold = LABELS[benignLimit:]
	pred = []

	FPFNx = []
	FPFNy = []
	rolling_window = []
	# pdb.set_trace()
	for i in tqdm( range(benignLimit, len(RMSEs)) ):
		# if i== len(RMSEs)-(10*benignLimit):
		# 	invert = True
		if invert:	
			rmse =  1- RMSEs[i]
		else:
			rmse =  RMSEs[i]
		ip = IPs[i]
		ip_d = IPd[i]

		# print(i)
		# if i>benignLimit:
		# pdb.set_trace()
		
			
			



		




		node_score.update(ip,i,rmse)
		# if (True):
		# 	if rmse >= train_max:
		# 		# RMSEsP.append(1)
		# 		add = 1
		# 	elif rmse > threshold:
		# 		# RMSEsP.append(1)
		# 		add =  (rmse - threshold)/scale
		# 	else:
		# 		# RMSEsP.append(rmse)
		# 		add = 0

		# 	try:
		# 		last_occ[ip] = i
		# 		ALL_IPs[ip] += 1
		# 	except KeyError as e:
		# 		first_occ[ip] = i
		# 		ALL_IPs[ip] = 1

		# 	if add >= 0:
		# 		# ip = IPs[i]
		# 		try:
		# 			SUS_IPs[ip] += add
		# 		except KeyError as e:
		# 			SUS_IPs[ip] = add

		# 		try:
		# 			target_IP[ip][ip_d] += 1
		# 		except KeyError as e:
		# 			try:
		# 				target_IP[ip][ip_d] = 1
		# 			except KeyError as e:				
		# 				target_IP[ip] = dict()
		# 				target_IP[ip][ip_d] = 1
		
		try:
			score = node_score.scores[ip].get_score()
		except Exception as e:
			# pdb.set_trace()
			score = rmse

		rolling_window.append(score)
		if len(rolling_window) > rolling_window_size:
			rolling_window = rolling_window[-rolling_window_size:]

			

		if (i - benignLimit) % (interval * n_window) == 0:
			all_scores = []
			for key in node_score.scores.keys():
				try:
					s = node_score.scores[key].get_score()
					all_scores.append(s)
				except Exception as e:
					continue

			if all_scores:
				if rolling_window:
					new_threshold = np.quantile(rolling_window, quantile)
                # Smooth the threshold update to avoid sudden jumps.
					threshold = smoothing_factor * threshold + (1 - smoothing_factor) * new_threshold
					print("thresh",threshold,train_max+3*std)
					threshold = max(threshold,train_max+3*std)
					

		

		if score>=threshold:
			flag=1
		else:
			flag=0
		

		if LABELS[i]!= flag:
			if ip == '192.168.2.1':
				flag = LABELS[i]
			else:
				# print(ip)
				FPFNx.append(i-benignLimit)
				FPFNy.append(score)



		pred.append(flag)

		if i%100000==0:
			node_score.finalize()

		if i%interval==0:
			# print(i)
			j= int((i-benignLimit)/interval)
			# node_score.finalize()
			for k, key in enumerate (node_score.scores.keys()):
				try:
					if key==ip:
						scores[k,j] = score #node_score.scores[key].get_score()
						# pass
				except Exception as e:
					traceback.print_exc()
					pdb.set_trace()

			# scores[-2,j] = node_score.scores[ip].get_score()
			scores[-1,j] = rmse

	# node_score.finalize()
	print(node_score.scores)

	# scores = [float('nan') if x==0 else x for x in scores]
	scores[ scores==0 ] = np.nan


	plt.axhline(y=threshold, color='g', ls='--')
	plt.axhline(y=train_max, color='r', ls='--')
	plt.axvline(x=benignLimit/interval, color='k', ls='--')

	plt.scatter(range(len(scores[-1,:])),scores[-1,:],s=1, marker='x', c='k',label='rmse scores')
	for k, key in enumerate (node_score.scores.keys()):
		plt.scatter(range(len(scores[k,:])),scores[k,:],s=1, marker='.',label=key)
		# print(k)
		
	# plt.scatter(range(len(scores[-2,:])),scores[-2,:],s=0.1, c='k',label='adjusted scores')
	# plt.plot(range(len(scores[-1,:])),scores[-1,:],'.')
	
	plt.scatter(FPFNx,FPFNy, s=1, c='r', marker='o',label='FP')
	

	# lgnd =plt.legend( title="node ids")#, bbox_to_anchor=(1.05, 1), loc='upper left', )
	# for k in range(len(node_score.scores)+1):
	# 	lgnd.legendHandles[k]._sizes = [30]

	plt.title("Adjusted Anomaly Scores")
	plt.ylabel("Scores")
	plt.xlabel("Time elapsed [1000 mins]")

	plt.show()
	Supected_IPs =  SUS_IPs
	Supected_IPs =  sorted(SUS_IPs.items(), key=lambda x: x[1], reverse=True)

	# with open(saveFile, 'w') as f:
	# 	f.write('ip, occurance, attack prob , first seen , last seen, destination ip , count\n' )

	# # pdb.set_trace()
	# 	for tupple in Supected_IPs:
	# 		# print(ip, ':', Supected_IPs[ip])
	# 		ip 			=  tupple[0]
	# 		score 		= tupple[1]
	# 		occurance 	= ALL_IPs[ip]
	# 		first 		= first_occ[ip]
	# 		last 		= last_occ[ip]
	# 		targets 	= target_IP[ip]
	# 		# print(ip,',', score, ',', occurance,',', score/occurance)
	# 		# print(ip,',', occurance,',', round(score/occurance,2), ',', first, ',', last )
	# 		f.write( str(ip)+','+str(occurance)+','+str(round(score,2))+ ','+str(first)+ ','+str(last)+ ',,,\n' )
	# 		for target in targets:
	# 			# print('\t',target,':', targets[target])
	# 			f.write( ',,,,,'+str(target)+','+str(targets[target])+',\n')

	# 		# f.write('\n' )


	
	# print(benignLimit)
	
	
	return gold, pred#Supected_IPs, node_score

def main():
	print('\x1bc')
	RMSEs = load('RMSEs_OS_scan.pkl')
	IPs, IPd = build_IP_list('OS_Scan_pcap.pcapng.tsv')
	LABELS = build_label_list(filename='OS_Scan_labels.csv')
	gold, pred = get_adversarial_IPs(IPs, IPd, LABELS, RMSEs, interval = 1, memorySize= 6 , blockchainMode = 'blocking' ) # 'offline', 'blocking', 'parallel')
	CM = confusion_matrix(gold, pred, labels=[0, 1])
	tn, fp, fn, tp = CM.ravel()
	print(CM)
	print(tn, fp, fn, tp) 

# print( len(IPs), len(IPsrc) )

# import importlib, results as r
# importlib.reload(r)
# RMSEs = r.load('RMSEs_OS_scan.pkl')
# IPs, IPd = r.build_IP_list('OS_Scan_pcap.pcapng.tsv')
# sip, ns = r.get_adversarial_IPs(IPs, IPd, RMSEs, memorySize= 3 , blockchainMode = 'blocking' ) # 'offline', 'blocking', 'parallel')
# sip, ns = r.get_adversarial_IPs(IPs, IPd, RMSEs)

# print( len(IPs), len(IPsrc) )

# pdb.set_trace()



if __name__ == '__main__':
	main()

