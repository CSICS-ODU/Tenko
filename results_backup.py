from matplotlib import pyplot as plt
from matplotlib import cm, colors
import numpy as np
from scipy.stats import norm, mode
import pickle
import csv
from tqdm import tqdm
import pdb, traceback

def load(filename='RMSEs.pkl'):
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

class scoreClass():
	"""docstring for scores"""
	def __init__(self, timestamp, n, timestep =1000):
		assert 0<=n<=1,"n must be in range [0, 1]!"
		self.timestamp 		= timestamp
		self.timestep 		= timestep
		self.init_timestamp = timestamp
		self.numerator 		= n
		self.dinominator	= 1
		self.finalized		= False

	def update_anamoly(self, current_timestamp, n):
		assert 0<=n<=1,"n must be in range [0, 1]!"
		self.numerator += n
		self.update_benign(current_timestamp)

	def update_benign(self, current_timestamp):
		self.dinominator +=1
		# self.decay_dinominator(current_timestamp)
		self.finalized = False

	def decay_fraction(self, n): # must decay all fractions at once
		# d =  (self.dinominator/self.numerator)*n
		self.numerator 		-= n
		self.dinominator 	-= 1
		# self.finalized = False not nessacary, dinominator decay not effected
		if self.dinominator < 1:  
			self.numerator = 0
			self.dinominator = 1
		elif self.numerator < 0:
			self.numerator = 0

		return self.numerator == 0

	def decay_dinominator(self, current_timestamp): # possible to decay only current dinominator 
		if current_timestamp-self.timestep>self.timestamp:
			# self.dinominator *= np.exp((self.timestamp-current_timestamp)/self.timestep)
			print((current_timestamp-self.timestamp)/self.timestep)
			self.dinominator -= (current_timestamp-self.timestamp)/self.timestep
			if self.dinominator<self.numerator:
				self.dinominator = self.numerator
				if self.dinominator<1:
					self.dinominator = 1
		self.timestamp = current_timestamp

	def set_score(self):
		self.finalized = True
		self.score = self.numerator/self.dinominator

	def get_score(self):
		if not self.finalized:
			raise Exception('Not finalized!')
		else:
			return self.score
			# return str(self.numerator)+'/'+str(self.dinominator)+'\n'

	def __lt__(self, other):
		# p1 < p2 calls p1.__lt__(p2)
		return self.get_score() < other.get_score()
	
	def __eq__(self, other):
		# p1 == p2 calls p1.__eq__(p2)
		return self.get_score() == other.get_score()

	def __str__(self):
		try:
			return "{:.2f}\n".format(self.get_score()) 
		except Exception as e:
			return "{num:.2f}/{den:.2f}\n".format(num=self.numerator,den=self.dinominator) 
		

	def __repr__(self):
		return self.__str__() 
		

class nodeScore():
	"""docstring for nodeScore"""
	def __init__(self, max_length=100):
		# super(nodeScore, self).__init__()
		self.max_length 	= max_length  # the manimum number of nodes tracked
		self.scores 		= dict()
		self.last_timestamp = 0
		self.zeroed_node	= True

	def update(self, nodeId, current_timestamp, n):
		self.last_timestamp = current_timestamp
		try:
			if n == 0:
				self.scores[nodeId].update_benign(current_timestamp)
				self.zeroed_node = nodeId
			else:
				self.scores[nodeId].update_anamoly(current_timestamp, n)
				self.zeroed_node = None
		except KeyError as e:			
			if len(self.scores) < self.max_length:
				self.scores[nodeId] = scoreClass(current_timestamp, n)
			else:
				# print('\n\n'+str(nodeId))
				if not self.zeroed_node:
					for nodeId_j in  self.scores.keys():
						# print("{nodeId}:\t{num:.2f}/{den:.2f}".format(nodeId=nodeId_j,num=self.scores[nodeId_j].numerator, den=self.scores[nodeId_j].dinominator) )
						zeroed = self.scores[nodeId_j].decay_fraction(n)
						# print("\t{score:.2f}:\t{num:.2f}/{den:.2f}".format(score=self.scores[nodeId_j].numerator/self.scores[nodeId_j].dinominator, num=self.scores[nodeId_j].numerator, den=self.scores[nodeId_j].dinominator) )
						
						if zeroed:
							self.zeroed_node = nodeId_j
							print
					# pdb.set_trace()
				if self.zeroed_node:
					try:
						del self.scores[self.zeroed_node]
					except Exception as e:
						traceback.print_exc()
						pdb.set_trace()
					
					self.scores[nodeId] = scoreClass(current_timestamp, n)
					self.zeroed_node = None
				
					





				
				# pdb.set_trace()
				# self.finalize()
				# self.scores =  sorted(self.scores.items(), key=lambda x: x[1], reverse=True)

	



	def finalize(self):
		for nodeId in  self.scores.keys():
			# print("{nodeId}:{num:.2f}/{den:.2f}".format(nodeId=nodeId,num=self.scores[nodeId].numerator, den=self.scores[nodeId].dinominator) )
			self.scores[nodeId].decay_dinominator(self.last_timestamp)
			# print("{nodeId}:{num:.2f}/{den:.2f}".format(nodeId=nodeId,num=self.scores[nodeId].numerator, den=self.scores[nodeId].dinominator) )
			# print(str(nodeId)+ ':'+ str(self.scores[nodeId].numerator)+'/'+str(self.scores[nodeId].dinominator) )
			self.scores[nodeId].set_score()



		






def get_adversarial_IPs(IPs, IPd, RMSEs, saveFile= 'results.csv'):
	benignLimit=100000
	FMgrace = 5000
	ADgrace = 50000

	RMSEs =  np.tanh(RMSEs)

	benignSample = RMSEs[FMgrace+ADgrace+1:benignLimit]

	mean = np.mean(benignSample)
	std = np.std(benignSample)

	train_max = max(benignSample)
	threshold = mean+3*std

	scale = train_max - threshold

	SUS_IPs = dict()
	ALL_IPs = dict()
	first_occ = dict()
	last_occ = dict()

	target_IP = dict()

	node_score = nodeScore()

	# RMSEsP  = []
	scores = np.zeros((10, int((len(RMSEs)-benignLimit)/1000)+1))

	for i in range(benignLimit, len(RMSEs)):
		rmse =  RMSEs[i]
		ip = IPs[i]
		ip_d = IPd[i]

		node_score.update(ip,i,rmse)
		if rmse >= train_max:
			# RMSEsP.append(1)
			add = 1
		elif rmse > threshold:
			# RMSEsP.append(1)
			add =  (rmse - threshold)/scale
		else:
			# RMSEsP.append(rmse)
			add = 0

		try:
			last_occ[ip] = i
			ALL_IPs[ip] += 1
		except KeyError as e:
			first_occ[ip] = i
			ALL_IPs[ip] = 1

		if add >= 0:
			# ip = IPs[i]
			try:
				SUS_IPs[ip] += add
			except KeyError as e:
				SUS_IPs[ip] = add

			try:
				target_IP[ip][ip_d] += 1
			except KeyError as e:
				try:
					target_IP[ip][ip_d] = 1
				except KeyError as e:				
					target_IP[ip] = dict()
					target_IP[ip][ip_d] = 1

		if i%1000==0:
			j= int((i-benignLimit)/1000)
			node_score.finalize()
			for k, key in enumerate (node_score.scores.keys()):
				try:
					scores[k,j] = node_score.scores[key].get_score()
				except Exception as e:
					traceback.print_exc()
					pdb.set_trace()
				
			scores[-1,j] = rmse

	# scores = [float('nan') if x==0 else x for x in scores]
	scores[ scores==0 ] = np.nan
	# fig, ax = plt.subplots()
	for k, key in enumerate (node_score.scores.keys()):
		plt.scatter(range(len(scores[k,:])),scores[k,:],s=0.1,label=key)
		# legend(key)
	plt.scatter(range(len(scores[-1,:])),scores[-1,:],s=0.1, c='k',label='rmse scores')
	# legend('score')

	lgnd =plt.legend( title="node ids")
	for k in range(len(node_score.scores)+1):
		lgnd.legendHandles[k]._sizes = [30]
	plt.show()
	Supected_IPs =  SUS_IPs
	# Supected_IPs =  sorted(SUS_IPs.items(), key=lambda x: x[1], reverse=True)

	# with open(saveFile, 'w') as f:
	# 	f.write('ip, occurance, attack prob , first seen , last seen, destination ip , count\n' )

	# 	# pdb.set_trace()
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
	# 		f.write( str(ip)+','+str(occurance)+','+str(round(score/occurance,2))+ ','+str(first)+ ','+str(last)+ ',,,\n' )
	# 		for target in targets:
	# 			# print('\t',target,':', targets[target])
	# 			f.write( ',,,,,'+str(target)+','+str(targets[target])+',\n')

	# 		# f.write('\n' )


	
	
	node_score.finalize()
	
	return Supected_IPs, node_score


# import results as r
# RMSEs = r.load('RMSEs_OS_scan.pkl')

# IPs, IPd = r.build_IP_list('OS_Scan_pcap.pcapng.tsv')

# print( len(IPs), len(IPsrc) )

# get_adversarial_IPs(IPs, RMSEs)

# pdb.set_trace()




