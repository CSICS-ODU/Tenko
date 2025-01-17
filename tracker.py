import random
import string
import requests
# import asyncio
# import aiohttp
import _thread
import threading

import pdb, traceback, time

class scoreClass():
	"""docstring for scores"""
	def __init__(self, timestamp, n, d=1, timestep =10000, historyEpoch=100000, initial_key = 0):
		if d==1:
			assert 0<=n<=1,"n must be in range [0, 1]!"
		self.timestamp 		= timestamp
		self.timestep 		= timestep
		self.historyEpoch 	= historyEpoch
		self.significanceEpoch = historyEpoch/100
		# self.init_timestamp = timestamp
		self.numerator 		= n
		self.denominator	= d
		self.finalized		= False

		self._key 			= initial_key
		self._key_lock 		= threading.Lock()


	def update_anamoly(self, current_timestamp, n):
		assert 0<=n<=1,"n must be in range [0, 1]!"
		with self._key_lock:
			self.numerator += n
			self.update_benign(current_timestamp)

	def update_benign(self, current_timestamp):
		self.denominator +=1

		if self.denominator> self.historyEpoch:
			self.denominator *= 0.8
			self.numerator *= 0.8		
		# self.decay_denominator(current_timestamp)
		self.finalized = False

	def merge_history(self, other):
		with self._key_lock:
			# try:
			# 	assert self.timestamp < other.timestamp, "history should not be newer!"
			# except Exception as e:
				# print(e)
				# pdb.set_trace()
				# self.timestamp 		= other.timestamp  ### timestamp saving at blockchain not implemented
			self.numerator 		+= other.numerator
			self.denominator	+= other.denominator

	def decay_fraction(self, n): # must decay all fractions at once
		with self._key_lock:
			if self.numerator ==0:
				return True
			else:
				k =  1 - (n/self.numerator)   # to ensure self.numerator = self.numerator - n 
				self.numerator 		*= k
				self.denominator 	*= k
				# self.finalized = False not nessacary, denominator decay not effected
				if self.denominator < 1:  
					self.numerator = 0
					self.denominator = 1
				elif self.numerator < 0:
					self.numerator = 0

			return self.numerator == 0

	# def decay_denominator(self, current_timestamp): # possible to decay only current denominator 
	# 	# print(current_timestamp-self.timestep, )
	# 	if current_timestamp-self.timestep>=self.timestamp:
	# 		# self.denominator *= np.exp((self.timestamp-current_timestamp)/self.timestep)
	# 		# print(1.5*np.log(current_timestamp-self.timestamp))
			
	# 		# print(self.denominator,end='\t')
	# 		self.denominator -= 1.5*np.log(current_timestamp-self.timestamp)#/self.timestep
	# 		# print(self.denominator)
	# 		if self.denominator<self.numerator:
	# 			self.denominator = self.numerator
	# 			if self.denominator<1:
	# 				self.denominator = 1
	# 		self.timestamp = current_timestamp

	def set_score(self):
		self.finalized = True
		self.score = self.numerator/self.denominator

	def get_score(self):
		if not self.finalized:
			# raise Exception('Not finalized!')
			self.set_score()
		
		return self.score
		# return str(self.numerator)+'/'+str(self.denominator)+'\n'

	def __lt__(self, other):
		# p1 < p2 calls p1.__lt__(p2)
		return self.get_score() < other.get_score()
	
	def __eq__(self, other):
		# p1 == p2 calls p1.__eq__(p2)
		return self.get_score() == other.get_score()

	def __repr__(self):
		try:
			return "\t{:.2f}\n".format(self.get_score()) 
		except Exception as e:
			traceback.print_exc()
			return "{num:.2f}/{den:.2f}\n".format(num=self.numerator,den=self.denominator) 
	
#http://34.135.203.85:7654/api/scores

class nodeScore():
	"""docstring for nodeScore"""
	def __init__(self, max_length=100, mode='parallel', name=None, endpoint='http://172.21.219.232:7654/api/scores'):
		# super(nodeScore, self).__init__()
		self.max_length 	= max_length  # the manimum number of nodes tracked
		self.scores 		= dict()
		self.last_timestamp = 0
		self.zeroed_node	= True
		self.endpoint 		= endpoint
		self.mode 			= mode
		if name:
			self.name 		= name
		else:			
			letters 		= string.ascii_lowercase
			self.name 		= 'IDS'.join(random.choice(letters) for i in range(4))

	
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
				# lookup_history
				self.lookup_from_blockchain( [nodeId])
			else:
				# print('\n\n'+str(nodeId))
				if not self.zeroed_node:
					for nodeId_j in  self.scores.keys():						
						zeroed = self.scores[nodeId_j].decay_fraction(n)
						if zeroed:
							self.zeroed_node = nodeId_j
							# print(nodeId_j)
					# pdb.set_trace()
				if self.zeroed_node:
					try:
						if  self.scores[self.zeroed_node].denominator >= self.scores[self.zeroed_node].significanceEpoch:						
							# backup_history
							self.backup_to_blockchain(  [self.get_score(self.zeroed_node)] )
						del self.scores[self.zeroed_node]
					except Exception as e:
						traceback.print_exc()
						pdb.set_trace()
					
					self.scores[nodeId] = scoreClass(current_timestamp, n)
					# lookup_history
					self.lookup_from_blockchain( [nodeId])
					self.zeroed_node = None	





				
				# pdb.set_trace()
				# self.finalize()
				# self.scores =  sorted(self.scores.items(), key=lambda x: x[1], reverse=True)


	def get_score(self,nodeId):
		return [nodeId , self.scores[nodeId].numerator, self.scores[nodeId].denominator]

	def get_transaction_id(self):
		return self.name+str(self.last_timestamp)

		
	def request_builder(self, scores, timestamp, addScore = False):
		letters     = string.ascii_lowercase
		unique      = ''.join(random.choice(letters) for i in range(4))
		
		if addScore:
			mode = "addScore"
		else:
			mode = "getScore"
		data = "[\n"
		for score in scores:
			transaction_id = 'IDS'+unique+'_'+str(score[0])+'_'+str(timestamp)
			# print(transaction_id)
			# pdb.set_trace()

			data += "{\n\"id\":\""+str(transaction_id)+"\",\n\"execer\": \"admin:admin\",\n\"messageType\": \""+mode+"\",\n\"digsig\": \"\""     
			if addScore:
				data += ",\n\"userId\": \""+str(score[0])+"\",\n\"numerator\":" +str(score[1])+",\n\"denominator\":" +str(score[2])       
			else:
				# pdb.set_trace()
				data += ",\t\"userId\": \""+str(score)+"\""
			data += "\n},"
		data = data[:-1]
		data += "\n]" 

		if  len(scores)==1:
			data=data[1:-1]
		return data  


	def backup_to_blockchain(self, scores):
		if self.mode=='offline':
			return 
		elif self.mode=='blocking':
			self.backup_routine(scores)
		else:
			_thread.start_new_thread( self.backup_routine, (scores,))
		 


	def backup_routine(self, scores):
		data_request = self.request_builder(scores, self.last_timestamp, addScore = True)
		# print(data_request)
		attempts = 0
		try:
			while attempts<3 :	
				# print(f'{attempts=}')
				# pdb.set_trace()			
				response = requests.post(self.endpoint, data=data_request)
				response_json = response.json()
				try:
					if response_json['msg'] == 'score added' or response_json['msg'] == 'scores added':
						# print(data_request,'\n',response_json)
						# time.sleep(3)
						# with open("data_dump.txt", "a") as dataFile:
						# 	dataFile.write(data_request)
						return
					else:
						raise ValueError(response_json['msg'])
				except Exception as e:
					print(e)
					traceback.print_exc()
					pdb.set_trace()
					attempts += 1
					if  attempts<3:
						print(response_json, "retrying...")
						# print(data_request)
						# pdb.set_trace()
					else:
						print(response_json, "aborting...")

		except Exception as e:
			print(e)
			pdb.set_trace()
			# pass
		

	def lookup_from_blockchain(self, identities):
		if self.mode=='offline':
			return 
		elif self.mode=='blocking':
			self.lookup_routine(identities)
		else:
			_thread.start_new_thread( self.lookup_routine, (identities,))
		

	def lookup_routine(self, identities):
		data_request = self.request_builder(identities, self.last_timestamp)
		try:
			response = requests.post(self.endpoint, data=data_request)
			response_json = response.json()
			try:
				if response_json['msg'] == 'not found':
					print(identities, response_json)
					pdb.set_trace()
					# time.sleep(1)
					return					
			except Exception as e:
				try:
					# pdb.set_trace()
					ts = response_json['timestamp']
					n = response_json['numerator'] 
					d = response_json['denominator'] 

					past_score = scoreClass(ts, n, d)
					try:
						self.scores[identities[0]].merge_history(past_score)
					except KeyError as e:
						return    # the query took too long to resolve, the result in no longer relevant					
					# update_history()
				except Exception as e1:
					# print(e, e1,'\n')
					# traceback.print_exc()
					# print(f'self.scores=')
					# pdb.set_trace()
					raise e				
			# print(response.json())
		except Exception as e:
			print(e)
			# pdb.set_trace()
			pass




	def finalize(self):  # backups scores to blockchain
		# pdb.set_trace()
		scores = []
		for nodeId in  self.scores.keys():
			# self.scores[nodeId].decay_denominator(self.last_timestamp)
			self.scores[nodeId].set_score()
			scores.append(self.get_score(nodeId))

		self.backup_to_blockchain(scores)		

		# # https://stackoverflow.com/questions/51699817/python-async-post-requests
		

		
