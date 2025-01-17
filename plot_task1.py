import pickle
from matplotlib import pyplot as plt, colors
import numpy as np
from sklearn.metrics import accuracy_score

class plot_figs():
	def __init__(self, filename='saved_data.pkl'):
		with open(filename, 'rb') as f:
			[self.results_raw, self.labels] 	= pickle.load(f)
			self.training_size 	= 596 
			self.results_raw = self.results_raw[:self.training_size]
			self.labels =self.labels[:self.training_size]

			self.threshold 		= 0.7386905499782933  # calculated elsewhere
			self.gold 			= np.round(np.tanh(self.labels))
			self.data_files 	= ['task_1/no_interference.csv', 'task_1/nr_11dBm.csv', 'task_1/lte_ul_11dBm.csv', 'task_1/lte_dl_11dBm.csv']
			self.num_samples	= len(self.labels)
			self.poison_persent = 0
			self.placement_percent = 0

	def plot_results(self, threshold = None, fig = True): #threshold set by inspection
		
		
		colors_set = ['green','red','blue','purple']
		try:
			plt.scatter(range(len(self.results_raw)),self.results_raw,s=1, marker='.',c=self.labels, cmap=colors.ListedColormap(colors_set) )
		except Exception as e:
			traceback.print_exc()
			pdb.set_trace()

		for i, file in enumerate(self.data_files):		
			plt.scatter([-1],[-1],s=3, marker='o', color=colors_set[i] , label=file[7:-4])


		plt.ylim((-0.01,1.01))
		plt.xlim(( 0, self.num_samples ))
		plt.axhline(y=self.threshold, xmin= self.training_size/self.num_samples, color='r', ls='--')

		# plt.axvline(x=0.05, ymin=0.1, ymax=1.1, color='k')
		plt.axvspan(0, self.training_size, facecolor='g', alpha=0.1)
		plt.text(self.training_size-350, -0.05, 'Train', fontsize=8)
		plt.text(self.training_size+100, -0.05, 'Test', fontsize=8)
		plt.legend()

		

		# plt.xticks([], [])
		if fig:
			plt.show()
			# pdb.set_trace()
		else:
			try:
				plt.savefig('task_1/poison_'+str(self.poison_persent)+'('+str(self.placement_percent)+').png', bbox_inches='tight')
				plt.close()
			except Exception as e:
				traceback.print_exc()
				pdb.set_trace()
			
		# 
		# pdb.set_trace()

	

	def draw_histograms(self, buckets =100, uniform_y_axis = True):
		hist_idx = []
		start_at = self.training_size+1
		num_classes = int(np.max(self.labels))+1
		fig, axs = plt.subplots(num_classes)
		colors_set = ['green','red','blue','purple']
		# try:
		for i in range(num_classes-1):
			end_at = np.where(self.labels==i+1)[0][0]
			hist_idx.append([start_at,end_at])
			start_at = end_at
		i +=1
		hist_idx.append([start_at,-1])
		for i in range(num_classes):
			axs[i].hist(self.results_raw[hist_idx[i][0]:hist_idx[i][1]], buckets, color = colors_set[i])

		if uniform_y_axis:
			plt.setp(axs, ylim=axs[-1].get_ylim(), xlim=axs[-1].get_xlim())
		else:
			plt.setp(axs, xlim=axs[-1].get_xlim())

		plt.show()

		pred = []
		for result_raw in self.results_raw:
			if result_raw>self.threshold:
				pred.append(1)
			else:
				pred.append(0)

		for i in range(num_classes):
			file = self.data_files[i]
			acc = accuracy_score(self.gold[hist_idx[i][0]:hist_idx[i][1]], pred[hist_idx[i][0]:hist_idx[i][1]])
			print(f'accuracy score for {file[7:-4]:s} :{acc:.3f}')
		acc = accuracy_score(self.gold[hist_idx[0][0]:hist_idx[-1][1]], pred[hist_idx[0][0]:hist_idx[-1][1]])
		print(f'overall accuracy :{acc:.3f}')

		# except Exception as e:
		# 	traceback.print_exc()
		# 	pdb.set_trace()


def main():
	print('\x1bc')
	plotter = plot_figs()
	plotter.plot_results()
	# plotter.draw_histograms(500)


if __name__ == '__main__':
	main()