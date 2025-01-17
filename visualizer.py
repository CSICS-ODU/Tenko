import numpy as np
import time, pdb
import matplotlib.pyplot as plt

class Visualiser:
    def __init__(self):
        self.fig, self.ax = plt.subplots()
        self.ax1 = self.fig.add_subplot(1,1,1)

        self.X = np.linspace(0, 1000, 10000)
        self.Y = np.cos(self.X)

        self.interval = 100
        
        plt.ion()
        self.figure, self.ax = plt.subplots(figsize=(8,6))

        x, y = self.get_xy(0)
        self.line1, = self.ax.plot(x, y)
        # pdb.set_trace()

        plt.title("Dynamic Plot of sinx",fontsize=25)

        plt.xlabel("X",fontsize=18)
        plt.ylabel("sinX",fontsize=18)
        
        
    def get_xy(self, start):
        x = self.X[start:start+self.interval]
        y = self.Y[start:start+self.interval]
        # pdb.set_trace()
        return x,y
        
    
   

    def update_figure(self,  i): 
        # print(i)
        x, y = self.get_xy(i)
        self.line1.set_xdata(x)
        self.line1.set_ydata(y)
        # newXticks= np.linspace(x[0],x[-1], 10)
        # prop = {'xticks': np.array(newXticks),
        #         'yticks': np.array([0,  0.2,  0.6,  0.8,  1.0]),
        #         'ylabel': None, 'xlabel': None}
        # self.ax.update(prop)

        self.ax.relim()
        # update ax.viewLim using the new dataLim
        self.ax.autoscale_view()

        self.figure.canvas.draw()
        self.figure.canvas.flush_events()


### useage
vis = Visualiser()

for i in range(100):
    vis.update_figure(i)
    time.sleep(0.9)






