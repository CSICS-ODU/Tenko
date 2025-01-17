from matplotlib import pyplot as plt
from matplotlib import cm, colors
import numpy as np
from scipy.stats import norm, mode
import pickle

def load(filename='RMSEs_OS_scan.pkl'):
    try:
        f = open(filename,'rb')
        RMSEs = pickle.load(f)
        f.close()
    except FileNotFoundError as e:
        print(filename+' not found')
        RMSEs = []
    return RMSEs

def exponential_smoothing(x, alpha=0.5):
    assert 0 < alpha <= 1.0
    s = []*len(x)
    s.append(x[0])
    for t in range(1,len(x)):
        st = alpha * x[t] + (1-alpha)*s[t-1]
        s.append(st)
    return s


def plot_loss(RMSEs, interval=100, fig_name = None, benignLimit=100000, FMgrace = 5000, ADgrace = 50000):
    # FMgrace #the number of instances taken to learn the feature mapping (the ensemble's architecture)
    # ADgrace #the number of instances used to train the anomaly detector (ensemble itself)
    if fig_name is None:
        show_fig = True
        fig_name = 'Test_fig.png'
    else:
        show_fig = False

    assert benignLimit>FMgrace+ADgrace+1000

    # print(benignLimit, FMgrace+ADgrace+1000)

    
    benignSample = RMSEs[FMgrace+ADgrace+1:benignLimit] 
    # logBenignSample = np.log(benignSample)
    # logProbs = norm.logsf(np.log(RMSEs[FMgrace+ADgrace+1:]), np.mean(logBenignSample), np.std(logBenignSample))

    # Probs = norm.logsf(RMSEs, np.mean(benignSample), np.std(benignSample))

    

    mean = np.mean(benignSample)
    std = np.std(benignSample)

    train_max = max(benignSample)

    threshold = mean+3*std


    # smoothed = exponential_smoothing(benignSample)

    # meanS = np.mean(smoothed)
    # stdS = np.mean(smoothed)

    # thresholdS = np.median(benignSample)+3*std

    # tRMSEs = RMSEs/threshold

    # high_vals = [i for i in benignSample if i >threshold]

    # meanH = np.mean(high_vals)
    # stdH = np.mean(high_vals)

    # thresholdH = meanH+3*stdH

    # print(threshold,thresholdS)
    # import pdb; pdb.set_trace()

    # interval = 100

    # plot the RMSE anomaly scores
    # print("Plotting results")
    


    num_colors = 40
    cmap = plt.get_cmap('RdYlGn', num_colors)
    # cmap = copy.copy(mpl.cm.get_cmap("RdYlGn_r"))
    # cmap.set_over('red')
    # cmap.set_under('green')
    cmap = cm.get_cmap('RdYlGn_r')

    FP = len([i for i in benignSample if i > threshold])/len(benignSample)

    
    

    fig = plt.figure(figsize=(10,5))
    ax = plt.axes()
    # fig = plt.scatter(range(FMgrace+ADgrace+1,len(RMSEs),interval),RMSEs[FMgrace+ADgrace+1::interval],s=0.1,c=logProbs[::interval],cmap=cmap,vmin=0,vmax=train_max)
    plt.scatter(range(FMgrace+ADgrace+1,len(RMSEs),interval),RMSEs[FMgrace+ADgrace+1::interval],s=0.1,c=RMSEs[FMgrace+ADgrace+1::interval],cmap=cmap,vmin=threshold,vmax=train_max)

    # plt.scatter(range(FMgrace+ADgrace+1,len(RMSEs),interval),RMSEs[FMgrace+ADgrace+1::interval], s=0.1 )

    plt.axhline(y=train_max, color='r', ls='--')
    plt.axhline(y=threshold, color='g', ls='--')
    # plt.axhline(y=thresholdS, color='y', ls='--')
    plt.axvline(x=benignLimit, color='k', ls='--')

    # plt.yscale("log")
    plt.title("Anomaly Scores from Kitsune's Execution Phase")
    plt.ylabel("RMSE (log scaled)")
    plt.xlabel("Time elapsed [min]")

    # cax = fig.add_axes([ax.get_position().x1, ax.get_position().y0, 0.02,  ax.get_position().height/4])
    # print('..')

    # axes = plt.gca()
    # ymin, ymax = axes.get_ylim()
    # yval = ymax-ymin

    # figHeight = ax.get_position().height
    # sacleFactor = figHeight /yval



    # cax = fig.add_axes([ ax.get_position().x1+0.02, ax.get_position().y0+(1/sacleFactor)*threshold , 0.02,  sacleFactor*(train_max-threshold) ])


    # import pdb; pdb.set_trace()

    # figbar=plt.colorbar(extend='both',cax=cax,ticks=[])
    # figbar.ax.set_ylabel('Attack probability\n ', rotation=270)
    plt.savefig(fig_name)

    if show_fig:
        print( f'{FP*100:.3f}% value above threshold')
        plt.show()