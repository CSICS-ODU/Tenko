#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Oct 10 22:50:11 2021

@author: yingwang
"""
import matplotlib
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

import itertools
marker = itertools.cycle(('o','x','+','*','<','^','v', '>',',',  '.')) 
import matplotlib.ticker as mtick
import pdb, traceback

# matplotlib.use('TkAgg')

# matplotlib.rcParams['figure.dpi'] = 400
# plt.rcParams.update({
#     "text.usetex": True,
#     "font.family": "serif",
#     "font.serif": ["Times"]})

fig = plt.figure(figsize=(7,3))
percentage = [0,
5,5,5,5,5,
10,10,10,10,10,
15,15,15,15,15,
20,20,20,20,20,
25,25,25,25,25,
30,30,30,30,30,
]

index_all = range(len(percentage))

# num = [0,0.1,0.25,0.5,0.75,1,0.1,0.25,0.5,0.75,1,0.1,0.25,0.5,0.75,1,0.1,0.25,0.5,0.75,1]
num_percentage = ['no noise',
'10-15\%','25-30\%','50-55\%','75-80\%','95-100\%',
'10-20\%','25-35\%','50-60\%','75-85\%','90-100\%',
'10-25\%','25-40\%','50-65\%','75-90\%','85-100\%',
'10-30\%','25-45\%','50-70\%','75-95\%','80-100\%', 
'10-35\%','25-50\%','50-75\%','75-100\%','75-100\%', 
'10-40\%','25-55\%','50-80\%','75-100\%','70-100\%', 
]





# auc = [0.828965541, #raw_model_data
# 0.765079852, 0.79239053, 0.783063685, 0.776038232, 0.76987213, 
# 0.774426184, 0.787081155, 0.769218635, 0.745918214, 0.733873628, 
# 0.779334573, 0.786731718, 0.767280408, 0.73801259, 0.7276629, 
# 0.78562774, 0.785503239, 0.763334795, 0.726003309, 0.718543847, 
# 0.791363045, 0.783731069, 0.758808359, 0.718782155, 0.718782155, 
# 0.796438651, 0.782565605, 0.753387104, 0.719756543, 0.719756543, 
# ]

auc = [0.986759731, #no downlink model data 
0.942934273, 0.97935123, 0.975533958, 0.972966609, 0.971352984, 
0.946505888, 0.978705864, 0.971036686, 0.959097229, 0.951270219, 
0.94743677, 0.978204705, 0.96918686, 0.952579257, 0.945394296, 
0.948852239, 0.976748511, 0.966170616, 0.943740605, 0.938731576, 
0.950069223, 0.974957966, 0.962564289, 0.937105229, 0.937105229, 
0.951651791, 0.973304449, 0.958197453, 0.93619392, 0.93619392, 
]



# auc = [0.922531327, #avg_model_data         # window = 100
# 0.868771365, 0.864395025, 0.868583767, 0.77394244, 0.661428133, 
# 0.877219258, 0.847537125, 0.83096708, 0.839137823, 0.769543994, 
# 0.900502385, 0.87468361, 0.85550529, 0.777491045, 0.79962447, 
# 0.896653048, 0.874758831, 0.819757199, 0.77023197, 0.745789965, 
# 0.900570879, 0.860261145, 0.846252052, 0.792701251, 0.792701251, 
# 0.890447293, 0.844907918, 0.825513928, 0.77628769, 0.77628769, 
# ]

# auc = [0.924252674, #avg_model_data         # window = 500
# 0.961651356, 0.885161562, 0.821646353, 0.86201973, 0.721707749, 
# 0.85059712, 0.856966284, 0.838479037, 0.669939087, 0.773404393, 
# 0.753972201, 0.727418916, 0.753289729, 0.801373305, 0.711566794, 
# 0.878692401, 0.691646818, 0.831074555, 0.822420537, 0.773996285, 
# 0.787461375, 0.881192607, 0.740870332, 0.701540494, 0.701540494, 
# 0.957999385, 0.85825288, 0.842201676, 0.732260012, 0.732260012, 
# ]


percentage_type = [0, 5, 10, 15, 20,25,30]

for loop in range(len(percentage_type)):
    index = []
    auc_temp = []
    for i in range(len(percentage)):
        if percentage[i] == percentage_type[loop]: 
            index.append(i)
            auc_temp.append(auc[i])
    print(index, auc_temp)
    plt.plot(index, auc_temp, marker = next(marker), label = 'poison percentage: '+str(percentage_type[loop]))


# pdb.set_trace()
# calc the trendline
z = np.polyfit(index_all, auc, 1)
p = np.poly1d(z)
plt.plot(index_all,p(index_all),"r--")
plt.xlabel( r'\textbf{Placement of the poisoned noise}',fontweight='bold', fontsize=15)
plt.ylabel( r'\textbf{AUC}',fontweight='bold', fontsize=15)


# pdb.set_trace()

plt.xticks(index_all, num_percentage, fontsize=15,rotation=60)
plt.yticks( fontsize=15)



plt.grid()
plt.legend(prop={'size': 'medium','size': 15})
fig.savefig('./task_1/'+'trend_new_avg.png',dpi=300, bbox_inches="tight") 
plt.show()



