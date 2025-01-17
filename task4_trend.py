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

matplotlib.use('TkAgg')

matplotlib.rcParams['figure.dpi'] = 400
plt.rcParams.update({
    "text.usetex": True,
    "font.family": "serif",
    "font.serif": ["Times"]})

fig = plt.figure(figsize=(7,3))
percentage = [0,
5,5,5,5,5,
10,10,10,10,10,
15,15,15,15,15#,
# 20,20,20,20,20,
# 25,25,25,25,25,
# 30,30,30,30,30,
]

index_all = range(len(percentage))

# num = [0,0.1,0.25,0.5,0.75,1,0.1,0.25,0.5,0.75,1,0.1,0.25,0.5,0.75,1,0.1,0.25,0.5,0.75,1]
num_percentage = ['no noise',
'10-15\%','25-30\%','50-55\%','75-80\%','95-100\%',
'10-20\%','25-35\%','50-60\%','75-85\%','90-100\%',
'10-25\%','25-40\%','50-65\%','75-90\%','85-100\%'#,
# '10%','25%','50%','75%','100%', 
# '10%','25%','50%','75%','100%',
# '10%','25%','50%','75%','100%'
]



auc = [0.986759731, #no downlink model data 
0.958214469, 0.97935123, 0.975533958, 0.972966609, 0.971352984, 
0.946505888, 0.978705864, 0.971036686, 0.959097229, 0.951270219, 
0.94473677, 0.978204705, 0.96918686, 0.952579257, 0.945394296, 
# 0.948852239, 0.976748511, 0.966170616, 0.943740605, 0.938731576, 
# 0.950069223, 0.974957966, 0.962564289, 0.937105229, 0.937105229, 
# 0.951651791, 0.973304449, 0.958197453, 0.93619392, 0.93619392, 
]




percentage_type = [0, 5, 10, 15]#, 20,25,30]

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
plt.xlabel( r'\text(?# bf{Placement of the poisoned noise}',fontweight='bold', fontsize=15)
plt.ylabel( r'\textb)f{AUC}',fontweight='bold', fontsize=15)

plt.xlabel( 'Placement of the poisoned noise',fontweight='bold', fontsize=15)
plt.ylabel( 'AUC',fontweight='bold', fontsize=15)



# pdb.set_trace()
plt.xticks(index_all, num_percentage, fontsize=15,rotation=60)
plt.yticks( fontsize=15)



plt.grid()
plt.legend(prop={'size': 'medium','size': 15}, loc='upper center', bbox_to_anchor=(0.5, -0.05),
          fancybox=True, shadow=True, ncol=2)
fig.savefig('./task_1/'+'trend.png',dpi=300, bbox_inches="tight") 
plt.show()



