import numpy as np
import task3 as m
import task1_2 as f
import pandas as pd

A = m.A # import matrix A and B computed in task3
B = m.B
u, x = [], [] # list of corresponding (u,x) pairs from the file

data = pd.read_csv('KPAdatazurich/KPApairsZurich_linear.hex', sep="\t", header=None)
for i in range(data.shape[0]) :
    u.append(hex(int('0x'+data[0][i], 16))) # u[i] is a hex string
    x.append(hex(int('0x' + data[1][i], 16)))
    u[i] = bin(int((u[i]), 16))[2:].zfill(32) # convert u[i] to binary string
    x[i] = bin(int((x[i]), 16))[2:].zfill(32)

# find k given (u,x) computing the formula k=A^(-1)*(x+B*u) in the slide
def KPA(u, x) :
    invA = ((np.round(np.linalg.inv(A) * np.linalg.det(A))) % 2) % 2
    u = f.str_to_np(u)
    x = f.str_to_np(x)
    key = np.matmul(invA, (np.bitwise_xor(x, np.matmul(B, u) % 2))) % 2
    print(key)
    return key

# CHECK if x=E(k,u[i])=x[i], i.e if encrypting u[i] with k given by KPA we find the same x[i] used for KPA
for i in range(5) :
    k = KPA(u[i], x[i])
    check = f.encryption(u[i], 32, 32, 17, random_key=0, key=k)[1]  # x=E(k,u)
    s = ''.join([str(elem) for elem in list(x[i])])
    print('check'+ str(i) + ' = ' + check)
    print('x'+ str(i) + '     = ' + s + '\n')