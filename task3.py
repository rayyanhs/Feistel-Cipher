import numpy as np
import task1_2 as f

# TASK 3
A = np.zeros((32, 32), dtype=int)           # matrix A to find
B = np.zeros((32, 32), dtype=int)           # matrix B to find
E = np.zeros((32, 32), dtype=int)           # matrix of standard orthonormal basis
y = np.zeros((32, 32), dtype=int)           # output matrix of l encryptions in binary format
y2 = np.zeros((32, 32), dtype=int)
l = A.shape[0]                              # dimension of matrices A,B
zeros_vec = np.zeros(32, dtype=int)         # null vector of 32 zeros
zeros_str = bin(0x00000000)[2:].zfill(32)   # string of 32 zeros, need it to maintain coherence with the definition of u in the encryption function
n = 17                                      # number of rounds for encryption phase

for i in range(l) :      # create a matrix in which each row is an orthonormal base
    E[i][i] = 1

# compute y=E(e_i, 0) to find A (see appendix 1 in slides)
for i in range(l) :          # i-th row of y is the i-th column of A
    y[i] = f.str_to_np(f.encryption(zeros_str, l, l, n, random_key=0, key=np.array(E[i], dtype=int))[1])

A = y.transpose()  # swap rows and columns in y in order to obtain A

# compute y=E(0, e_i) to find B (see appendix 1 in slides)
for i in range(l) :         # i-th row of y is the i-th column of B
    # create a string of 32 bit from a numpy array to pass at encryption as u
    q = ''.join([str(elem) for elem in ([str(int(E[i][j])) for j in range(E[i].shape[0])])])
    y2[i] = f.str_to_np(f.encryption(q, l, l, n, random_key=0, key=zeros_vec)[1])

B = y2.transpose()  # swap rows and columns in y in order to obtain B

# CHECK IF x=E(k,u)=?=Ak+Bu=y

u = 0x05000000
k = (f.str_to_np(bin(0x05000000)[2:].zfill(32)))
x = f.encryption(bin(u)[2:], l, l, n, random_key=0, key=k)[1]  # x=E(k,u)

prova = np.sum(A & k, axis=1) % 2
prova2 = np.sum(B & f.str_to_np(bin(u)[2:].zfill(32)), axis=1) % 2
risultato = prova ^ prova2
print("x: {0}".format(x))
print("Ak+Bu: {0}".format(risultato))

# check if they are equal
string = np.array2string(risultato, precision=int, separator='')[1:-1]

if string == x: print("x is equal to Ak+Bu!")