#!/usr/bin/env python
# coding: utf-8

# In[2]:


from helper import * 


# In[3]:


### TASK 1 ###
print("### TASK 1 ###\n")

u = bin(0x80000000)[2:]
k = bin(0x80000000)[2:]
print("plaintext u: {0}\nkey k: {1}\n".format(hex(int(u,2)), hex(int(k,2))))

#encryption
x = encryption(u, 32, 32, 17, str_to_np(k))
print("ciphertext x (binary): {0}\nciphertext x (hex): {1}".format(x, hex(int(x, 2))))


# In[4]:


### TASK 2 ###
print("\n### TASK 2 ###\n")

#encryption parameters (max length: 32bits)
u = 0x90f0700   #plaintext
k = 0x00000071  #key

u = bin(u)[2:].zfill(32)
k = str_to_np(bin(k)[2:])
print("plaintext (binary form): {0}\nplaintext (hex form): {1}".format(u, hex(int(u, 2))))

#encryption
x = encryption(u, 32, 32, 17, key=k)
print("\nciphertext (binary form): {0}\nciphertext (hex form): {1}".format(x, hex(int(x, 2))))

#decryption
u1 = dencryption(x, 32, 32, 17, key=k)

#print
print("\nciphertext (binary form): {0}\nciphertext (hex form): {1}".format(u1, hex(int(u1, 2))))

#check if they match
if u1 == u:
    print("\nretrieved message is equal to the original one: success!")
else:
    print("fail")


# In[5]:


### TASK 3 ###
# CHECK IF x=E(k,u)=?=Ak+Bu=y
print("\n### TASK 3 ###\n")

#encryption parameters (max length: 32bits)
u = 0x05000040   #plaintext
k = 0x05000001   #key
n = 17           #number of rounds

#parameters setting
u = bin(u)[2:].zfill(32)
k = (str_to_np(bin(k)[2:].zfill(32)))

#encryption
x = encryption(u, len(u), k.shape[0], n,   key=k)  #x=E(k,u)
print("ciphertext x: {0} ({1})".format(x, hex(int(x,2))))

#find matrices A and B
A,B = find_matrices(len(u), len(x), k.shape[0], n)

#computes A AND k, B AND x, summing mod2 over rows to get a (lx,1) vector
first = np.sum(A&k, axis=1)%2
second = np.sum(B&str_to_np(u), axis=1)%2

#computes Ak XOR Bx
stringa = np.array2string(first^second, precision=int, separator='')[1:-1]
print("Ak+Bu: {0} ({1})\n".format(stringa, hex(int(stringa,2))))

#cheack if the results we get are equal
if stringa == x:
    print("\nx is equal to Ak+Bx! success!")
else:
    print("epic fail")


# In[6]:


### TASK 4 ###
print("### TASK 4 ###\n")

A,B = find_matrices(32, 32, 32, 17) # the intruder know the system
u, x = [], [] # list of (u,x) pairs from the file

# read file
data = pd.read_csv('KPAdatazurich/KPApairsZurich_linear.hex', sep="\t", header=None)

# create arrays of plaintext and ciphertext in the format we need
for i in range(data.shape[0]) :
    u.append(hex(int('0x' + data[0][i], 16))) # u[i] is a hex string
    x.append(hex(int('0x' + data[1][i], 16)))
    u[i] = bin(int((u[i]), 16))[2:].zfill(32)  # convert u[i] to binary string
    x[i] = bin(int((x[i]), 16))[2:].zfill(32)
    
# find k given (u,x) computing the formula k=A^(-1)*(x+B*u) in the slide
def KPA(u, x) :
    invA = ((np.round(np.linalg.inv(A) * np.linalg.det(A))) % 2) % 2
    u = str_to_np(u)
    x = str_to_np(x)
    key = np.ndarray.astype(np.matmul(invA, (np.bitwise_xor(x, np.matmul(B, u) % 2))) % 2, dtype = int)
    #s = ''.join([str(elem) for elem in list(key)])
    #print("KPA key  : {0}".format(s))
    return key
    
# CHECK if x=E(k,u[i])=x[i], i.e if encrypting u[i] with k given by KPA we find the same x[i] used for KPA
# check for all the pairs in the input file
count = 0
k = np.zeros([data.shape[0], 32], dtype=int)
for i in range(data.shape[0]) :
    
    print("### message pair {0} ###".format(i))
    
    # key returned by KPA
    k = KPA(u[i], x[i])
    # encryption using such k
    check = encryption(u[i], 32, 32, 17, k)  # x=E(k,u)
    
    #print results and compare
    s = ''.join([str(elem) for elem in list(x[i])])
    print('check_'+ str(i) + '  : ' + check)
    print('x_'+ str(i) + '      : ' + s)
    if s == check:
        count = count+1

if count == data.shape[0]:
    key_str = np.array2string(k, precision=int, separator='')[1:-1]
    print("\nThe encryption key k is: {0} ({1})".format(key_str, hex(int(key_str,2))))
else:
    print("no common key k found")


# In[7]:


### TASK 5 ###
print("### TASK 5 ###\n")

u = bin(0x12345678)[2:]
k = bin(0x87654321)[2:]
print("plaintext u: {0}\nkey k: {1}\n".format(hex(int(u,2)), hex(int(k,2))))

#encryption
x = encryption(u, 32, 32, 5, str_to_np(k), task_number=5)
print("ciphertext x (binary): {0} ({1})".format(x, hex(int(x, 2))))


# In[ ]:


### TASK 6 ###
print("### TASK 6 ###\n")

# parameters
l, n, flag = 32, 5, 0
u, x = [], []
A, B = find_matrices(l, l, l, n)
C = np.zeros((l, l), dtype=int)
k = np.array(list(bin(0x87654321)[2:]), dtype=int)
zero = np.zeros(l, dtype=int)
eps = 1 / pow(2, l) # threshold for probability
n_guess, succ, = 0, 0 # number of attempts and successes

# read and store (u,x) pairs from file
data = pd.read_csv('KPAdatazurich/KPApairsZurich_nearly_linear.hex', sep="\t", header=None)
for i in range(data.shape[0]) :
    u.append(hex(int('0x'+data[0][i], 16)))
    x.append(hex(int('0x' + data[1][i], 16)))
    u[i] = bin(int((u[i]), 16))[2:].zfill(32)
    x[i] = bin(int((x[i]), 16))[2:].zfill(32)

while(flag) :
    n_guess += 1
    for i in range(l): # create random C
        for j in range(l):
            C[i][j] = np.random.randint(2, high=None)
    # compute Ak XOR Bu XOR Cx
    p = np.bitwise_xor(np.bitwise_xor(np.sum(A & k, axis=1) % 2, np.sum(B & (str_to_np(u[0])), axis=1) % 2), np.sum(C & (str_to_np(x[0])), axis=1) % 2)
    # increase number of success events if Ak XOR Bu XOR Cx = 0
    if (np.array_equal(zero, p)) : succ += 1
    ratio = succ / n_guess # compute number of success events / number of total attempts, i.e P[Ak XOR Bu XOR Cx = 0]
    if (ratio > eps) : # if P[Ak XOR Bu XOR Cx = 0] greater than the threshold then C is the required matrix so save it
        good_C = C
        flag = 0 # and exit from loop


# In[8]:


### TASK 7 ###
print("### TASK 7 ###\n")

u = bin(0)[2:]
k = bin(0x369c)[2:]
print("plaintext u: {0}\nkey k: {1}\n".format(hex(int(u,2)), hex(int(k,2))))

x = encryption(bin(0x0)[2:], 16, 16, 13, str_to_np(k), task_number=7)

print("x binary: {0}\nx hex: {1}".format(x, hex(int(x, 2))))


# In[17]:


print("\n### TASK 8 ###\n")

k = 2**16 #K' and K'' cardinality
n1 = 2**10
n2 = 2**10

if n1>k or n2>k:
    raise Exception("N' and N'' should be less than K' and K'' respectively (in our case K'=K''=K)")

#import data
data = pd.read_csv('KPAdatazurich/KPApairsZurich_non_linear.hex', sep = "\t", header = None)

nomi = []
for i in range(data.shape[0]):
    nomi.append("matches_" + str(i))
matches = {name: pd.DataFrame() for name in nomi}

#perform attack for each (u,x) pair in data
tot = pd.DataFrame(columns=['k1','k2'])
for i in range (data.shape[0]):
    matches[i] = meet_in_the_middle(bin(int(data[0][i],16))[2:], bin(int(data[1][i],16))[2:], n1, n2)
    print("# of possible keys found from (u,x) pair nr.{0}: {1}".format(i, matches[i].shape[0]))
    #tot is the concatenation of the matches gotten for all the (u,x) pairs
    tot = pd.concat([tot, matches[i]], ignore_index=True)

if check_task8(data, matches) == 0:
    print("the found pairs are correct for the corresponding plaintext/ciphertext pair")
else:
    print("Fail")


# In[21]:


# unfortunately using the next part we do not find any (k1,k2) pair that works for all the input pairs.
#probabily the procedure should be iterated using more bits for both n1 and n2
"""
#save tot
compression_opts = dict(method='zip',
                        archive_name='tot.csv')
tot.to_csv('tot.zip', index=False, compression=compression_opts)

#create pandas df with only duplicated rows of tot, i.e. (k1,k2) pairs that are more probable
dup = tot.duplicated()
index = dup[dup == True]
index_list = index.index.tolist()
dup = tot[tot.index.isin(index_list)]
dup.reset_index(inplace=True, drop=True)

#check if some pair k1, k2 works fine for all (u,x) pairs
possible_keys = dup
for i in range (data.shape[0]):
    
    u = bin(int(data[0][i], 16))[2:].zfill(16)
    x = bin(int(data[1][i], 16))[2:].zfill(16)
    
    for j in range(possible_keys.shape[0]):
        
        #get k1 and k2
        k1 = int(str(possible_keys['k1'][j]),10)
        k2 = int(str(possible_keys['k2'][j]),10)
        k1 = str_to_np(bin(k1)[2:].zfill(16))
        k2 = str_to_np(bin(k2)[2:].zfill(16))
        
        #perform E(k2,(E(k1,u)))
        x1 = encryption(u, 16, 16, 13, k1, task_number=7)
        x2 = encryption(x1, 16, 16, 13, k2, task_number=7)
        
        #check if result is equal to the right one
        if x2 != x:
            #print(j)
            possible_keys = possible_keys.drop(axis=0, index=j)
    
    possible_keys.reset_index(inplace=True, drop=True)
    print("# keys that works for all the first {0} (u,x) pairs: {1}".format(i,possible_keys.shape))

print("\npossible keys found in the end: ", possible_keys)
"""


# In[20]:


print(check_task8(data, matches))


# In[ ]:




