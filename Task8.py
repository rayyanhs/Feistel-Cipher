#!/usr/bin/env python
# coding: utf-8

# In[1]:


from helper import *


# In[2]:


### TASK 8 ###
print("\n### TASK 8 ###\n")

data = pd.read_csv('KPAdatazurich/KPApairsZurich_non_linear.txt', sep = "\t", header = None)
print("data:\n{0}\n".format(data))


# In[3]:


#TASK 8 for one msg only case

k1 = 2**16
n1 = 2**10
n2 = 2**10

#STEP 1: key' guess
k1 = np.zeros([n1, 16], dtype=int) #to store N' random guessing of k'
k1_ = np.zeros([n1, 1], dtype=int)
for i in range(n1):
    rand_key = random.getrandbits(16)
    k1[i] = str_to_np(bin(rand_key)[2:].zfill(16)) #random key in bits
    k1_[i] = rand_key

#STEP 2: cipher guess
x1 = np.zeros([n1], dtype=int) #to store N' random guessing of k'
#x1_ = np.zeros([n1, 1], dtype=int)
for i in range(n1):
    x1[i] = int(encryption(bin(int(data[0][0], 16))[2:].zfill(16), 16, 16, 13, k1[i], task_number=7),2) #for better visual idea
    
#STEP 3: sort table according to x1
df1 = pd.DataFrame(k1_, columns=['k1'])
df1 = pd.concat([df1, pd.DataFrame(x1, columns=['x1'])], axis=1)
df1.sort_values('x1', inplace=True, ignore_index=True) 
#print(df1)

#STEP 4: key'' guess
k2 = np.zeros([n2, 16], dtype=int) #to store N' random guessing of k'
k2_ = np.zeros([n2, 1], dtype=int)
for i in range(n2):
    rand_key = random.getrandbits(16)
    k2[i] = str_to_np(bin(rand_key)[2:].zfill(16)) #random key in bits
    k2_[i] = rand_key

#STEP 5: plaintext guess
u2 = np.zeros([n2], dtype=int) #to store N' random guessing of k'
for i in range(n2):
    u2[i] = int(dencryption(bin(int(data[1][0], 16))[2:].zfill(16), 16, 16, 13, k2[i], task_number=7),2) #for better visual idea
#STEP 6: sort table according to u2
df2 = pd.DataFrame(k2_, columns=['k2'])
df2 = pd.concat([df2, pd.DataFrame(u2, columns=['u2'])], axis=1)
df2.sort_values('u2', inplace=True, ignore_index=True) 
#print(df2)

#STEP 7: search for  match between df1 and df2
matches = pd.DataFrame(columns=['k1','k2','x1','u2'])
count = 0
for i in range(n1):
    result = binary_search(df2['u2'], df1['x1'][i])
    #matches = matches.append(pd.DataFrame([1,1,2,3], columns=['k1','k2','x1','x2']), ignore_index=True)
    if result != -1:
        #print("match found")
        matches = matches.append(pd.DataFrame({'k1': df1['k1'][i], 'k2': df2['k2'][result], 'x1': df1['x1'][i], 'u2': df2['u2'][result]}, index=[count]))
        count = count+1

print(matches)


# In[4]:


old_matches = pd.DataFrame({'k1': 42822, 'k2': 19168, 'x1': 3, 'u2': 4}, index=[0])
print(old_matches)

common_matches = pd.merge(old_matches, matches, how='inner', on=['k1', 'k2'])
common_matches = common_matches[['k1','k2']]
print(common_matches)


# In[5]:


# TODO: TASK 8 for all the five plaintext/ciphertext pairs


# In[6]:


prova = pd.DataFrame(k1_, columns=['letter'])
pd.concat([prova, pd.DataFrame(x1, columns=['ndf'])], names=['prova1', 'prova2'], axis=1)

#prova2 = prova
df_empty = prova[0:0]
print(df_empty)


# In[7]:


#s1 = pd.merge(dfA, dfB, how='inner', on=['S', 'T']


# In[8]:


"""
u=0x3333
print(type(u))
k=0x1

x= encryption_alt(bin(u)[2:], 16,16,17, str_to_np(bin(k)[2:]), task_number=7)
print(type(x))
u1= dencryption_alt(bin(int(x, 16))[2:], 16,16,17, str_to_np(bin(k)[2:]), task_number=7)
print(u1)
"""


# In[13]:


#TASK 8 for one msg only case
#DataFrame.equals(other)

k1 = 2**16
n1 = 2**7
n2 = 2**7

#matches = pd.DataFrame(columns=['k1','k2','x1','u2']) #matches table structure
matches = pd.DataFrame(columns=['k1','k2'])
comm_matches = pd.DataFrame(columns=['k1','k2'])

for j in range(data.shape[0]): #for each (u,x) pair in data
    
    #STEP 1: key' guess
    k1 = np.zeros([n1, 16], dtype=int) #to store N' random guessing of k'
    k1_ = np.zeros([n1, 1], dtype=int)
    for i in range(n1):
        rand_key = random.getrandbits(16)
        k1[i] = str_to_np(bin(rand_key)[2:].zfill(16)) #random key in bits
        k1_[i] = rand_key

    #STEP 2: cipher guess
    x1 = np.zeros([n1], dtype=int) #to store N' random guessing of k'
    #x1_ = np.zeros([n1, 1], dtype=int)
    for i in range(n1):
        x1[i] = int(encryption(bin(int(data[0][j], 16))[2:].zfill(16), 16, 16, 13, k1[i], task_number=7),2) #for better visual idea

    #STEP 3: sort table according to x1
    df1 = pd.DataFrame(k1_, columns=['k1'])
    df1 = pd.concat([df1, pd.DataFrame(x1, columns=['x1'])], axis=1)
    df1.sort_values('x1', inplace=True, ignore_index=True) 
    #print(df1)

    #STEP 4: key'' guess
    k2 = np.zeros([n2, 16], dtype=int) #to store N' random guessing of k'
    k2_ = np.zeros([n2, 1], dtype=int)
    for i in range(n2):
        rand_key = random.getrandbits(16)
        k2[i] = str_to_np(bin(rand_key)[2:].zfill(16)) #random key in bits
        k2_[i] = rand_key

    #STEP 5: plaintext guess
    u2 = np.zeros([n2], dtype=int) #to store N' random guessing of k'
    for i in range(n2):
        u2[i] = int(dencryption(bin(int(data[1][j], 16))[2:].zfill(16), 16, 16, 13, k2[i], task_number=7),2) #for better visual idea
    #STEP 6: sort table according to u2
    df2 = pd.DataFrame(k2_, columns=['k2'])
    df2 = pd.concat([df2, pd.DataFrame(u2, columns=['u2'])], axis=1)
    df2.sort_values('u2', inplace=True, ignore_index=True) 
    #print(df2)

    #STEP 7: search for  match between df1 and df2
    count = 0
    for i in range(n1):
        result = binary_search(df2['u2'], df1['x1'][i])
        #matches = matches.append(pd.DataFrame([1,1,2,3], columns=['k1','k2','x1','x2']), ignore_index=True)
        if result != -1:
            #print("match found")
            #matches = matches.append(pd.DataFrame({'k1': df1['k1'][i], 'k2': df2['k2'][result], 'x1': df1['x1'][i], 'u2': df2['u2'][result]}, index=[count]))
            matches = matches.append(pd.DataFrame({'k1': df1['k1'][i], 'k2': df2['k2'][result]}, index=[count]))
            count = count+1
    
    if j > 0:
        #print("old_matches: ", old_matches)
        common_matches = pd.merge(old_matches, matches, how='inner', on=['k1', 'k2'])
        common_matches = common_matches[['k1','k2']]
        common_matches.drop_duplicates(subset=['k1', 'k2'], inplace=True, ignore_index=True)
        
    old_matches = matches
    #print(common_matches)
print(common_matches)


# In[51]:


u = int(data[0][0], 16)
k1 = str_to_np(bin(64322)[2:].zfill(16))
k2 = str_to_np(bin(13737)[2:].zfill(16))


# In[53]:


x1 = encryption(bin(u)[2:].zfill(16), 16, 16, 13, k1, task_number=7)
print(x1)
x2 = encryption(x1, 16, 16, 13, k2, task_number=7)

print("ciphertext x: {0}".format(x2))

print(hex(int(data[1][0], 16)))


# In[ ]:




