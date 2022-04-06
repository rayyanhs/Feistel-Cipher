#!/usr/bin/env python
# coding: utf-8

# In[14]:


#imports
import random
import numpy as np
import sys

np.set_printoptions(threshold=sys.maxsize)

#for later
random.seed(42)

### helper functions ### 
def str_to_np(str): #to make code easier to read
    """
    str: binary string
    returns a binary numpy array with str's bits
    """
    return np.array(list(str), dtype=int)

#subkey generation
def generate_roundkeys(key, n_rounds):
    """
    key: 'original' key of Fiestel cipher
    n_rounds: number of rounds
    returns a numpy array of n_rounds round keys
    """
    round_keys = np.zeros([n_rounds, key.shape[0]], dtype=int) #nparray to store round keys
    lk = key.shape[0] #key length
    element = np.zeros([lk], dtype=int)
    
    for i in range(n_rounds):
        for j in range(lk):
            element[j] = key[((5*(i+1)+j)%lk)]
        round_keys[i] = element #save i-th round key
        
    return round_keys

#round function for block i
def round_function(ki, yi, task_number=1):
    """
    ki: i-th round key, i.e. the i-th element of the object is 
        returned by function generate_roundkeys(binary numpy array)
    yi: y of i-th iteration
    task_number: to select the function on the base of the task we want to perform
    returns wi=f(ki,yi), output of the i-th round function
    """
    l = yi.shape[0]
    wi = np.zeros([l], dtype=int)
    
    if task_number == 1: 
        for j in range(l): 
            if j < l/2:
                wi[j] = yi[j]^ki[4*(j+1)-4]
            else:
                wi[j] = yi[j]^ki[4*(j+1)-2*l-1]
    elif task_number == 7:
        for j in range(l): 
            if j < l/2:
                wi[j] = (yi[j]&ki[2*(j+1)-2])|(yi[2*(j+1)-2]&ki[2*(j+1)-1])|ki[4*(j+1)-1]

            else:
                wi[j] = (yi[j]&ki[2*(j+1)-2])|(ki[4*(j+1)-2*l-2]&ki[2*(j+1)-1])|yi[2*(j+1)-l-1]
    
    return wi

def encryption(u, message_length, key_length, n_rounds, random_key=1, key=None, task_number=1):
    """
    u: binary message (string)
    message_length: lu
    key_length: lk
    n_rounds: number of rounds
    random_key: set to 0 if want to pass your own key, to 1 to generate a random key
    key: customizable key to use (binary numpy array of length key_length)
    task_number: to choose the function for task 1, 5 or 7
    """
    u = u.zfill(message_length)
    l = int(message_length/2)
    
    #initial split of message u
    y1 = str_to_np(u[:l])
    z1 = str_to_np(u[l:])
    #print("y1={0}\nz1={1}".format(y1,z1))
    
    #random key
    if random_key == 1:
        key = str_to_np(bin(random.getrandbits(key_length))[2:]) #random key in bits
    elif key.shape[0] < key_length: #pad key if needed
        key = np.pad(key, (key_length-key.shape[0], 0), 'constant', constant_values=0)
           
    
    #get round keys
    round_keys = generate_roundkeys(key, n_rounds)
    #print("round keys:\n", round_keys)
    
    prova = np.zeros([message_length], dtype=int)
    for i in range(n_rounds):
        wi = round_function(round_keys[i], y1, task_number)
        vi = wi^z1 #equivalento to:(wi+z1)%2
        z1 = y1
        y1 = vi
        
        #to print midterm results
        #np.concatenate((z1,y1), out=prova)
        #print("Round {0}\nki={1}\nwi={2}\n[yi,zi]={3}\n".format(i,round_keys[i],wi,np.packbits(prova)))
         
    x = np.zeros([message_length], dtype=int)
    np.concatenate((z1, y1), out=x)
    
    return np.array2string(x, precision=int, separator='')[1:-1]

def dencryption(x, ciphertext_length, key_length, n_rounds, random_key=1, key=None, task_number=1):
    """
    x: binary ciphertext (string)
    ciphertext_length: lx
    key_length: lk
    n_rounds: number of rounds
    random_key: set to 0 if want to pass your own key, to 1 to generate a random key
    key: customizable key to use (binary numpy array of length key_length)
    task_number: to choose the function for task 1, 5 or 7
    """
    x = x.zfill(ciphertext_length)
    l = int(ciphertext_length/2)
    
    #initial split of message u
    yn = str_to_np(x[:l])
    vn = str_to_np(x[l:])
    #print("yn={0}\nvn={1}".format(yn,vn))
    
    #random key
    if random_key == 1:
        key = np.array(list(bin(random.getrandbits(key_length))[2:]), dtype=int) #random key in bits
    elif key.shape[0] < key_length: #pad key if needed
        key = np.pad(key, (key_length-key.shape[0], 0), 'constant', constant_values=0)
           
    #get round keys
    round_keys = generate_roundkeys(key, n_rounds)
    #print("round keys:\n", round_keys)
    
    prova = np.zeros([ciphertext_length], dtype=int)
    for i in range(n_rounds-1, -1, -1):
        wi = round_function(round_keys[i], yn, task_number)
        zi = wi^vn 
        vn = yn
        yn = zi
        
        #to print midterm results
        #np.concatenate((z1,y1), out=prova)
        #print("Round {0}\nki={1}\nwi={2}\n[yi,zi]={3}\n".format(i,round_keys[i],wi,np.packbits(prova)))
         
    u = np.zeros([ciphertext_length], dtype=int)
    np.concatenate((vn, yn), out=u)
    
    return np.array2string(u, precision=int, separator='')[1:-1]

def find_matrices(u, x, message_length, ciphertext_length, key_length, n_rounds, key):
    """
    finds matrices for encryption. Arguments are the same asked for function encryption
    u: plaintext (binary string)
    x: ciphertext - output of function encryption for u (binary string)
    """
    u = u.zfill(message_length)
    x = u.zfill(ciphertext_length)
    
    #parameters initialization
    A = np.zeros((ciphertext_length, key_length), dtype=int)           # matrix A to find
    Ek = np.identity(key_length, dtype=int)                            # matrix of standard orthonormal basis
    a = np.zeros((key_length, key_length), dtype=int)                  # output matrix of l encryptions in binary format
    zeros_str = bin(0)[2:].zfill(message_length)                       # string of 32 zeros, need it to maintain coherence with the definition of u in the encryption function
    
    B = np.zeros((ciphertext_length, message_length), dtype=int)       # matrix B to find
    Eu = np.identity(message_length, dtype=int)                        # matrix of standard orthonormal basis
    b = np.zeros((message_length, message_length), dtype=int)          # output matrix of l encryptions in binary format
    zeros_vec = np.zeros(key_length, dtype=int)                        # null vector of 32 zeros
    
    #compute A
    for i in range(A.shape[0]) :          # i-th row of y is the i-th column of A
        a[i] = str_to_np(encryption(zeros_str, message_length, key_length, n_rounds, random_key=0, key=Ek[i]))
    A= a.transpose()  # swap rows and columns in y in order to obtain A
    
    #compute B
    for i in range(B.shape[0]) :         # i-th row of y is the i-th column of B
        # create a string of 32 bit from a numpy array to pass at encryption as u
        q = ''.join([str(elem) for elem in ([str(int(Eu[i][j])) for j in range(Eu[i].shape[0])])])        # i-th row of y is the i-th column of A
        b[i] = str_to_np(encryption(q, message_length, key_length, n_rounds, random_key=0, key=zeros_vec))
    B= b.transpose()  # swap rows and columns in y in order to obtain A
    
    return A,B


# In[10]:


### TASK 1 ###
print("### TASK 1 ###\n")

k = str_to_np(bin(0x80000000)[2:])
x = encryption(bin(0x80000000)[2:], 32, 32, 17, random_key=0, key=k)

print("x binary: {0}\nx hex: {1}".format(x, hex(int(x, 2))))


# In[8]:


### TASK 2 ###
print("\n### TASK 2 ###\n")

#encryption parameters
u = 0x80000000
k = 0x80000000

u = bin(u)[2:].zfill(32)
k = str_to_np(bin(k)[2:])
print("plaintext (binary form): {0}\nplaintext (hex form): {1}".format(u, hex(int(u, 2))))

#encryption
x = encryption(u, 32, 32, 17, random_key=0, key=k)

#decryption
u1 = dencryption(x, 32, 32, 17, random_key=0, key=k)

#print
print("\ndeciphered message (binary form): {0}\ndeciphered message (hex form): {1}".format(u1, hex(int(u1, 2))))

#check if they match
if u1 == u:
    print("\nretrieved message is equal to the original one: success!")
else:
    print("fail")


# In[5]:


### TASK 3 ###
# CHECK IF x=E(k,u)=?=Ak+Bu=y
print("\n### TASK 3 ###\n")

#insert the parameters you want (max length=32)
u = 0x05000040
k = 0x05000001
n = 17

#parameters setting
u = bin(u)[2:].zfill(32)
k = (str_to_np(bin(k)[2:].zfill(32)))
x = encryption(u, len(u), k.shape[0], n, random_key=0, key=k)  # x=E(k,u)
print("ciphertext x: {0}".format(x))

#find matrices A and B
A,B = find_matrices(u, x, len(u), len(x), k.shape[0], n, k)

#computes Ak AND Bx, summing mod2 over rows to get a (lx,1) vector
first = np.sum(A&k, axis=1)%2
second = np.sum(B&str_to_np(u), axis=1)%2

#computes Ak XOR Bx
string = np.array2string(first^second, precision=int, separator='')[1:-1]
print("Ak+Bu: {0}".format(string))

#cheack if they are equal
if string == x:
    print("\nx is equal to Ak+Bx! success!")
else:
    print("epic fail")


# In[16]:


### TASK 7 ###
print("### TASK 7 ###\n")

k = str_to_np(bin(0x369C)[2:])
x = encryption(bin(0x0)[2:], 16, 16, 13, random_key=0, key=k, task_number=7)

print("x binary: {0}\nx hex: {1}".format(x, hex(int(x, 2))))


# In[ ]:




