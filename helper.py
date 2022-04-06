#!/usr/bin/env python
# coding: utf-8

# In[ ]:


#!/usr/bin/env python
# coding: utf-8

# In[ ]:


#imports
import random
import numpy as np
import pandas as pd

### helper functions ###

#to make code easier to read
def str_to_np(str):
    """
    Returns a binary numpy array with str's bits
    str: binary string
    """
    return np.array(list(str), dtype=int)

#subkey generation
def generate_roundkeys(key, n_rounds):
    """
    Returns the set of subkeys starting from key, using n_rounds rounds
    key: 'original' key of Fiestel cipher
    n_rounds: number of rounds
    returns a numpy array of n_rounds round keys
    """
    round_keys = np.zeros([n_rounds, key.shape[0]], dtype=int) #to store round keys
    lk = key.shape[0] #key length
    element = np.zeros([lk], dtype=int) #to store midterm results in the loop
    
    for i in range(n_rounds):
        for j in range(lk):
            element[j] = key[((5*(i+1)+j)%lk)]
        round_keys[i] = element #save i-th round-key
        
    return round_keys

#round function for block i
def round_function(ki, yi, task_number=1):
    """
    Returns wi=f(ki,yi), output of the i-th round function
    ki: i-th round key, i.e. the i-th element of the object is 
        returned by function generate_roundkeys(binary numpy array)
    yi: y of i-th iteration
    task_number: select which function to use on the base of the task we want to perform (1,5 or 7)
    """

    l = yi.shape[0]                     #block length
    wi = np.zeros([l], dtype=int)       #to store output
    
    if task_number == 1: 
        for j in range(l): 
            if j < l/2:
                wi[j] = yi[j]^ki[4*(j+1)-4]
            else:
                wi[j] = yi[j]^ki[4*(j+1)-2*l-1]
    elif task_number == 5:
        for j in range(l):
            if j < l/2:
                wi[j] = yi[j]^(ki[4*(j+1)-4]&(yi[2*(j+1)-2]|ki[2*(j+1)-2]|ki[2*(j+1)-1]|ki[4*(j+1)-3]))
            else:
                wi[j] = yi[j]^(ki[4*(j+1)-2*l-1]&(ki[4*(j+1)-2*l-2]|ki[2*(j+1)-2]|ki[2*(j+1)-1]|yi[2*(j+1)-l-1]))
    elif task_number == 7:
        for j in range(l): 
            if j < l/2:
                wi[j] = (yi[j]&ki[2*(j+1)-2])|(yi[2*(j+1)-2]&ki[2*(j+1)-1])|ki[4*(j+1)-1]

            else:
                wi[j] = (yi[j]&ki[2*(j+1)-2])|(ki[4*(j+1)-2*l-2]&ki[2*(j+1)-1])|yi[2*(j+1)-l-1]
    else:
        #in case task_number passed was invalid
        raise SystemExit("Wrong task_number: use 1, 5 or 7!")
    return wi

def encryption(u, message_length, key_length, n_rounds, key, task_number=1):
    """
    Given a plaintext returns the corresponding ciphertext for the passed encryption parameters
    u: message (binary string)
    message_length: lu
    key_length: lk
    n_rounds: number of rounds
    key: customizable key to use (binary numpy array of length key_length)
    task_number: to choose the function for task 1, 5 or 7 (default = 1)
    """
    # make u of correct length
    u = u.zfill(message_length)
    
    #initial split of message u
    l = int(message_length/2)
    y1 = str_to_np(u[:l])
    z1 = str_to_np(u[l:])

    # pad key if needed
    if key.shape[0] < key_length:
        key = np.pad(key, (key_length-key.shape[0], 0), 'constant', constant_values=0)

    #get round keys for passed key
    round_keys = generate_roundkeys(key, n_rounds)

    # Fiestel cipher algorithm for encryption
    for i in range(n_rounds):
        wi = round_function(round_keys[i], y1, task_number)
        vi = wi^z1 #equivalento to:(wi+z1)%2
        z1 = y1
        y1 = vi

    #final output
    x = np.zeros([message_length], dtype=int)
    np.concatenate((z1, y1), out=x)
    
    return np.array2string(x, precision=int, separator='')[1:-1]

def dencryption(x, ciphertext_length, key_length, n_rounds, key, task_number=1):
    """
    Given a ciphertext returns the corresponding plaintext for the passed decryption parameters
    x: ciphertext (binary string)
    ciphertext_length: lx
    key_length: lk
    n_rounds: number of rounds
    key: customizable key to use (binary numpy array of length key_length)
    task_number: to choose the function for task 1, 5 or 7 (default=1)
    """
    # make x of correct length
    x = x.zfill(ciphertext_length)
    
    #initial split of ciphertext x
    l = int(ciphertext_length / 2)
    yn = str_to_np(x[:l])
    vn = str_to_np(x[l:])

    #pad key if needed
    if key.shape[0] < key_length:
        key = np.pad(key, (key_length-key.shape[0], 0), 'constant', constant_values=0)
           
    #get round keys for passed key
    round_keys = generate_roundkeys(key, n_rounds)

    #Fiestel cipher algorithm for decryption
    for i in range(n_rounds-1, -1, -1):
        wi = round_function(round_keys[i], yn, task_number)
        zi = wi^vn 
        vn = yn
        yn = zi

    #final output
    u = np.zeros([ciphertext_length], dtype=int)
    np.concatenate((vn, yn), out=u)
    
    return np.array2string(u, precision=int, separator='')[1:-1]

def find_matrices(message_length, ciphertext_length, key_length, n_rounds):
    """
    Finds matrices for our cryptosystem: x = Ak + Bu
    message_length: lu
    ciphertext_length: lx
    key_length: lk
    n_rounds: number of rounds in encryption/decryption
    """

    #parameters initialization
    Ek = np.identity(key_length, dtype=int)                            # matrix of standard orthonormal basis
    a = np.zeros((key_length, key_length), dtype=int)                  # output matrix of l encryption in binary format
    zeros_str = bin(0)[2:].zfill(message_length)                       # string of 32 zeros, need it to maintain coherence with the definition of u in the encryption function

    Eu = np.identity(message_length, dtype=int)                        # matrix of standard orthonormal basis
    b = np.zeros((message_length, message_length), dtype=int)          # output matrix of l encryption in binary format
    zeros_vec = np.zeros(key_length, dtype=int)                        # null vector of 32 zeros
    
    #compute A
    for i in range(ciphertext_length) :          # i-th row of y is the i-th column of A
        a[i] = str_to_np(encryption(zeros_str, message_length, key_length, n_rounds, key=Ek[i]))
    A= a.transpose()  # swap rows and columns in y in order to obtain A

    #compute B
    for i in range(ciphertext_length) :         # i-th row of y is the i-th column of B
        # create a string of 32 bit from a numpy array to pass at encryption as u
        q = ''.join([str(elem) for elem in ([str(int(Eu[i][j])) for j in range(Eu[i].shape[0])])])        # i-th row of y is the i-th column of A
        b[i] = str_to_np(encryption(q, message_length, key_length, n_rounds, key=zeros_vec))
    B= b.transpose()  # swap rows and columns in y in order to obtain A
    
    return A,B

# Iterative Binary Search Function
def binary_search(arr, x):
    """
    Returns index of x in array arr if present, otherwise returns -1
    arr: array
    x: element to look for
    """
    low = 0
    high = len(arr) - 1
    mid = 0

    while low <= high:

        mid = (high + low) // 2

        # Check if x is present at mid
        if arr[mid] < x:
            low = mid + 1
        # If x is greater, ignore left half
        elif arr[mid] > x:
            high = mid - 1
        # If x is smaller, ignore right half
        else:
            return mid

    #x is not present in arr
    return -1


def meet_in_the_middle(u, x, n1, n2):
    """
    Performs a "meet in the middle" attack given the plaintext/ciphertext pair (u,x)
    u,x : binary plaintext and correspondent ciphertext
    n1 = cardinality of K'
    n2 = cardinality of K''
    """

    # STEP 1: key' guess
    k1 = np.zeros([n1, 16], dtype=int)  # to store N' random guessing of k'
    k1_ = np.zeros([n1, 1], dtype=int)
    for i in range(n1):
        rand_key = random.getrandbits(16)
        k1[i] = str_to_np(bin(rand_key)[2:].zfill(16))  # random key in bits
        k1_[i] = rand_key

    # STEP 2: cipher guess
    x1 = np.zeros([n1], dtype=int)  # to store N' random guessing of k'
    # x1_ = np.zeros([n1, 1], dtype=int)
    for i in range(n1):
        x1[i] = int(encryption(u.zfill(16), 16, 16, 13, k1[i], task_number=7), 2)  # for better visual idea

    # STEP 3: sort table according to x1
    df1 = pd.DataFrame(k1_, columns=['k1'])
    df1 = pd.concat([df1, pd.DataFrame(x1, columns=['x1'])], axis=1)
    df1.sort_values('x1', inplace=True, ignore_index=True)
    # print(df1)

    # STEP 4: key'' guess
    k2 = np.zeros([n2, 16], dtype=int)  # to store N' random guessing of k'
    k2_ = np.zeros([n2, 1], dtype=int)
    for i in range(n2):
        rand_key = random.getrandbits(16)
        k2[i] = str_to_np(bin(rand_key)[2:].zfill(16))  # random key in bits
        k2_[i] = rand_key

    # STEP 5: plaintext guess
    u2 = np.zeros([n2], dtype=int)  # to store N' random guessing of k'
    for i in range(n2):
        u2[i] = int(dencryption(x.zfill(16), 16, 16, 13, k2[i], task_number=7), 2)  # for better visual idea
    # STEP 6: sort table according to u2
    df2 = pd.DataFrame(k2_, columns=['k2'])
    df2 = pd.concat([df2, pd.DataFrame(u2, columns=['u2'])], axis=1)
    df2.sort_values('u2', inplace=True, ignore_index=True)
    # print(df2)

    # STEP 7: search for  match between df1 and df2
    matches = pd.DataFrame(columns=['k1', 'k2', 'x1', 'u2'])
    count = 0
    for i in range(n1):
        result = binary_search(df2['u2'], df1['x1'][i])
        # matches = matches.append(pd.DataFrame([1,1,2,3], columns=['k1','k2','x1','x2']), ignore_index=True)
        if result != -1:
            # print("match found")
            # matches = matches.append(pd.DataFrame({'k1': df1['k1'][i], 'k2': df2['k2'][result]}, index=[count]))
            matches = matches.append(
                pd.DataFrame({'k1': df1['k1'][i], 'k2': df2['k2'][result], 'x1': df1['x1'][i], 'u2': df2['u2'][result]},
                             index=[count]))  # useful to cheack correctness
            count = count + 1

    return matches[['k1', 'k2']]


def check_task8(data, matches):
    # for each (u,x) pair
    for i in range(data.shape[0]):
        # get plaintext and ciphertext
        u = int(data[0][i], 16)
        x = int(data[1][i], 16)

        # check if all the correspondent matches are actually correct
        for j in range(matches[i].shape[0]):
            # get keys pair
            k1 = int(str(matches[i]['k1'][j]))
            k2 = int(str(matches[i]['k2'][j]))
            k1 = str_to_np(bin(k1)[2:].zfill(16))
            k2 = str_to_np(bin(k2)[2:].zfill(16))

            # encryption
            x1 = encryption(bin(u)[2:].zfill(16), 16, 16, 13, k1, task_number=7)
            x2 = encryption(x1, 16, 16, 13, k2, task_number=7)

            # check if E(k2,(E(k1,u))) = x
            if x2 != bin(x)[2:].zfill(16):
                return -1
    return 0