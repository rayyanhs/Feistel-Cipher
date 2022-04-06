import numpy as np

#----------------
#     TASK 7
#----------------

def generate_roundkeys(key, n_rounds):
    
    round_keys = np.zeros([n_rounds, key.shape[0]], dtype=int)
    lk = key.shape[0]
    element = np.zeros([lk], dtype=int)
    
    for i in range(n_rounds):
        for j in range(lk):
            element[j] = key[((5*(i+1)+j)%lk)]
        round_keys[i] = element 
        
    return round_keys

def round_function7(ki, yi):
    
    l = yi.shape[0]
    wi = np.zeros([l], dtype=int)

    for j in range(l): 
        if j < l/2:
            wi[j] = (yi[j]&ki[2*j-1])|(yi[2*j-1]&ki[2*j])|ki[4*j]
            
        else:
            wi[j] = (yi[j]&ki[2*j-1])|(ki[4*j-2*l-1]&ki[2*j])|yi[2*j-l]
           
    return wi

def encryption(u, key_length, n_rounds, key):
    
    l = int(key_length/2)
    #l = int(len(u)/2)
    

    y1 = np.array(list(u[:l]), dtype=int)
    z1 = np.array(list(u[l:]), dtype=int)
    
    round_keys = generate_roundkeys(key, n_rounds)
    
    for i in range(n_rounds):
        wi = round_function7(round_keys[i], y1)
        vi = wi^z1 #equivalent to:(wi+z1)%2
        z1 = y1
        y1 = vi
              
    x = np.zeros([len(u)], dtype=int)
    np.concatenate((z1, y1), out=x)
    x_bits = np.packbits(x)
    
    return x_bits, np.array2string(x, precision=int, separator='')[1:-1]
     
def decryption(x, key_length, n_rounds, key):
    
    l = int(key_length/2)
    #l = int(len(x)/2)
    
    yn = np.array(list(x[:l]), dtype=int)
    vn = np.array(list(x[l:]), dtype=int)
  
    round_keys = generate_roundkeys(key, n_rounds)
    
    for i in range(n_rounds-1, -1, -1):
        wi = round_function7(round_keys[i], yn)
        zi = wi^vn 
        vn = yn
        yn = zi
         
    u = np.zeros([len(x)], dtype=int)
    np.concatenate((vn, yn), out=u)
    u_bits = np.packbits(u)
    
    return u_bits, np.array2string(u, precision=int, separator='')[1:-1]

#encryption parameters
u = 0x0000
k = np.array(list(bin(0x369C)[2:].zfill(16)), dtype=int)
#encryption
x, x_bin = encryption(bin(u)[2:].zfill(16), 16, 13, key=k)
print("\nciphered message (binary form): ", x_bin)
print("ciphered message (packbits): {0}".format(x))

for i in range(x.shape[0]):
    print(np.base_repr(x[i], base=16, padding=0))  
    
#decryption
u1, u1_bin = decryption(x_bin, 16, 13, key=k)

#print
print("\ndeciphered message (binary form): ", u1_bin)
print("deciphered message (packbits): {0}\n".format(u1))

#print x in hex notation
for i in range(u1.shape[0]):
    print(np.base_repr(u1[i], base=16, padding=0))         
    
