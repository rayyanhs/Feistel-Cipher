#imports
import random
import numpy as np

#for later
random.seed(42)

def str_to_np(str): #to make code easier to read
    """
    str: binary string
    returns a binary numpy array with str's bits
    """
    return np.array(list(str), dtype=int)


# subkey generation
def generate_roundkeys(key, n_rounds):
    """
    key: 'original' key of Fiestel cipher
    n_rounds: number of rounds
    returns a numpy array of n_rounds round keys
    """
    round_keys = np.zeros([n_rounds, key.shape[0]], dtype=int)  # nparray to store round keys
    lk = key.shape[0]  # key length
    element = np.zeros([lk], dtype=int)

    for i in range(n_rounds):
        for j in range(lk):
            element[j] = key[((5 * (i + 1) + j) % lk)]
        round_keys[i] = element  # save i-th round key

    return round_keys

# task1 round function for block i
def round_function1(ki, yi):
    """
    ki: i-th round key, i.e. the i-th element of the object is
        returned by function generate_roundkeys(binary numpy array)
    yi: y of i-th iteration
    returns wi=f(ki,yi), output of the i-th round function
    """
    l = yi.shape[0]
    wi = np.zeros([l], dtype=int)

    for j in range(l):
        if j < l/2:
            wi[j] = yi[j]^ki[4*(j+1)-4]
        else:
            wi[j] = yi[j]^ki[4*(j+1)-2*l-1]
    return wi


def encryption(u, message_length, key_length, n_rounds, random_key=1, key=None):
    """
    u: binary message (string)
    message_length: lu
    key_length: lk
    n_rounds: number of rounds
    random_key: set to 0 if want to pass your own key, to 1 to generate a random key
    key: customizable key to use (binary numpy array of length key_length)
    """
    u = u.zfill(message_length)
    l = int(message_length / 2)

    # initial split of message u
    y1 = str_to_np(u[:l])
    z1 = str_to_np(u[l:])
    # print("y1={0}\nz1={1}".format(y1,z1))

    # random key
    if random_key == 1:
        key = str_to_np(bin(random.getrandbits(key_length))[2:])  # random key in bits
    elif key.shape[0] < key_length:  # pad key if needed
        key = np.pad(key, (key_length - key.shape[0], 0), 'constant', constant_values=0)

    # get round keys
    round_keys = generate_roundkeys(key, n_rounds)
    # print("round keys:\n", round_keys)

    prova = np.zeros([message_length], dtype=int)
    for i in range(n_rounds):
        wi = round_function1(round_keys[i], y1)
        vi = wi ^ z1  # equivalento to:(wi+z1)%2
        z1 = y1
        y1 = vi

        # to print midterm results
        # np.concatenate((z1,y1), out=prova)
        # print("Round {0}\nki={1}\nwi={2}\n[yi,zi]={3}\n".format(i,round_keys[i],wi,np.packbits(prova)))

    x = np.zeros([message_length], dtype=int)
    np.concatenate((z1, y1), out=x)
    x_bits = np.packbits(x)

    return x_bits, np.array2string(x, precision=int, separator='')[1:-1]

#check task1
k = str_to_np(bin(0x80000000)[2:])
x, x_bin = encryption(bin(0x80000000)[2:], 32, 32, 17, random_key=0, key=k)

print("x binary form: ", x_bin)
print("x packbits: {0}\n".format(x))

#print x in hex notation
for i in range(x.shape[0]):
    print(np.base_repr(x[i], base=16, padding=0))

k = str_to_np(bin(0x001)[2:])
print(k)

k = np.pad(k, (32-k.shape[0], 0), 'constant', constant_values=0)
print(k)
print(k.shape)


def dencryption(x, ciphertext_length, key_length, n_rounds, random_key=1, key=None):
    """
    x: binary ciphertext (string)
    ciphertext_length: lx
    key_length: lk
    n_rounds: number of rounds
    random_key: set to 0 if want to pass your own key, to 1 to generate a random key
    key: customizable key to use (binary numpy array of length key_length)
    """
    x = x.zfill(ciphertext_length)
    l = int(ciphertext_length / 2)

    # initial split of message u
    yn = str_to_np(x[:l])
    vn = str_to_np(x[l:])
    # print("yn={0}\nvn={1}".format(yn,vn))

    # random key
    if random_key == 1:
        key = np.array(list(bin(random.getrandbits(key_length))[2:]), dtype=int)  # random key in bits
    elif key.shape[0] < key_length:  # pad key if needed
        key = np.pad(key, (key_length - key.shape[0], 0), 'constant', constant_values=0)

    # get round keys
    round_keys = generate_roundkeys(key, n_rounds)
    # print("round keys:\n", round_keys)

    prova = np.zeros([ciphertext_length], dtype=int)
    for i in range(n_rounds - 1, -1, -1):
        wi = round_function1(round_keys[i], yn)
        zi = wi ^ vn
        vn = yn
        yn = zi

        # to print midterm results
        # np.concatenate((z1,y1), out=prova)
        # print("Round {0}\nki={1}\nwi={2}\n[yi,zi]={3}\n".format(i,round_keys[i],wi,np.packbits(prova)))

    u = np.zeros([ciphertext_length], dtype=int)
    np.concatenate((vn, yn), out=u)
    u_bits = np.packbits(u)

    return u_bits, np.array2string(u, precision=int, separator='')[1:-1]

#check task2

#encryption parameters
u = 0x80000000
k = str_to_np(bin(0x80000000)[2:])

#encryption
x, x_bin = encryption(bin(u)[2:], 32, 32, 17, random_key=0, key=k)
print("\nciphertext: {0}\n".format(x_bin))

#decryption
u1, u1_bin = dencryption(x_bin, 32, 32, 17, random_key=0, key=k)

#print
print("\ndeciphered message (binary form): ", u1_bin)
print("deciphered message (packbits): {0}\n".format(u1))

#print x in hex notation
for i in range(u1.shape[0]):
    print(np.base_repr(u1[i], base=16, padding=0))