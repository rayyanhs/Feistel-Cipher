import numpy as np
import task1_2 as f
# ----------------
#     TASK 5
# ----------------

def round_function5(ki, yi):
    l = yi.shape[0]
    wi = np.zeros([l], dtype=int)
    for j in range(l):
        if j < l/2:
            wi[j] = yi[j] ^ (ki[4*(j+1)-4] & (yi[2*(j+1)-2] | ki[2*(j+1)-2] | ki[2*(j+1)-1] | ki[4*(j+1)-3]))
        else:
            wi[j] = yi[j] ^ (ki[4*(j+1)-2*l-1] & (ki[4*(j+1)-2*l-2] | ki[2*(j+1)-2] | ki[2*(j+1)-1] | yi[2*(j+1)-l-1]))

    return wi


def encryption(u, message_length, key_length, n_rounds, random_key=1, key=None):

    u = u.zfill(message_length)
    l = int(message_length / 2)

    # initial split of message u
    y1 = f.str_to_np(u[:l])
    z1 = f.str_to_np(u[l:])

    # random key
    if random_key == 1:
        key = f.str_to_np(bin(f.random.getrandbits(key_length))[2:])  # random key in bits
    elif key.shape[0] < key_length:  # pad key if needed
        key = np.pad(key, (key_length - key.shape[0], 0), 'constant', constant_values=0)

    # get round keys
    round_keys = f.generate_roundkeys(key, n_rounds)

    for i in range(n_rounds):
        wi = round_function5(round_keys[i], y1)
        vi = wi ^ z1  # equivalent to:(wi+z1)%2
        z1 = y1
        y1 = vi

    x = np.zeros([message_length], dtype=int)
    np.concatenate((z1, y1), out=x)
    x_bits = np.packbits(x)

    return x_bits, np.array2string(x, precision=int, separator='')[1:-1]


def decryption(x, ciphertext_length, key_length, n_rounds, random_key=1, key=None):

    x = x.zfill(ciphertext_length)
    l = int(ciphertext_length / 2)

    # initial split of message u
    yn = f.str_to_np(x[:l])
    vn = f.str_to_np(x[l:])

    # random key
    if random_key == 1:
        key = np.array(list(bin(f.random.getrandbits(key_length))[2:]), dtype=int)  # random key in bits
    elif key.shape[0] < key_length:  # pad key if needed
        key = np.pad(key, (key_length - key.shape[0], 0), 'constant', constant_values=0)

    # get round keys
    round_keys = f.generate_roundkeys(key, n_rounds)

    for i in range(n_rounds - 1, -1, -1):
        wi = round_function5(round_keys[i], yn)
        zi = wi ^ vn
        vn = yn
        yn = zi

    u = np.zeros([ciphertext_length], dtype=int)
    np.concatenate((vn, yn), out=u)
    u_bits = np.packbits(u)

    return u_bits, np.array2string(u, precision=int, separator='')[1:-1]


# encryption parameters
u = 0x12345678
k = np.array(list(bin(0x87654321)[2:]), dtype=int)
# encryption
x, x_bin = encryption(bin(u)[2:], 32, 32, 5, random_key=0, key=k)
print("\nciphered message (binary form): ", x_bin)
print("ciphered message (packbits): {0}".format(x))

for i in range(x.shape[0]):
    print(np.base_repr(x[i], base=16, padding=0))

# decryption
u1, u1_bin = decryption(x_bin, 32, 32, 5, random_key=0, key=k)

# print
print("\ndeciphered message (binary form): ", u1_bin)
print("deciphered message (packbits): {0}\n".format(u1))

# print x in hex notation
for i in range(u1.shape[0]):
    print(np.base_repr(u1[i], base=16, padding=0))