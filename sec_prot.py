
import sys
import numpy as np
import utils
import psutil
import os
import ast

import time
from Crypto.Random import get_random_bytes
import json
import base64
import random


# negacyclic multiplication
def negacyclic_mul(a, b):

    n = len(a)
    conv = np.convolve(a, b)   # length 2n-1
    conv = np.pad(conv, (0, 1)) #padding

    # X^n = -1 reduction
    res = conv[:n] - conv[n:2*n]

    return res % q # modular reduction


# Xsk:uniform distribution over ternary polynomials in R: R_2
def ternary_uniform_distribution(size):
    # A ternary polynomial can have only -1, 0 or 1 as coefficients
    return np.random.choice([-1, 0, 1], size = size).astype(np.int64)

#Xe: gaussian distibution in D_sigma_q
def gaussian_distribution( standard_deviation, size):
    value = np.random.normal( 0 , scale = standard_deviation, size = size)
    return np.mod(np.rint(value), q).astype(np.int64)

# used to generate random polynomials in Zt or Rq
def random_polynomial(low, high, size):
    return np.random.randint(low = low, high = high , size = size, dtype=np.int64)


# Algo 1: setup algorithm: used to generate KC FE sk and KC FE pk
def set_up(pp):
    global  a
    n,m, q = pp
    compute_mem_time(0,"setup")
    sk = [] # KC_FE_sk
    pk = [] # KC_FE_pk = (KC_FE_pk1,...., KC_FE_pkm)

    a = random_polynomial(low = 0, high = q , size = n) # 𝑎 polynomial sampled randomly in R_q: polynomials of degree at most n-1 with coefficients from the ring ℤq
    e_alpha = gaussian_distribution(sigma, n)  # Sampled from D_q,o
    alpha_in = ternary_uniform_distribution(n) # Ternary polynomial sampled in R_2
    k_alpha_in = (negacyclic_mul(a, alpha_in) + t* e_alpha).astype(np.int64) # k_𝛼 = [a ·𝛼 + 𝑡 *𝑒_𝛼]_q

    for i in range(m): # loop over message space
        sk_i = ternary_uniform_distribution(n) # KC_FE_sk= (KC_FE_sk1,...., KC_FE_skm) ; a ternary polynomial sampled randomly in R_2

        e_0_i = gaussian_distribution(sigma, n) #e0, ..., e0m sampled from [D_(q,o)]^ m

        bi = (-negacyclic_mul(a, sk_i) + t *e_0_i) #  𝑏𝑖 = [−𝑎 · KC_FE_sk𝑖 + 𝑡 𝑒_(0,𝑖) ]

        pk.append((bi,a))
        sk.append(sk_i)

    compute_mem_time(1,"setup")
    return (sk, pk, k_alpha_in)



#Algo 3: Encryption algotithm
def enc(KC_FE_pki, xi, alpha):
    global precomp_a_alpha
    
    #convert xi value to a polynomial
    x_polynomial = np.zeros(n, dtype = np.int64)
    x_polynomial[0] = xi % t 

    u = ternary_uniform_distribution(n) # sample u from R_2

    e1 = gaussian_distribution(sigma, n) # sample e1 from D_q,sigma

    e2 = gaussian_distribution(sigma, n) # sample e2 from D_q,sigma

    c1 = np.mod((negacyclic_mul(KC_FE_pki[0], alpha) + t * e1 + negacyclic_mul(u, x_polynomial)), q).astype(np.int64) # c1 ← [𝑏𝑖· 𝛼 + 𝑡 𝑒1 + 𝑢 · 𝑥]_q

    c2 = np.mod((precomp_a_alpha + t * e2 - u), q).astype(np.int64) # c2 = [𝑎 · 𝛼 + 𝑡 𝑒2 − 𝑢]_q
    return (c1, c2)


# Algo 3: key derivation, to generate the decryption key
def Kder(KC_FE_sk, k_alpha, v):
    
    compute_mem_time(0,"kdev")
    # convert v value to a polynomial
    v_polynomial = np.zeros(n, dtype = np.int64)
    v_polynomial[0] = v % t

    dk_alpha_v = []
    e3 = np.mod(gaussian_distribution(sigma, n),q) # sample e3 from D_q,sigma
    for i in range(m):
        ki =  np.mod(negacyclic_mul(k_alpha , (KC_FE_sk[i] - v_polynomial)) + t * e3 , q) # ki =  k𝛼 · (sk𝑖 − 𝑣) + 𝑡 𝑒3
        dk_alpha_v.append(ki.astype(np.int64)) # append dk𝛼,v

    compute_mem_time(1,"kdev")
    return dk_alpha_v

# Algo 4: decryption using functional decryption key dk_alpha_v
def dec(dk_alpha_v, all_cx):
    global v
    compute_mem_time(0, "dec")
    v_polynomial = np.zeros(n, dtype = np.int64) # convert value v to a polynomial
    v_polynomial[0] = v % t # v should be in Z_t
    y = []

    for i in range(m):
        c1, c2 = all_cx[i] # Parse (c1, c2) ← c𝑥i
        yi = np.mod(dk_alpha_v[i] + c1 +  negacyclic_mul(v_polynomial , c2),q) # yi = c1 + ki + v *c2
        yi = np.mod(yi , t) # reduce 𝑦𝑖 ∈ [0, 𝑡)
        yi = np.where(yi> q // 2, yi - q, yi).astype(np.int64) # reduce 𝑦𝑖 ∈ (-q/2, q/2]
    
        if all(val == 0 for val in yi): # match if result is [0, 0, ....., 0]
            y.append(1)
        else:
            y.append(0)
        
    compute_mem_time(1,"dec")
    return y

# Algo 5: generate the update token
def TokGen(pk, alpha, alpha_out):
    compute_mem_time(0,"tk_gen")
    
    a = pk[0][1] #extract a
    
    #compute 𝛼𝑜𝑢𝑡 − 𝛼𝑖𝑛
    diff_out_in = (alpha_out - alpha) %q
    #pre compute (𝛼𝑜𝑢𝑡 − 𝛼𝑖𝑛)* a
    diff_a = negacyclic_mul(diff_out_in,  a)
    
    update_token = []
    for KC_FE_pki in pk:
        bi,_ = KC_FE_pki
        e_tk = [gaussian_distribution(sigma, n) for _ in range(2)] #sampled from D²_q,sigma

        # update_token = 𝑡 * etk + pk · (𝛼𝑜𝑢𝑡 − 𝛼𝑖𝑛) 
        token_0 = np.mod((t * e_tk[0] + negacyclic_mul(diff_out_in, bi)), q).astype(np.int64) # compute (𝑡 * etk + (𝛼𝑜𝑢𝑡 − 𝛼𝑖𝑛)* bi)% q
        token_1 = np.mod((t * e_tk[1] + diff_a), q).astype(np.int64) # compute (𝑡 * etk + (𝛼𝑜𝑢𝑡 − 𝛼𝑖𝑛)* a)% q

        update_token.append((token_0, token_1)) # merge results & append it to the update token 

    compute_mem_time(1,"tk_gen")
    return update_token


#update ciphertext's label using update token: Algo 6
def upd(update_token, c_alpha_in):
    compute_mem_time(0,"upd")
    
    c_alpha_out = [0] * m 
    for i in range(m):
        c0_in, c1_in = c_alpha_in[i]  # extract ciphertext 𝑐_𝛼𝑖𝑛 encrypted under alpha_in components
        token_0, token_1 = update_token[i] # extract update token components
  
        #compute update token + ciphertext 𝑐_𝛼𝑖𝑛 encrypted under alpha_in
        c_alpha_out[i] = ((token_0 + c0_in), (token_1 + c1_in)) 
        
    compute_mem_time(1,"upd")
    return c_alpha_out



# used by KC to save initial data owner data
def register_data_owner(m_j, do_pk):

    if utils.verify(m_j, do_pk):
        
        _, dic, _ = m_j
        
        dic = json.loads(dic.decode()) # convert dic back to python object
        
        # extract dictionary values
        encrypted_key = base64.b64decode(dic["aes_key"])
        c_alpha_j = base64.b64decode(dic["c_alpha_j"])
        nonce = base64.b64decode(dic["nonce"])
        tag = base64.b64decode(dic["tag"])
        
        #decrypt AES key using RSA
        key = utils.PKE_dec(KC_PKE_sk, encrypted_key)
        
        #decrypt c_alpha_j using AES
        decrypted_c_alpha_j = utils.aes_decrypt(key, c_alpha_j, tag, nonce)
        
        if decrypted_c_alpha_j:
            
            # extract and convert back j and alphaj to their initial format
            j = int.from_bytes(decrypted_c_alpha_j[:4])
            alpha_j = np.frombuffer(decrypted_c_alpha_j[4:], dtype=np.int16)
     
            if j == register_do: 
            
                m1 = utils.generate_message(KC_PKE_sk, KC_FE_pk)

                # KC saves do data
                KC_data_owner_data[register_do] = { # implicitely j is saved: j == register_do
                    "alpha_j": alpha_j, 
                    "do_pk": do_pk,
                    "cx_j": [],
                    "do_k_alpha": []
                }

                return m1

    sys.exit("Error: Set Up Invalid Communication")

# used by KC to save data owner ciphertext
def kc_save_cxj(m4, do_id, dataset_size):

    if do_id not in KC_data_owner_data:
        sys.exit("Data Owner Not Saved in KC System")

    do_pk = KC_data_owner_data[do_id]["do_pk"]

    if utils.verify(m4, do_pk): # verifies validity of m4 message
        _, cjx, _ = m4 #extracts ciphertext
        KC_data_owner_data[do_id]["cx_j"] = cjx # store do ciphertext
        do_k_alpha = get_k_alpha(KC_data_owner_data[do_id]["alpha_j"])
        KC_data_owner_data[do_id]["do_k_alpha"]  = do_k_alpha # compute do's k_alpha and save it
        
        # create a dataset and write to it the results/ just to view the results
        kc_dataset = "KC"
        file_path = f"{kc_dataset}/{dataset_size}/do_{do_id +1}.txt"
        os.makedirs(f"{kc_dataset}/{dataset_size}", exist_ok = True)
        with open(file_path, "w") as f:
            f.write(f"{cjx}\n")

    else:
        sys.exit("Error: Encryption Invalid Communication")

#used by data owners to store their own data
def create_data_owner(xj, dataset_size):
    global register_do, precomp_a_alpha # register_do = j
    alpha_j = ternary_uniform_distribution(n)  # generate a personal do identifier

    do_sk, do_pk = utils.PKE_gen() # generate do's public key encryption/ signature key pair

    # data owner
    c_alpha_j = register_do.to_bytes(4, "big") + alpha_j.astype(np.int16).tobytes()  # append do_id to do's identifier
    
    # generate a random AES key of 32 bytes
    aes_key = get_random_bytes(32)
    
    #encrypt c_alpha_j using AES
    (c_alpha_j, tag, nonce) = utils.aes_encrypt(aes_key, c_alpha_j)
   
    # encrypt AES Key using RSA
    encrypted_key = utils.PKE_enc(KC_PKE_pk, aes_key)  
    
    #build a dictionary of all data merged
    c_alpha_j_dic = {
        "c_alpha_j": base64.b64encode(c_alpha_j).decode(),
        "nonce":base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "aes_key": base64.b64encode(encrypted_key).decode()
    }
    
    c_alpha_j_dic = json.dumps(c_alpha_j_dic).encode() # convert dic to JSON string
    
    mj = utils.generate_message(do_sk, c_alpha_j_dic) # generate message mj

    m1 = register_data_owner(mj, do_pk) # register in KC system by sending to it mj

    if utils.verify(m1, KC_PKE_pk): # do verifies m1 validity
        _, KC_FE_pk, _ = m1 #extract KC's functional encryption key
        all_cx_j = []

        #Encryption: data owner encrypting their plaintext
        compute_mem_time(0,"enc")
        precomp_a_alpha = negacyclic_mul(KC_FE_pk[0][1], alpha_j)# a * alpha
        for idx in range(m): # loop over message space
            cxi = enc(KC_FE_pk[idx], xj[idx], alpha_j)
            time.perf_counter()
            all_cx_j.append(cxi)
        compute_mem_time(1,"enc")
        
        m4 = utils.generate_message(do_sk , all_cx_j) # generate message m4
        
        
        data_owners [register_do] = {  # save do data
            "x_j": xj,
            "alpha_j": alpha_j,
            "KC_FE_pk": KC_FE_pk,
            # "do_k_alpha": do_k_alpha,
            "cx_j": all_cx_j,
            "do_sk": do_sk,
            "do_pk": do_pk
        }

        kc_save_cxj(m4, register_do, dataset_size) #send m4 to KC
        register_do  = register_do + 1
    else:
        sys.exit("Error: Set Up Invalid Communication")



# KC registering the user
def register_user(m2, user_pk):
    global KC_users_data
    if utils.verify(m2, user_pk): #KC verifies m2
        _, reg, _ = m2 # KC extracts the registration request
        dk_j_v = []
        for value in reg:
            j = value[0] # extract do_id

            if j < 0 or j> number_do: #check if do exists
                sys.exit(f"Error: No Registred Data Owner with ID {j +1}")

            v = value[1] # extract v value
            k_alpha_used = KC_data_owner_data[j]["do_k_alpha"] 
            dk = Kder(KC_FE_sk, k_alpha_used, v) # extract derivation key
            dk_j_v.append(dk)

        KC_users_data[user_number] = {
            "is_valid": 1, # set user to valid and hence allowed to access that specific do data
            "user_pk": user_pk
        }

        return utils.generate_message(KC_PKE_sk, dk_j_v) # returns message m3

    sys.exit("Error: User Registration Invalid Communication")

# used by users to store their own data
def set_user_k_data(m3, reg, user_PKE_sk , user_PKE_pk):
    global user_number, users

    if user_number not in users:# create entry for user, if it does not exist
        users[user_number] = {"j": [], "v": [] , "dk_j_v": [], "PKE_sk": user_PKE_sk, "PKE_pk": user_PKE_pk}

    if utils.verify(m3, KC_PKE_pk): # verify message m3 validity
        _, dk_j_v, _ = m3 # extract derivated key

        for i, value in enumerate(reg): # append users data
            users [user_number]["j"].append(value[0])
            users [user_number]["v"].append(value[1])
            users [user_number]["dk_j_v"].append(dk_j_v[i])

    else:
        sys.exit("Error: User Registration Invalid Communication")


# extract KC saved data owner's ciphertext based on user request
def get_data_owner_data(req_id):
    if req_id in KC_data_owner_data:
        return KC_data_owner_data[req_id]["cx_j"]
    sys.exit(f"Data Owner {req_id} Not Saved in KC System")

#generate k_alpha based on alpha
def get_k_alpha(alpha):
    e_alpha = gaussian_distribution(sigma, n)  # sampled from D_q,o
    return np.mod(negacyclic_mul(a, alpha) + t* e_alpha, q).astype(np.int64)


# User Registration
def user_registration(reg):

    user_PKE_sk , user_PKE_pk = utils.PKE_gen() #generate user's PKE key pair
    m2 = utils.generate_message(user_PKE_sk, reg) # generate m2 message
    m3 = register_user(m2, user_PKE_pk) #send m2 to KC 

    set_user_k_data(m3, reg, user_PKE_sk , user_PKE_pk) #user storing data


#Data Access based on user request
def data_access(m5, user_id, is_updated ):
    global v
    if utils.verify(m5, KC_users_data[user_id]["user_pk"]): #verified by KC

        _, req_id, _ = m5

        do_cxj = get_data_owner_data(req_id) #extract data owner ciphertext
        output = f"{decryption_folder}/User_{user_id + 1}"
        os.makedirs(output, exist_ok = True)

        m6 = utils.generate_message(KC_PKE_sk, do_cxj) # generated by KC

        if utils.verify(m6, KC_PKE_pk): # verified by the user
            _, cxj, _ = m6
            for i, value in enumerate(users[user_id]["j"]):
                
                if value == req_id :
                    dk_j_v = users[user_id]["dk_j_v"][i] # extract decryption keys
                    v = users[user_id]["v"][i]    # extract v chosen by the user

                    # create a folder and write to it the results
                    file_path = f"{output}/do_{req_id + 1}.txt"
                    decryption_result = dec(dk_j_v, cxj)
                                
                    with open(file_path, "a") as f:
                        if is_updated :
                            f.write(f"\n\nData Access After Label Update")
        
                        f.write(f"\nMatch For Value = {v} % {t} = {v % t}: \n")
                        for value in decryption_result:
                            if value == 1:
                                f.write("1")
                            else:
                                f.write("_")
        else:
            sys.exit("Error: Data Access Invalid Communication")
    else:
        sys.exit("Error: Data Access Invalid Communication")


# update a data owner label
def update(do_id):
    global KC_users_data 
    alpha_out = ternary_uniform_distribution(n) # generate a new alpha token
    k_alpha_out = get_k_alpha(alpha_out) # derive the new derivation key
    alpha_in = KC_data_owner_data[do_id]["alpha_j"] #get the initial data owner label
    
    updated_token = TokGen(KC_FE_pk, alpha_in, alpha_out) # call tokengen to get the updated token
    
    #update a specific data owners ciphertext 
    KC_data_owner_data[do_id]["cx_j"] = upd(updated_token, KC_data_owner_data[do_id]["cx_j"])
    for user_id, value in users.items():
        if KC_users_data[user_id]["is_valid"] == 1: # only for valid users
            if do_id in value["j"]:
                for i, _ in enumerate(value["j"]):
                    if value["j"][i] == do_id: # KC Should send to valid users only, the new kdev to be used
                        v = value["v"][i]  # extract the value v defined by the user
                        kdev = Kder(KC_FE_sk, k_alpha_out, v) # compute the new kdev
                        value["dk_j_v"][i] = kdev #update stored user dkjv
    
    #update KC saved data as well as data owner's data                          
    KC_data_owner_data[do_id]["alpha_j"] = alpha_out # this is the new alpha_in for this do
    KC_data_owner_data[do_id]["do_k_alpha"] = k_alpha_out #update kc's stored do_k_alpha
    data_owners [do_id]["alpha_j"] = alpha_out
    print(f"\n ******************** KC Token Updated of Data Owner {do_id +1} ********************\n")
    

# function to compute used memory and total execution time of # functions
process = psutil.Process(os.getpid())
mem_before = 0
start_time = 0
def compute_mem_time(index, func_type):
    global enc_mem, kdev_mem, upd_mem, tk_gen_mem, setup_mem, mem_before
    global setup_time, tk_gen_time, upd_time, dec_time, kdev_time, enc_time, start_time
    if index == 0:
        mem_before = process.memory_info().rss
        start_time = time.perf_counter()
    else:
        mem_after = process.memory_info().rss
        mem_computed = (mem_after - mem_before) / 1024
        end_time = time.perf_counter()
        time_computed = (end_time - start_time) 
    
        if func_type == "enc":
            enc_mem.append(mem_computed)
            enc_time.append(time_computed)
            
        elif func_type == "kdev":
            kdev_mem.append(mem_computed)
            kdev_time.append(time_computed)
            
        elif func_type == "dec":
            dec_mem.append(mem_computed)
            dec_time.append(time_computed)
            
        elif func_type == "upd":
            upd_mem.append(mem_computed)
            upd_time.append(time_computed)
            
        elif func_type == "tk_gen":
            tk_gen_mem.append(mem_computed)
            tk_gen_time.append(time_computed)
            
        elif func_type == "setup":
            setup_mem = (mem_computed)
            setup_time = (time_computed)
            
            

# create a dataset of random values in Zt       
def create_dataset():
    for i, vec_size in enumerate(m_values):
        for do in range(number_do):
            x = np.mod(random_polynomial(low = 0, high = t, size = vec_size), t).tolist()  # generate random values in Zt of size 100, 200, 500 or 1000
            file_path = f"{do_dataset}/{size[i]}/do_{do + 1}.txt" # do+1; counter visisble to end users starts at 1
            os.makedirs(f"{do_dataset}/{size[i]}", exist_ok = True)  # create folder if it does not exist
            with open(file_path, "w") as f:
                f.write(f"{x}\n")

# revoke user access after 1 run 
def revoke_user_access(user_id):
    global KC_users_data
    KC_users_data[user_id]["is_valid"] = 0 # set user_validity to 0, no longer valid


def main():
    global m, n, q, KC_FE_sk, KC_FE_pk, user_number
    create_dataset() # create an arbitrary dataset based on the paper requirements

    # End User Interaction for code parameters setting
    m = int(input("Please Choose The Vector Size (100 - 200 - 500 - 1000) or 0 to Exit\n"))
    while m not in m_values and m!= 0:
        print("Error: Please Enter 100, 200, 500, 1000, or 0")
        m = int(input("Please Choose The Vector Size (100 - 200 - 500 - 1000) or 0 to Exit\n"))

    # set paramaeters based on vector size
    if m == 0:
        sys.exit()

    elif m == 100:
        q = pow(2,39)
        n = pow(2,12)

    elif m == 200:
        q = pow(2,42)
        n = pow(2,13)

    elif m == 500:
        q = pow(2,43)
        n = pow(2,14)

    elif m == 1000:
        q = pow(2,47)
        n = pow(2,15)

    chosen_size = size[m_values.index(m)]

    pp = n,m, q
    # KC set up: generate KC's functional encryption key pair, alpha_in and derivation key k_alpha_in
    set_up_result = set_up(pp)

    KC_FE_sk, KC_FE_pk, k_alpha_in = set_up_result
  
    # register data owners
    for num in range(number_do):
        file_path = f"{do_dataset}/{chosen_size}/do_{num +1}.txt"
        with open(file_path, "r") as f:
            xj = ast.literal_eval(f.read()) # to read array of integers
        create_data_owner(xj, chosen_size)


    add_new_user = 1

    while add_new_user:
        reg = []
        num_data = -1
        print(f"\n ___________________________ User {user_number +1}: ___________________________\n")
        while num_data <= 0 or num_data> number_do:
            num_data = int(input(f" Please Enter Total Number of Data To be Accessed, Min: 1, Max: {number_do} "))
            
        for num in range(num_data):
            while True:
                    val = input(f"{num+1}- Please Enter (Data Owner ID, Value to Look For): ")
                    if "," not in val:
                        print("Error: Input Should Be of Shape Integer, Integer")
                    else:
                        try:
                            val = [int(x.strip()) for x in val.split(",")]
                            break
                        except ValueError:
                            print("Error: Input Should Be of Shape Integer, Integer")
            j = val[0] - 1  # extract data owner id from end user input
            v = val[1] # extract value v from end user input
            reg.append((j,v))  # form the reg request
        user_registration(reg)
        
        print("\nUser Registered Successfully!!\n")
        
        #Data Access Phase
        all_j_values = [j for j, _ in reg]
        loop = 1
        while loop:
            req_id = int(input(f" Please Enter Data Owner's Id To be Accessed, 0 to Stop "))
            if req_id == 0:
                loop = 0
            elif (req_id - 1) not in all_j_values:
                print("Error: You Are Not Allowed to Access This Data Owner's Data ")
            else:
                m5 = utils.generate_message(users[user_number]["PKE_sk"], req_id - 1)
                data_access(m5, user_number, 0)
            

        # randomly update a data owner's label alpha and then access it to show it's working; I choose a do_id randomly from reg
        do_to_update = random.choice(all_j_values)
        update(do_to_update)
        m5 = utils.generate_message(users[user_number]["PKE_sk"], do_to_update)
        data_access(m5, user_number, 1 )

        revoke_user_access(user_number) # revoke access to user, user can no longer access the requested data

        user_number += 1
        res = input(f"\nDo You Want To Register A New User (If yes, enter 1): ")
        if res!= "1":
            add_new_user = 0

# to store memory usage computed values
kdev_mem = []
enc_mem = []
dec_mem = []
upd_mem = []
tk_gen_mem = []
setup_mem = 0

# to store execution time computed values
kdev_time = []
enc_time = []
dec_time = []
upd_time = []
tk_gen_time = []
setup_time = 0



data_owners = {} # used by data owners to track their personal data
KC_data_owner_data = {} # used by KC to track registred data owners data
KC_users_data = {} # used by KC to track user data
users = {} # used by users to track their own data
user_number = 0  #used by the system to count all registred users

register_do = 0 # used by the system to count all registred data owners

KC_FE_sk = [] # KC functional encryption private key
KC_FE_pk = [] # KC functional encryption public key

sigma = 3.0 # standard derivation

KC_PKE_sk , KC_PKE_pk = utils.PKE_gen() #generate KC keypairs for encryption/ decryption and signatures

do_dataset = "DataOwner"  # Define data owners folder
decryption_folder = "Decryption_Results" # Define decryption folder which will be visible to users only
m_values = [100, 200, 500, 1000] # defined m values (input vector sizes) by the paper
size = ["Small", "Medium", "Large", "XLarge"] # parameter sizes defined by the paper

number_do = 10 #set the data owner number for testing purposes only to generate a dataset to test our code

a = []

m = 0
q = 0
n = 0
t = pow(2, 16)

main()


# print results
    # compute mean of execution times and extract peak of memory usage
idx_size = m_values.index(m)
chosen_size = size[idx_size][0]
print("\nComponent\t\tTime\t\tMemory Allocations")
print("           \t\t(s/op)\t\t(KB/op)")
print("__________________________________________________________")
print(f"\t\t\tB{idx_size+1} with parameter set {chosen_size}")
print("__________________________________________________________")
print(f"Set Up   \t\t{setup_time:.3f}\t\t{setup_mem:.3f}")
print(f"Encryption\t\t{np.mean(enc_time):.3f}\t\t{np.max(enc_mem):.3f}")
print(f"Key Derivation\t\t{np.mean(kdev_time):.3f}\t\t{np.max(dec_mem):.3f}")
print(f"Decryption\t\t{np.mean(dec_time):.3f}\t\t{np.max(upd_time):.3f}")
print(f"Token Generation \t{np.mean(tk_gen_time):.3f}\t\t{np.max(tk_gen_mem):.3f}")
print(f"Update    \t\t{np.mean(upd_time):.3f}\t\t{np.max(upd_mem):.3f}")


