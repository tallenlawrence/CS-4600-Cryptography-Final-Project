#################[TWO FISH BLOCK CIPHER]#################################################################################################################################
#Name: Tallen Lawrence
#Class: CS:4660 Cryptography
#
#Description: Implementation of the 128-bit TwoFish Block Cipher, utilizes key size of 128-bit
#Use: When ran, the program will prompt the user whether they would like to encrypt or decrypt a message. The user will then be asked if they'd like to enter a
# key and plaintext/ciphertext manually, or have these inputs randomly generated for them. If the user selected manual entry, the user will then be prompted if they are
# entering a binary or hex 128-bit value for their key and plaintext/ciphertext. Program returns all subkeys, and the final cipher/plaintext 
#Libraries Used: Random
#Ai use: Claude and Gemini were used for converting hex matrices of the RS and MDS matrices, as well as the q permutation t-tables into binary representation, as well as
# for debugging and algorithm comprehension. No code used was generated with AI. 
#########################################################################################################################################################################

#Libraries
import random


def main():

    # testplaintext = "01111110010011100000001010111101101011101110101110001010111001101101011101001011101110001101111010110110111111101010011001111110"
    # testkey = "10111111001001101111011111001100101100010101010000000011001001001111100110011110001100001100101011011110101000011001110111001010"
    # testplaintext = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    # testkey = hexToBinary("FF000000000000000000000000000000")
    # testkey = testplaintext
    # testkey = hexToBinary("00000000000000000000000000000001")

   #########[Input Loop]###########
   #prompts user for mode (encryption/decryption), whether they'd like to manual enter or have text/keys generated for them, 
   # and if they are manually entering, whether they're using hex or binary. Handles misinputs.

    while(True):
        
            mode = input("Welcome to TWOFISH! Enter (e) to encrypt a message, (d) to decrypt a message: ").lower()
            if not(mode == 'e' or mode == 'd'):
                print("Invalid input. Please enter (e) to encrypt or (d) to decrypt.")
                continue
            if mode == 'e':
                choice = input("Enter (m) to manually enter 128-bit plaintext and key, or (g) to generate random plaintext and key: ").lower()
                if not(choice == 'm' or choice == 'g'):
                    print("Invalid input. Please enter (m) to manually enter plaintext and key, or (g) to generate random plaintext and key.")
                    continue
            if mode == 'd':
                choice = input("Enter (m) to manually enter 128-bit ciphertext and key, or (g) to generate random ciphertext and key: ").lower()
                if not(choice == 'm' or choice == 'g'):
                    print("Invalid input. Please enter (m) to manually enter ciphertext and key, or (g) to generate random ciphertext and key.")
                    continue
                    
            if choice == 'g':
                plaintext = generate128BitNumber()
                key = generate128BitNumber()
                break

            if choice == 'm':
                base = input("Enter (h) for hexadecimal input or (b) for binary input: ").lower()
                if not(base == 'h' or base == 'b'):
                    print("Invalid input. Please enter (h) for hexadecimal input or (b) for binary input.")
                    continue
                if base == 'h':
                    plaintext = hexToBinary(input("Enter 128-bit plaintext in hexadecimal: "))
                    key = hexToBinary(input("Enter 128-bit key in hexadecimal: "))
                    if len(plaintext) != 128 or len(key) != 128:
                        print("Invalid input. Please enter 128-bit plaintext and key.")
                        continue
                if base == 'b':
                    plaintext = input("Enter 128-bit plaintext in binary: ")
                    key = input("Enter 128-bit key in binary: ")
                    if len(plaintext) != 128 or len(key) != 128 or not all(char in '01' for char in plaintext) or not all(char in '01' for char in key):
                        print("Invalid input. Please enter 128-bit plaintext and key consisting of only 0s and 1s.")
                        continue
            break

    if mode == 'e':
        print("plaintext:", binaryToHexadecimal(plaintext))
        print("key:", binaryToHexadecimal(key))
        encrypted = encrypt(plaintext, key)
        print("ciphertext:", binaryToHexadecimal(encrypted))
    if mode == 'd':
        print("ciphertext:", binaryToHexadecimal(plaintext))
        print("key:", binaryToHexadecimal(key))
        decrypted = decrypt(plaintext, key)
        print("plaintext:", binaryToHexadecimal(decrypted))

    # encrypted = encrypt(testplaintext, testkey)
    # print("ciphertext:" , binaryToHexadecimal(encrypted))
  
    # decrypted = decrypt(encrypted, testkey)
    # print("plaintext:",  binaryToHexadecimal(decrypted))

  

##########[Key Schedule/Generation]#############
#-generates subkeys s0, s1 (used for s-box in function g)
#-generates subkeys k0-k39 (used in function f)

def keySchedule(k):
    
    m = [k[:8], k[8:16], k[16:24], k[24:32], k[32:40], k[40:48], k[48:56], k[56:64],
        k[64:72], k[72:80], k[80:88], k[88:96], k[96:104], k[104:112], k[112:120], k[120:128]] #split 128-bit key into 8-bit m values
    
    m0 = m[0] + m[1] + m[2] + m[3]
    m1 = m[4] + m[5] + m[6] + m[7]
    m2 = m[8] + m[9] + m[10] + m[11]
    m3 = m[12] + m[13] + m[14] + m[15]

    mEven = [m0, m2] #Me = even m values
    mOdd = [m1, m3] #Mo = odd m values

    
     #Reed-Solomon (RS) matrix
    RS = [
  ["00000001", "10100100", "01010101", "10000111", "01011010", "01011000", "11011011", "10011110"],
  ["10100100", "01010110", "10000010", "11110011", "00011110", "11000110", "01101000", "11100101"],
  ["00000010", "10100001", "11111100", "11000001", "01000111", "10101110", "00111101", "00011001"],
  ["10100100", "01010101", "10000111", "01011010", "01011000", "11011011", "10011110", "00000011"]
]
    
    #subkey S generation (s0 = RS x [m0-m7], s1 = RS x [m8-15] (4x8 * 8x1 matrix multiplication))
   
    s0bytes = []
    s1bytes = []
    for row in range(len(RS)):
        s0bytes.append(rowMult(m[:8], RS[row], "rs"))
        s1bytes.append(rowMult(m[8:16], RS[row], "rs"))

    s0 = s0bytes[3] + s0bytes[2] + s0bytes[1] + s0bytes[0]
    s1 = s1bytes[3] + s1bytes[2] + s1bytes[1] + s1bytes[0]

    # print(s0)
    # print(s1)
    #subkey K generation (function h)
    subkeys = []
    for i in range(20): #20 rounds (40 subkeys)
            p = "00000001000000010000000100000001" #p = 2^24 + 2^16 + 2^8 + 2^0
            
            input2ip = decimalToBinary((2*i*(binaryToDecimal(p))),32) #2ip 
            input2ip_plus_1 = decimalToBinary(((2*i+1)*(binaryToDecimal(p))),32) #(2i + 1)p

            Ai = h(input2ip, mEven) #Ai = h(2ip, Me), where Me = [M0, M2]
            Bi = h(input2ip_plus_1, mOdd) #Bi = ROL(h(2i + 1)p, Mo) 8), where Me = [M0, M2]
            
            for _ in range(8): #ROL8
                Bi = ROL(Bi)
            k2i, k2ip = PHT(Ai, Bi) #k2i = (Ai + Bi)mod2^32, #k2i+1 = 
         
            #ROL9
            for x in range(9):
                k2ip = ROL(k2ip)
           
            #add subkeys to subkey list
            subkeys.append(k2i)
            subkeys.append(k2ip)

  
    return (s0, s1, subkeys)

#######[Encryption Method]########
#takes 128-bit plaintext and 128-bit key as input
#output is encrypted ciphertext

def encrypt(p, k):

    s0, s1, kSubkeys = keySchedule(k) #key schedule, generates subkeys s0, s1 and k subkeys (k0-k39)
    print("s0:", s0)
    print("s1:", s1)
    print("subkeys:", [binaryToHexadecimal(key) for key in kSubkeys]) #print all subkeys
    ###[input whitening]###
    
    pValues = [p[:32], p[32:64], p[64:96], p[96:128]]
    r = []
    for i in range(4):
        r.append(XOR(pValues[i], kSubkeys[i]))
    
    #####[function f (16 rounds of encryption)]#####
    print("Round: ", 0, " x =" , binaryToHexadecimal(r[0]), binaryToHexadecimal(r[1]), binaryToHexadecimal(r[2]), binaryToHexadecimal(r[3]))

    for i in range(16):
        
        ###[function g]###

        #r0: 32-bit output
        r0sBoxValues = sBox(r[0], s0, s1)
        t0 = MDS(r0sBoxValues)

        #r1 32-bit output
        r1 = r[1]
        for _ in range(8): #ROL8
            r1 = ROL(r1)

        r1sBoxValues = sBox(r1, s0, s1)
        t1 = MDS(r1sBoxValues)

        # print("t0= " , binaryToHexadecimal(t0), "t1= ", binaryToHexadecimal(t1))

        aPrime, bPrime = PHT(t0, t1) #PHT

        f0 = decimalToBinary((binaryToDecimal(aPrime) + binaryToDecimal(kSubkeys[(2*i) + 8]))%(2**32), 32) #K2r+8
        f1 = decimalToBinary((binaryToDecimal(bPrime) + binaryToDecimal(kSubkeys[(2*i) + 9]))%(2**32), 32) #K2r +9

        c2 = ROR(XOR(f0, r[2]))
        c3 = XOR(f1, ROL(r[3]))

        tempr0 = r[0]
        tempr1 = r[1]

        # print("Round: ", i + 1, " x =" , binaryToHexadecimal(r[0]), binaryToHexadecimal(r[1]), binaryToHexadecimal(r[2]), binaryToHexadecimal(r[3]))

        r[0], r[1], r[2], r[3] = c2, c3, tempr0, tempr1 #outputs c2 and c3 become inputs for next round, previous inputs become k2 and k3 values
        print("Round: ", i + 1, " x =" , binaryToHexadecimal(r[0]), binaryToHexadecimal(r[1]), binaryToHexadecimal(r[2]), binaryToHexadecimal(r[3]))

    
    #####[output whitening]#####
    r[0], r[1], r[2], r[3] = r[2], r[3], r[0], r[1] #undo last swap
    ct = ""
    for i in range(4):
        ct += (XOR(r[i], kSubkeys[i+4]))

    ctle = [ct[:8], ct[8:16], ct[16:24], ct[24:32], ct[32:40], ct[40:48], ct[48:56], ct[56:64],
        ct[64:72], ct[72:80], ct[80:88], ct[88:96], ct[96:104], ct[104:112], ct[112:120], ct[120:128]] #split 128-bit key into 8-bit m values
    
    ct0 = ctle[3] + ctle[2] + ctle[1] + ctle[0]
    ct1 = ctle[7] + ctle[6] + ctle[5] + ctle[4]
    ct2 = ctle[11] + ctle[10] + ctle[9] + ctle[8]
    ct3 = ctle[15] + ctle[14] + ctle[13] + ctle[12]

    return ct0 + ct1 + ct2 + ct3 #final cipher text

def decrypt(c, k):
    #decryption is the same as encryption, but with subkeys used in reverse order
    s0, s1, kSubkeys = keySchedule(k) #key schedule, generates subkeys s0, s1 and k subkeys (k0-k39)
    print("s0:", s0)
    print("s1:", s1)

    print("subkeys:", [binaryToHexadecimal(key) for key in kSubkeys]) #print all subkeys


    ###[input whitening]###
    ctle = [c[:8], c[8:16], c[16:24], c[24:32], c[32:40], c[40:48], c[48:56], c[56:64],
        c[64:72], c[72:80], c[80:88], c[88:96], c[96:104], c[104:112], c[112:120], c[120:128]] #split 128-bit key into 8-bit m values
    
    ct0 = ctle[3] + ctle[2] + ctle[1] + ctle[0]
    ct1 = ctle[7] + ctle[6] + ctle[5] + ctle[4]
    ct2 = ctle[11] + ctle[10] + ctle[9] + ctle[8]
    ct3 = ctle[15] + ctle[14] + ctle[13] + ctle[12]


    cValues = [ct0, ct1, ct2, ct3]

    r = []
    for i in range(4):
        r.append(XOR(cValues[i], kSubkeys[i+4]))

    #swap at start
    r[0], r[1], r[2], r[3] = r[2], r[3], r[0], r[1]

    #####[function f (16 rounds of encryption)]#####

    for i in range(15, -1, -1):

        prevr0, prevr1 = r[2], r[3]

        ###[function g (in reverse)]###
        print("Round: ", i + 1, " x =" , binaryToHexadecimal(r[0]), binaryToHexadecimal(r[1]), binaryToHexadecimal(r[2]), binaryToHexadecimal(r[3]))

        r0sBoxValues = sBox(prevr0, s0, s1) #sbox + mds
        t0 = MDS(r0sBoxValues)

        tempr1 = prevr1 #ROL8
        for _ in range(8):
            tempr1 = ROL(tempr1)
        r1sBoxValues = sBox(tempr1, s0, s1)
        t1 = MDS(r1sBoxValues)

        # print("t0= " , binaryToHexadecimal(t0), "t1= ", binaryToHexadecimal(t1))
  
        aPrime, bPrime = PHT(t0, t1)

        #multiply with subkeys 
        f0 = decimalToBinary((binaryToDecimal(aPrime) + binaryToDecimal(kSubkeys[(2*i) + 8]))%(2**32), 32)
        f1 = decimalToBinary((binaryToDecimal(bPrime) + binaryToDecimal(kSubkeys[(2*i) + 9]))%(2**32), 32)
        # print(len(f0))

        r2 = XOR(f0, ROL(r[0]))
        r3 = ROR(XOR(f1, r[1]))
   
        r[0], r[1], r[2], r[3] = prevr0, prevr1, r2, r3   # set r0 and r1 to f0 and f1, and c2 and c3 become the new r2 and r3 for the next round


    #####[reverse output whitening]#####
    print("Round: ", 0, " x =" , binaryToHexadecimal(r[0]), binaryToHexadecimal(r[1]), binaryToHexadecimal(r[2]), binaryToHexadecimal(r[3]))

    plaintext = ""
    for i in range(4):
        plaintext += (XOR(r[i], kSubkeys[i]))

    return plaintext

##################[q permutations (used for S-Box generation)]##########################
#splits an 8 bit value, splits it into 4-bit nibbles, then permutates them uses q0 and q1 tables
def qPermutation(x, q):

    #t-tables of 4-bit values (0-15) used for permutation
    q0tTable = [
        ["1000", "0001", "0111", "1101", "0110", "1111", "0011", "0010", "0000", "1011", "0101", "1001", "1110", "1100", "1010", "0100"],
        ["1110", "1100", "1011", "1000", "0001", "0010", "0011", "0101", "1111", "0100", "1010", "0110", "0111", "0000", "1001", "1101"],
        ["1011", "1010", "0101", "1110", "0110", "1101", "1001", "0000", "1100", "1000", "1111", "0011", "0010", "0100", "0111", "0001"],
        ["1101", "0111", "1111", "0100", "0001", "0010", "0110", "1110", "1001", "1011", "0011", "0000", "1000", "0101", "1100", "1010"]]

    q1tTable = [
        ["0010", "1000", "1011", "1101", "1111", "0111", "0110", "1110", "0011", "0001", "1001", "0100", "0000", "1010", "1100", "0101"],
        ["0001", "1110", "0010", "1011", "0100", "1100", "0011", "0111", "0110", "1101", "1010", "0101", "1111", "1001", "0000", "1000"],
        ["0100", "1100", "0111", "0101", "0001", "0110", "1001", "1010", "0000", "1110", "1101", "1000", "0010", "1011", "0011", "1111"],
        ["1011", "1001", "0101", "0001", "1100", "0011", "1101", "1110", "0110", "0100", "0111", "1111", "0010", "0000", "1000", "1010"]
    ]

    #seperate 8-bit input into two 4-bit strings

    a0 = x[:4] #upper nibble
    b0 = x[4:8] #lower nibble

    a1 = XOR(a0, b0)
    b1 = XOR(XOR(a0, ROR(b0)), decimalToBinary(((8*(binaryToDecimal(a0)))%16), 4))

    if(q == 0): #different tables for q0 and q1
        a2 = q0tTable[0][binaryToDecimal(a1)]
        b2 = q0tTable[1][binaryToDecimal(b1)]

    if(q == 1):
        a2 = q1tTable[0][binaryToDecimal(a1)]
        b2 = q1tTable[1][binaryToDecimal(b1)]

    a3 = XOR(a2, b2)
    b3 = XOR(XOR(a2, ROR(b2)), decimalToBinary(((8*(binaryToDecimal(a2)))%16), 4))

    if(q == 0):
        a4 = q0tTable[2][binaryToDecimal(a3)]
        b4 = q0tTable[3][binaryToDecimal(b3)]

    if(q == 1):
        a4 = q1tTable[2][binaryToDecimal(a3)]
        b4 = q1tTable[3][binaryToDecimal(b3)]

    
    return(b4 + a4) #final 8-bit string

##########[function h]############
#main function for generating subkeys k0-k39 - very similar structure to Sbox, but uses L0 and L1 instead of s1 and s0

def h(X, L):
    x  = [X[:8],    X[8:16],    X[16:24],    X[24:32]]
    L0 = [L[0][:8], L[0][8:16], L[0][16:24], L[0][24:32]]
    L1 = [L[1][:8], L[1][8:16], L[1][16:24], L[1][24:32]]


    qOrder = [[0, 1, 0, 1], [0, 0, 1, 1], [1, 0, 1, 0]]

    for i in range(4):
        x[i] = qPermutation(x[i], qOrder[0][i]) #first q permutation: use q0 if sbox0 or sbox2, use q1 if sbox1 or sbox3

    for i in range(4):
        x[i] = XOR(x[i], L0[i]) #xor with L0

    for i in range(4):
        x[i] = qPermutation(x[i], qOrder[1][i]) #second q permutation 2

    for i in range(4):
        x[i] = XOR(x[i], L1[i]) #xor with L1

    for i in range(4):
        x[i] = qPermutation(x[i], qOrder[2][i]) #third q permutation

    # print("h bytes before MDS:", [binaryToHexadecimal(b) for b in x])
    result = MDS(x)
    # print("h result:", binaryToHexadecimal(result))
    return result

#######################[S-BOX METHOD]##########################
#Key-dependent s-boxes
#used in function g
def sBox(input, s0, s1):
    
    sBoxValues = [input[24:32], input[16:24], input[8:16], input[:8]]
    s0Split = [s0[24:32], s0[16:24], s0[8:16], s0[:8]]
    s1Split = [s1[24:32], s1[16:24], s1[8:16], s1[:8]]
    
    #main sbox function for sbox0-sbox3
    qOrder = [[0, 1, 0, 1], [0, 0, 1, 1], [1, 0, 1, 0]]

    for i in range(4):
        sBoxValues[i] = qPermutation(sBoxValues[i], qOrder[0][i]) #first q permutation: use q0 if sbox0 or sbox2, use q1 if sbox1 or sbox3

    for i in range(4):
        sBoxValues[i] = XOR(sBoxValues[i], s0Split[i]) #xor with s0

    for i in range(4):
        sBoxValues[i] = qPermutation(sBoxValues[i], qOrder[1][i]) #second q permutation 2

    for i in range(4):
        sBoxValues[i] = XOR(sBoxValues[i], s1Split[i]) #xor with s1

    for i in range(4):
        sBoxValues[i] = qPermutation(sBoxValues[i], qOrder[2][i]) #third q permutation
    return sBoxValues

#######################[Maximum Distance Seperate (MDS) MATRIX]##########################


def MDS(input):
    MDSmatrix = [["00000001", "11101111", "01011011", "01011011"],
                 ["01011011", "11101111", "11101111", "00000001"],
                 ["11101111", "01011011", "00000001", "11101111"],
                 ["11101111", "00000001", "11101111", "01011011"]]
    
    z = []
    for i in range(4): #matrix multiplication of input and MDS matrix (4x8 * 8x4)
       
        z.append(rowMult(input, MDSmatrix[i], "mds")) 
    
    z.reverse() #reverse order of z values for output
    return "".join(z) #combine z values into one 32-bit string and return


#############[Pseudo-Hadamard transform (PHT) Method]##################
#given two inputs, a and b:
#a' = a + b (mod 2^n)
#b' = a + 2b (mod 2^n)
#where n = 32

def PHT(t0, t1):
    a = binaryToDecimal(t0)
    b = binaryToDecimal(t1)
    
    aPrime = decimalToBinary((a + b)%(2**32), 32)
    bPrime = decimalToBinary((a + (2*b))%(2**32), 32)

    return (aPrime, bPrime)


#######[helper functions]########

def ROR(s): #rotate right bit shift
    ror = s[(len(s) - 1): len(s)] + s[:(len(s) - 1)]
    return ror

def ROL(s): #rotate right bit shift
    rol = s[(1): len(s)] + s[:1]
    return rol

def GFMult(a, b, funct): #galois field multiplication of two 8-bit binary strings
    polynomial = ""
    if (funct == "rs"):
        polynomial = "101001101" #multiplication polynomial for RS: x^8 + x^6 + x^3 + x^2 + 1
    if (funct == "mds"):
        polynomial = "101101001" #multiplication polynomial for MDS: x^8 + x^6 + x^5 + x^3 + 1
    result = "00000000"

    for i in range(8): #if lsb of b is 1, XOR with a
        if b[7] == "1":
            # print("result:", result, "a:", a)
            result = XOR(result, a)

        msb = a[0] #shift left by 1 (mult by x)
        a = a[1:] + "0"

        if msb == "1": #if msb was 1, reduce by polynomial
            a = XOR(a, polynomial[1:])

        b = "0" + b[:7] #shift b right

    return result

def rowMult(m, matrix, funct): #matrix row multiplication
    rowResult = "00000000"
    
    for i in range(len(matrix)):
        # print("262: m[i]:" ,m[i], "rs[i]: ", rs[i])
        gf = GFMult(m[i], matrix[i], funct)
        # print(f"  GFMult({binaryToHexadecimal(m[i])}, {binaryToHexadecimal(matrix[i])}) = {binaryToHexadecimal(gf)}")
        rowResult = XOR(rowResult, gf)

    # rowResult = decimalToBinary((sum % 256), 8) #mod 256 for 8 bit result
    return rowResult
    
def XOR(a, b): #xor operation
    result = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            result += "0"
        else:
            result += "1"
    return result

def binaryToDecimal(binary): #converts binary string of any length to decimal int representation
    result = 0
    for i in range(len(binary)):
        result += int(binary[len(binary) - 1 - i]) * (2 ** i)
    return result

def decimalToBinary(decimal, length): #converts decimal int to a binary string of specified length
    result = ""
    while decimal > 0:
        result = str(decimal % 2) + result
        decimal = decimal // 2

    while(len(result) != length):
        result = "0" + result
    return result

def binaryToHexadecimal(binary): #binary to hex
    hexDigits = "0123456789ABCDEF"
    result = ""
    for i in range(0, len(binary), 4):
        bits = binary[i:i+4]
        decimal = binaryToDecimal(bits)
        result += hexDigits[decimal]
    return result    
   
def hexToBinary(hexString): #hex to binary
    hexDigits = "0123456789ABCDEF"
    result = ""
    for char in hexString:
        decimal = hexDigits.index(char)
        binary = decimalToBinary(decimal, 4)
        result += binary
    return result

def generate128BitNumber(): #generates a random 128-bit binary string
    num = ""
    for i in range(128):
        bit = random.randint(0, 1) #generate a random bit (0 or 1)
        num = num + str(bit) #append bit to number string
    return num

main()