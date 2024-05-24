from itertools import chain

# Algoritmul AES - Advanced Encryption Standard
s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

def SUB_BYTES(word):
    """Inlocuieste fiecare octet din cuvant cu valoarea corespunzatoare din SBox"""
    return [s_box[b] for b in word]

def INV_SUB_BYTES(word):
    """Inlocuieste fiecare octet din cuvant cu valoarea corespunzatoare din Inv_SBox"""
    return [inv_s_box[b] for b in word]

def SHIFT_ROWS(word, n=1):
    """Shiftare circulara la stanga de 1-octet pentru un cuvant"""
    """Pentru shiftare la dreapta, n trebuie sa aiba o valoare negativa"""
    return word[n:] + word[:n]

def transpose(matrix):
    # Determinam numarul de randuri si coloane ale matricei transpuse
    num_rows = len(matrix)
    num_cols = len(matrix[0]) if matrix else 0

    # Cream matricea transpusa initial cu toate elementele initializate cu 0
    transposed_matrix = [[0] * num_rows for _ in range(num_cols)]

    for i in range(num_rows):
        for j in range(num_cols):
            transposed_matrix[j][i] = matrix[i][j]

    return transposed_matrix

def ADD_ROUND_KEY(word1, key_round):
    """Aplicarea operatiei XOR intre blocul de date si o cheie de runda derivata din cheia principala"""
    result = []

    for sublist1, sublist2 in zip(word1, key_round):
        xor_result = [elem1 ^ elem2 for elem1, elem2 in zip(sublist1, sublist2)]
        result.append(xor_result)
    return result 

def multiply_by_2(v):
    s = v << 1
    s &= 0xff
    # Daca cel mai semnificativ bit al rezultatului este setat (1), trebuie sa facem xor cu polinomul ireductibil
    if (v & 128) != 0: 
        s = s ^ 0x1b
    return s

def multiply_by_3(v):
    return multiply_by_2(v) ^ v 

def mix_columns(state):
    new_state = [[], [], [], []]
    for i in range(4):
        col = [state[j][i] for j in range(4)]
        col = mix_column(col)
        for i in range(4):
            new_state[i].append(col[i])
    return new_state

def mix_column(column):
    # Se aplica functia de amestecare pentru fiecare coloana a matricei
    # XOR cu polinomul ireductibil x8 + x4 + x3 + x + 1 daca nr este mai mare de 1 byte; GF(2^8).
    # s'0,c = ({02} * s0,c) ^ ({03} * s1,c) ^ s2,c ^ s3,c
    # s'1,c = s0,c ^ ({02} * s1,c) ^ ({03} * s2,c) ^ s3,c
    # s'2,c = s0,c ^  s1,c ^ ({02} * s2,c) ^ ({02} * s3,c)
    # s'3,c = ({03} * s0,c) ^ s1,c ^ s2,c ^ ({02} * s3,c)
    result = [
        multiply_by_2(column[0]) ^ multiply_by_3( column[1]) ^ column[2] ^ column[3],
        multiply_by_2(column[1]) ^ multiply_by_3( column[2]) ^ column[3] ^ column[0],
        multiply_by_2(column[2]) ^ multiply_by_3( column[3]) ^ column[0] ^ column[1],
        multiply_by_2(column[3]) ^ multiply_by_3( column[0]) ^ column[1] ^ column[2]
    ]
    return result

# Inmultire in campul Galois -> standardul GCM (Galois Counter Mode)
def multiply(a, b):
    p = 0
    for _ in range(8):  # Pentru fiecare bit din b
        if b & 1:  
            p ^= a  
        if a & 0x80 == 0: 
            a <<= 1  
        else:
            a = (a << 1) ^ 0x1b  
        b >>= 1  
    return p & 0xff

def INV_MIX_COLUMNS(state):
    # Matricea de stocare a rezultatului
    result_state = [[0] * 4 for _ in range(4)]
    
    # Formula pentru inversul mix_column
    for col in range(4):
        result_state[0][col] = multiply(0x0e, state[0][col]) ^ multiply(0x0b, state[1][col]) ^ multiply(0x0d, state[2][col]) ^ multiply(0x09, state[3][col])
        result_state[1][col] = multiply(0x09, state[0][col]) ^ multiply(0x0e, state[1][col]) ^ multiply(0x0b, state[2][col]) ^ multiply(0x0d, state[3][col])
        result_state[2][col] = multiply(0x0d, state[0][col]) ^ multiply(0x09, state[1][col]) ^ multiply(0x0e, state[2][col]) ^ multiply(0x0b, state[3][col])
        result_state[3][col] = multiply(0x0b, state[0][col]) ^ multiply(0x0d, state[1][col]) ^ multiply(0x09, state[2][col]) ^ multiply(0x0e, state[3][col])
    
    return result_state

def KEY_EXPANSION(key_matrix):
    num_rounds = 10
    key_schedule = [key_matrix] # Round Key 0
    #print(key_schedule)

    for i in range(1, num_rounds + 1):
        prev_key = key_schedule[-1]
        w0 = prev_key[0]
        w1 = prev_key[1]
        w2 = prev_key[2]
        w3 = prev_key[3]

        gw3 = w3
        # Rotire circulara a ultimei coloane din prev_key
        gw3 = SHIFT_ROWS(prev_key[3], 1)

        # Aplicare substitutie
        gw3 = SUB_BYTES(gw3)
        # XOR cu un RCon pe prima coloană a noii chei
        rcon = Rcon[i - 1]
        result = []
        for elem1, elem2 in zip(gw3, rcon):
            result.append(elem1 ^ elem2)
        gw3 = result

        # Generarea matricei
        w4 = []
        for elem1, elem2 in zip(w0, gw3):
            w4.append(elem1 ^ elem2)
        w5 = []
        for elem1, elem2 in zip(w4, w1):
            w5.append(elem1 ^ elem2)
        w6 = []
        for elem1, elem2 in zip(w5, w2):
            w6.append(elem1 ^ elem2)
        w7 = []
        for elem1, elem2 in zip(w6, w3):
            w7.append(elem1 ^ elem2)
        
        # Adaugam noua cheie in lista cheilor de runda
        key_schedule.append([w4, w5, w6, w7])
    return key_schedule

Rcon = [
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1b, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00]
]

def text_to_matrix(text):
    if isinstance(text, str):
        text_bytes = text.encode('utf-8')
    elif isinstance(text, bytes):
        text_bytes = text
    else:
        raise TypeError("Input must be a string or bytes object")
    
    # Continue with the existing conversion from bytes to matrix
    return [list(text_bytes[i:i+4]) for i in range(0, len(text_bytes), 4)]

def cipher(plaintext, keys):
    if isinstance(plaintext, bytes):
        state = text_to_matrix(plaintext)
    elif isinstance(plaintext, str):
        state = text_to_matrix(plaintext.encode('utf-8'))
    else:
        raise TypeError("Plaintext must be a string or bytes object")
    rounds = 10
    state = text_to_matrix(plaintext)
    #print("State initial ")
    #print_matrix_hex(state)
    state = ADD_ROUND_KEY(state, keys[0])
    #print("Dupa aplicarea Round key 0")
    #print_matrix_hex(state)
    i = 1
    for round in range(1, rounds + 1):
        #print("Runda", round)
        #print("State: ")
        #print_matrix_hex(state)
        new_state = []
        for row in state:
            new_state.append(SUB_BYTES(row))
        state = new_state
        #print("SUB_BYTES")
        #print_matrix_hex(state)
        state = transpose(state)
        for i in range(1, 4):
           state[i] = SHIFT_ROWS(state[i], i)
        #print("SHIFT_ROWS")
        #print_matrix_hex(state)
        if round != 10:
            state = mix_columns(state)
            #print("MIX_COLUMNS")
            #print_matrix_hex(state)
        state = transpose(state)
        state = ADD_ROUND_KEY(state, keys[round])
        #print("ADD_ROUND_KEY")
        #print_matrix_hex(state)
    state = transpose(state)
    return state

def decrypt(ciphertext, keys):
    rounds = 9
    state = ciphertext
    #print("INITIAL STATE: ", state)
    state = transpose(state)
    state = ADD_ROUND_KEY(state, keys[-1])  # decriptarea rundei finale
    state = transpose(state)
    for i in range(1, 4):
        state[i] = SHIFT_ROWS(state[i], -i)
    #print_matrix_hex(state)
    state = [INV_SUB_BYTES(row) for row in state]
    #print("SUB BYTES runda finala")
    #print_matrix_hex(state)

    for round in range(rounds, 0, -1):  # parcurgem rundele in ordine inversa
        state = transpose(state)
        state = ADD_ROUND_KEY(state, keys[round])
        #print("After round key: ", round)
        #print_matrix_hex(state)
        state = transpose(state)
        state = INV_MIX_COLUMNS(state)
        #print("After INV_MIX_COLUMNS: ", round)
        #print_matrix_hex(state)
        for i in range(1, 4):
            state[i] = SHIFT_ROWS(state[i], -i)
        #print("After SHIFT_ROWS: ", round)
        #print_matrix_hex(state)  
        state = [INV_SUB_BYTES(row) for row in state]
        #print("After INV_SUB_BYTES: ", round)
        #print_matrix_hex(state)
    #print("KEY [0]: ")
    #print_matrix_hex(keys[0])
    state = transpose(state)  
    state = ADD_ROUND_KEY(state, keys[0])  # decriptarea rundei initiale
    #print("After ADD_ROUND_KEY[0]: ")
    #print_matrix_hex(state)
    return state

def encrypt_and_print(plaintext, keys):
    encrypt_matrix = cipher(plaintext, keys)
    encrypt_text = transpose(encrypt_matrix)
    encrypt_text = matrix_to_text(encrypt_text)
    print("Text criptat:")
    print(encrypt_text)
    return encrypt_matrix

def decrypt_and_print(ciphertext, keys):
    decrypted_matrix = decrypt(ciphertext, keys)
    decrypted_text = matrix_to_text(decrypted_matrix)
    print("Text decriptat:")
    print(decrypted_text)
    return decrypted_matrix

def print_matrix_hex(matrix):
    for row in matrix:
        hex_row = [hex(byte) for byte in row]
        print(hex_row)

def matrix_to_text(matrix):
    concatenated_rows = []
    for row in matrix:
        concatenated_rows.extend(row)
    print(concatenated_rows)

    ascii_string = ''
    first_element = True
    for number in concatenated_rows:
        if first_element:
            ascii_string += hex(number)[2:].zfill(2)
            first_element = False
        else:
            ascii_string += '' + hex(number)[2:].zfill(2)
    print(ascii_string)
    return ascii_string

def criptat_to_matrix(hex_string):
    matrix = []
    for i in range(0, len(hex_string), 8):  
        row = []
        for j in range(0, 8, 2):  
            hex_num = hex_string[i + j:i + j + 2]  
            decimal_num = int(hex_num, 16) 
            row.append(decimal_num) 
        matrix.append(row)  
    for row in matrix:
        print(row)
    return matrix

def ascii_to_text(matrix):
    concatenated_rows = []
    for row in matrix:
        concatenated_rows.extend(row)
    print(concatenated_rows)
    concatenated_chr = []
    for elem in concatenated_rows:
        concatenated_chr.extend(chr(elem))
    text = ''
    for elem in concatenated_chr:
        text += elem
    return text

def text_in_blocks(text):
    blocks = []
    while len(text) > 0:
        if len(text) >= 16:
            blocks.append(text[:16])
            text = text[16:]
        else:
            text += ' ' * (16 - len(text))
            blocks.append(text)
            break
    return blocks

def cipher_blocks(matrices, keys):
    matrici_criptate = []
    text_criptat = ''
    for matrix in matrices:
        encoded_matrix = encrypt_and_print(matrix, keys)
        matrix_text = matrix_to_text(encoded_matrix)
        matrice_criptata = criptat_to_matrix(matrix_text)
        matrici_criptate.append(matrice_criptata)
        text_criptat += matrix_text
    return text_criptat

def decrypt_blocks(matrices, keys):
    decriptat = ''
    for matrice in matrices:
        decode = decrypt_and_print(matrice, keys)
        text_decriptat = ascii_to_text(decode)
        print(text_decriptat)
        decriptat += text_decriptat
    print(decriptat)
    return decriptat

def split_string_32bits(sir, lungime_element=32):
    matrix = []
    for i in range(0, len(sir), lungime_element):
        matrix.append(sir[i:i+lungime_element])
    return matrix


# Functie care calculeaza autentificarea criptografica a blocurilor de date 
# folosind algoritmul GHASH specificat in standardul GCM

def AES_GCM_encrypt(plaintext, aad, keys, iv):
    # generare text criptat
    ciphertext = cipher(plaintext, keys)
    # calculam autentificarea criptografica folosind operatiile specifice GCM

    # calculam H = E(k, 0^128)
    H = cipher(bytes([0]*16), keys)
    # calculam J0 = IV || 0^31 || 1
    Y0 = iv + bytes([0]*8) + bytes([1])
    # calculam CIPH = AES-CTR(H, J0)
    CIPH = cipher(Y0, keys) 
    # calculam GHASH(A, C) = AAD' XOR (0 || AAD) || C' XOR (0 || C)
    AAD_prim = len(aad).to_bytes(8, byteorder='big') + aad
    C_prim = len(ciphertext).to_bytes(8, byteorder='big') + bytes(matrix_to_text(ciphertext), 'utf-8')
    GHASH_input = AAD_prim + C_prim

    flattened_CIPH = list(chain.from_iterable(CIPH))
    CIPH_bytes = bytes(flattened_CIPH)
    # calculam Tag = GHASH(A, C) XOR CIPH
    Tag = bytes([x ^ y for x, y in zip(GHASH_input, CIPH_bytes)])
    return ciphertext, Tag

def AES_GCM_decrypt(ciphertext, aad, keys, iv, tag):
    # calculam H = E(k, 0^128)
    H = cipher(bytes([0]*16), keys)
    # calculam J0 = IV || 0^31 || 1
    Y0 = iv + bytes([0]*8) + bytes([1])
    # calculam CIPH = AES-CTR(H, J0)
    CIPH = cipher(Y0, keys)
    # calculam GHASH(A, C) = AAD' XOR (0 || AAD) || C' XOR (0 || C)
    AAD_prim = len(aad).to_bytes(8, byteorder='big') + aad
    C_prim = len(ciphertext).to_bytes(8, byteorder='big') + bytes(matrix_to_text(ciphertext), 'utf-8')
    GHASH_input = AAD_prim + C_prim

    flattened_CIPH = list(chain.from_iterable(CIPH))
    CIPH_bytes = bytes(flattened_CIPH)

    # calculam Tag' = GHASH(A, C) XOR CIPH
    Tag_prim = bytes([x ^ y for x, y in zip(GHASH_input, CIPH_bytes)])

    Tag_prim = Tag_prim.hex()
    Tag_prim = bytes.fromhex(Tag_prim)

    print("Tag: ", tag)
    print("Tag prim: ", Tag_prim)

    # comparare tag-uri
    if Tag_prim != tag:
        raise ValueError("Autentificarea criptografica a esuat!")

    plaintext = decrypt(ciphertext, keys)

    return plaintext

def main():
    #key = "Thats my Kung Fu"
    #matrix = text_to_matrix(key)

    #keys = KEY_EXPANSION(matrix)

    #plaintext = "Two One Nine Two 2222222"

    #blocks = text_in_blocks(plaintext)
    #text_criptat = cipher_blocks(blocks, keys)
    #print("Text criptat: ", text_criptat)
    #text_criptat = split_string_32bits(text_criptat)
    #text_criptat = [criptat_to_matrix(element) for element in text_criptat]
    #text_decriptat = decrypt_blocks(text_criptat, keys)
    #print("Text decriptat: ", text_decriptat)

    key = "Thats my Kung Fu"
    matrix = text_to_matrix(key)

    keys = KEY_EXPANSION(matrix)

    iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b'
    plaintext = b'Hello, GCM Mode!'
    aad = b'Date de autentificare aditionale'

    ciphertext, tag = AES_GCM_encrypt(plaintext, aad, keys, iv)
    tag = tag.hex()
    tag = bytes.fromhex(tag)
    decrypted_text = AES_GCM_decrypt(ciphertext, aad, keys, iv, tag)

    print("Plaintext:", plaintext)
    print("Ciphertext:", ciphertext)
    print("Tag:", tag)
    print("Decrypted Text:", decrypted_text)
    decrypted_text = ascii_to_text(decrypted_text)
    print("Decrypted Text:", decrypted_text)

if __name__ == "__main__":
    main()