import tkinter as tk
from tkinter import filedialog, messagebox
from main import AES_GCM_decrypt, AES_GCM_encrypt, text_in_blocks, cipher_blocks, decrypt_blocks, split_string_32bits, matrix_to_text, criptat_to_matrix, text_to_matrix, KEY_EXPANSION, encrypt_and_print, decrypt_and_print, ascii_to_text, transpose

def encrypt_file():
    filepath = filedialog.askopenfilename(initialdir="./", title="Selectează fișierul pentru criptare")
    if not filepath:
        return
    
    key = key_entry.get()
    if not key:
        messagebox.showerror("Eroare", "Introduceti cheia de criptare!")
        return
    
    with open(filepath, 'r') as file:
        plaintext = file.read()
    
    matrix = text_to_matrix(key)
    keys = KEY_EXPANSION(matrix)
    
    blocks = text_in_blocks(plaintext)
    text_criptat = cipher_blocks(blocks, keys)

    with open("text_criptat.txt", 'w') as file:
        file.write(text_criptat)
    
    messagebox.showinfo("Info", "Criptare finalizată. Text criptat salvat în 'text_criptat.txt'")

def decrypt_file():
    filepath = filedialog.askopenfilename(initialdir="./", title="Selectează fișierul pentru decriptare")
    if not filepath:
        return
    
    key = key_entry.get()
    if not key:
        messagebox.showerror("Eroare", "Introduceti cheia de criptare!")
        return
    
    with open(filepath, 'r') as file:
        cipher_text = file.read()
        
    matrix = text_to_matrix(key)
    keys = KEY_EXPANSION(matrix)

    cipher_text = split_string_32bits(cipher_text)
    print("CIPHER TEXT: ", cipher_text)
    cipher_text = [criptat_to_matrix(element) for element in cipher_text]
    decrypted_text = decrypt_blocks(cipher_text, keys)
    print("Text decriptat: ", decrypted_text)
    
    with open("text_decriptat.txt", 'w') as file:
        file.write(decrypted_text)
    
    messagebox.showinfo("Info", "Decriptare finalizată. Text decriptat salvat în 'text_decriptat.txt'")

def encrypt_file_gcm():
    filepath = filedialog.askopenfilename(initialdir="./", title="Selectează fișierul pentru criptare GCM")
    if not filepath:
        return
    
    key = key_entry.get()
    if not key:
        messagebox.showerror("Eroare", "Introduceti cheia de criptare!")
        return
    
    aad = aad_entry.get().encode('utf-8')
    
    with open(filepath, 'r') as file:
        plaintext = file.read().encode('utf-8')
    
    matrix = text_to_matrix(key)
    keys = KEY_EXPANSION(matrix)
    
    iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b'
    ciphertext, tag = AES_GCM_encrypt(plaintext, aad, keys, iv)
    
    ciphertext = matrix_to_text(ciphertext)
    print("cipher: ", ciphertext)
    tag_hex = tag.hex()
    print("tag", tag_hex)

    with open("text_criptat_gcm.txt", 'w') as file:
        file.write(ciphertext + tag_hex)
    
    messagebox.showinfo("Info", "Criptare finalizată. Text criptat salvat în 'text_criptat_gcm.txt'")

def decrypt_file_gcm():
    filepath = filedialog.askopenfilename(initialdir="./", title="Selectează fișierul pentru decriptare GCM")
    if not filepath:
        return
    
    key = key_entry.get()
    if not key:
        messagebox.showerror("Eroare", "Introduceti cheia de criptare!")
        return
    
    aad = aad_entry.get().encode('utf-8')
    
    with open(filepath, 'r') as file:
        data = file.read()
    
    cipher_text = data[:len(data)-32]
    print("cipher_text", cipher_text)
    iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b'
    tag = data[len(data)-32:len(data)]

    print("tag ", tag)
    tag = bytes.fromhex(tag)
    print("tag ", tag)
    
    matrix = text_to_matrix(key)
    keys = KEY_EXPANSION(matrix)
    
    cipher_text = criptat_to_matrix(cipher_text)
    print("cipher", cipher_text)
    decrypted_text = AES_GCM_decrypt(cipher_text, aad, keys, iv, tag)
    decrypted_text = ascii_to_text(decrypted_text)
    
    with open("text_decriptat_gcm.txt", 'w') as file:
        file.write(decrypted_text)
    
    messagebox.showinfo("Info", "Decriptare finalizată. Text decriptat salvat în 'text_decriptat_gcm.txt'")

# Creare main window
root = tk.Tk()
root.title("AES Criptare/Decriptare")

root.geometry("500x400")  

# Creare buton de criptare fisier
encrypt_file_button = tk.Button(root, text="Criptare Fisier", command=encrypt_file, bg="#4CAF50", fg="white", font=("Arial", 12))
encrypt_file_button.grid(row=0, column=0, padx=150, pady=10, sticky="ew")

# Creare buton de decriptare fisier
decrypt_file_button = tk.Button(root, text="Decriptare Fisier", command=decrypt_file, bg="#FF5722", fg="white", font=("Arial", 12))
decrypt_file_button.grid(row=1, column=0, padx=150, pady=10, sticky="ew")

# Creare buton de criptare fisier GCM
encrypt_file_gcm_button = tk.Button(root, text="Criptare Fisier GCM", command=encrypt_file_gcm, bg="#3F51B5", fg="white", font=("Arial", 12))
encrypt_file_gcm_button.grid(row=2, column=0, padx=150, pady=10, sticky="ew")

# Creare buton de decriptare fisier GCM
decrypt_file_gcm_button = tk.Button(root, text="Decriptare Fisier GCM", command=decrypt_file_gcm, bg="#009688", fg="white", font=("Arial", 12))
decrypt_file_gcm_button.grid(row=3, column=0, padx=150, pady=10, sticky="ew")

# Eticheta pentru cheie
key_label = tk.Label(root, text="Cheie de criptare:", font=("Arial", 12))
key_label.grid(row=4, column=0, padx=170, pady=10, sticky="w")

# Intrare pentru cheie
key_entry = tk.Entry(root, font=("Arial", 12))
key_entry.grid(row=5, column=0, padx=150, pady=10, sticky="ew")

# Eticheta pentru AAD
aad_label = tk.Label(root, text="AAD (Additional Auth Data):", font=("Arial", 12))
aad_label.grid(row=6, column=0, padx=170, pady=10, sticky="w")

# Intrare pentru AAD
aad_entry = tk.Entry(root, font=("Arial", 12))
aad_entry.grid(row=7, column=0, padx=150, pady=10, sticky="ew")

root.mainloop()