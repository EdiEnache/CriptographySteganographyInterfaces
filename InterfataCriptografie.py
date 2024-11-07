import tkinter as tk
import rsa
from collections import Counter
from tkinter import messagebox
from tkinter import ttk, filedialog
import re
from cryptography.hazmat.primitives import serialization

from langdetect import detect
from pyDes import des, ECB, PAD_PKCS5
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib



###################################
def encrypt_aes_action(plaintext_entry, key_entry, result_entry):
    plaintext = plaintext_entry.get()
    key = key_entry.get()
    if len(key) not in [16, 24, 32]:
        result_entry.delete(0, tk.END)
        result_entry.insert(0, "Cheia trebuie să fie de 16, 24 sau 32 biti.")
        return
    key = key.encode()
    ciphertext, iv = encrypt_aes(plaintext, key)
    result_entry.delete(0, tk.END)
    result_entry.insert(0, ciphertext.hex() + " - IV: " + iv.hex())


def decrypt_aes_action(ciphertext_entry, key_entry, result_entry):
    ciphertext_iv = ciphertext_entry.get().split(" - IV: ")
    ciphertext = bytes.fromhex(ciphertext_iv[0])
    iv = bytes.fromhex(ciphertext_iv[1])
    key = key_entry.get()
    if len(key) not in [16, 24, 32]:
        result_entry.delete(0, tk.END)
        result_entry.insert(0, "Cheia trebuie să fie de 16, 24 sau 32 biti.")
        return
    key = key.encode()
    plaintext = decrypt_aes(ciphertext, key, iv)
    result_entry.delete(0, tk.END)
    result_entry.insert(0, plaintext)


def encrypt_aes(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return ct_bytes, cipher.iv

# Funcție pentru decriptare AES
def decrypt_aes(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return pt_bytes.decode()



def one_time_pad_decrypt(ciphertext, key):
    plaintext = ""
    for i in range(len(ciphertext)):
        char = ciphertext[i]
        if char.isupper():
            plaintext += chr((ord(char) - ord(key[i]) + 26) % 26 + 65)
        elif char.islower():
            plaintext += chr((ord(char) - ord(key[i]) + 26) % 26 + 97)
        else:
            plaintext += char
    return plaintext


def decrypt_one_time_pad(ciphertext_entry, key_entry, result_entry):
    ciphertext = ciphertext_entry.get().upper()
    key = key_entry.get().upper()

    if len(ciphertext) != len(key):
        result_entry.delete(0, tk.END)
        result_entry.insert(0, "Textul cifrat și cheia trebuie să aibă aceeași lungime.")
        return

    plaintext = one_time_pad_decrypt(ciphertext, key)
    result_entry.delete(0, tk.END)
    result_entry.insert(0, plaintext)



def one_time_pad_encrypt(plaintext, key):
    ciphertext = ""
    for i in range(len(plaintext)):
        char = plaintext[i]
        if char.isupper():
            ciphertext += chr((ord(char) + ord(key[i]) - 2 * 65) % 26 + 65)
        elif char.islower():
            ciphertext += chr((ord(char) + ord(key[i]) - 2 * 97) % 26 + 97)
        else:
            ciphertext += char
    return ciphertext


def encrypt_one_time_pad(plaintext_entry, key_entry, result_entry):
    plaintext = plaintext_entry.get().upper()
    key = key_entry.get().upper()

    if len(plaintext) != len(key):
        result_entry.delete(0, tk.END)
        result_entry.insert(0, "Textul clar și cheia trebuie să aibă aceeași lungime.")
        return

    ciphertext = one_time_pad_encrypt(plaintext, key)
    result_entry.delete(0, tk.END)
    result_entry.insert(0, ciphertext)

##############################################



class InterfataCriptografie:
    def __init__(self, root):

        self.root = root
        self.root.title("Interfata Criptografie")

        # Crearea unui frame principal
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configurarea grilei
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Adăugarea de elemente UI
        self.add_widgets()

    def add_widgets(self):
        # Frame pentru butoanele de algoritmi de criptografie clasici
        classical_crypto_frame = ttk.Frame(self.main_frame, padding="10")
        classical_crypto_frame.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))

        # Adăugarea titlului pentru prima coloană
        title_label_classical = ttk.Label(classical_crypto_frame, text="Algoritmi de criptografie clasici",
                                          font=("Arial", 12, "bold"))
        title_label_classical.grid(row=0, column=0, columnspan=2, pady=(0, 10.2), sticky=(tk.W, tk.E))

        # Butonul pentru a afișa exemplul Caesar Cipher
        self.caesar_button = ttk.Button(classical_crypto_frame, text="Caesar Cipher",
                                        command=self.show_caesar_cipher_interface)
        self.caesar_button.grid(row=1, column=0, pady=(0, 5), sticky=(tk.W, tk.E))

        # Butonul pentru a detecta limba
        self.language_button = ttk.Button(classical_crypto_frame, text="Language Detection",
                                          command=self.show_language_detection_interface)
        self.language_button.grid(row=2, column=0, pady=5, sticky=(tk.W, tk.E))

        # Butonul pentru Vigenere Cipher
        self.vigenere_button = ttk.Button(classical_crypto_frame, text="Vigenere Cipher",
                                          command=self.show_vigenere_cipher_interface)
        self.vigenere_button.grid(row=3, column=0, pady=5, sticky=(tk.W, tk.E))

        # Butonul pentru algoritmul Kasiski
        self.kasiski_button = ttk.Button(classical_crypto_frame, text="Kasiski",
                                         command=self.show_kasiski_interface)
        self.kasiski_button.grid(row=4, column=0, pady=5, sticky=(tk.W, tk.E))

        # Butonul pentru One-Time Pad
        self.one_time_pad_button = ttk.Button(classical_crypto_frame, text="One-Time Pad",
                                              command=self.show_one_time_pad_interface)
        self.one_time_pad_button.grid(row=5, column=0, pady=(5, 0), sticky=(tk.W, tk.E))

        # Frame pentru butoanele de algoritmi de criptografie moderni
        modern_crypto_frame = ttk.Frame(self.main_frame, padding="10")
        modern_crypto_frame.grid(row=0, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))

        # Adăugarea titlului pentru a doua coloană
        title_label_modern = ttk.Label(modern_crypto_frame, text="Algoritmi de criptografie moderni",
                                       font=("Arial", 12, "bold"))
        title_label_modern.grid(row=0, column=0, columnspan=2, pady=(15, 10), sticky=(tk.W, tk.E))

        # Butonul pentru DES
        self.des_button = ttk.Button(modern_crypto_frame, text="DES",
                                      command=self.show_des_interface)
        self.des_button.grid(row=1, column=0, pady=(0, 5), sticky=(tk.W, tk.E))

        # Butonul pentru AES
        self.aes_button = ttk.Button(modern_crypto_frame, text="AES",
                                     command=self.show_aes_interface)
        self.aes_button.grid(row=2, column=0, pady=(0,5), sticky=(tk.W, tk.E))

        # Butonul pentru Diffie-Hellman
        self.diffie_hellman_button = ttk.Button(modern_crypto_frame, text="Diffie-Hellman",
                                    command=self.show_diffie_hellman_interface)
        self.diffie_hellman_button.grid(row=3, column=0, pady=(0, 5), sticky=(tk.W, tk.E))

        # Butonul pentru RSA
        self.rsa_button = ttk.Button(modern_crypto_frame, text="RSA",
                                     command=self.show_rsa_interface)
        self.rsa_button.grid(row=4, column=0, pady=(0,5), sticky=(tk.W, tk.E))

        # Butonul pentru ECC
        self.ecc_button = ttk.Button(modern_crypto_frame, text="ECC",
                                     command=self.show_ecc_interface)
        self.ecc_button.grid(row=5, column=0, pady=(0, 5), sticky=(tk.W, tk.E))

        # Butonul pentru Hashing Algorithms
        self.hashing_button = ttk.Button(modern_crypto_frame, text="Hashing Algorithms",
                                         command=self.show_hashing_interface)
        self.hashing_button.grid(row=6, column=0, pady=(0, 5), sticky=(tk.W, tk.E))

    #######################################
    def show_caesar_cipher_interface(self):
        # Crearea unei noi ferestre pentru interfața Caesar Cipher
        caesar_window = tk.Toplevel(self.root)
        caesar_window.title("Caesar Cipher")

        # Crearea unui frame principal pentru noua fereastră
        caesar_frame = ttk.Frame(caesar_window, padding="10")
        caesar_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configurarea grilei pentru noua fereastră
        caesar_window.columnconfigure(0, weight=1)
        caesar_window.rowconfigure(0, weight=1)

        # Eticheta și câmpul pentru textul simplu
        plaintext_label = ttk.Label(caesar_frame, text="Text Simplu:")
        plaintext_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.plaintext_entry = ttk.Entry(caesar_frame, width=50)
        self.plaintext_entry.grid(row=0, column=1, padx=5, pady=5)

        # Eticheta și câmpul pentru cheia de criptare
        key_label = ttk.Label(caesar_frame, text="Cheie:")
        key_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.key_entry = ttk.Entry(caesar_frame, width=5)
        self.key_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        # Butonul pentru criptare
        encrypt_button = ttk.Button(caesar_frame, text="Criptează",
                                    command=lambda: self.encrypt())
        encrypt_button.grid(row=2, column=0, padx=5, pady=5)

        # Butonul pentru decriptare
        decrypt_button = ttk.Button(caesar_frame, text="Decriptează",
                                    command=lambda: self.decrypt())
        decrypt_button.grid(row=2, column=1, padx=5, pady=5)

        # Eticheta și câmpul pentru rezultatul criptării/decriptării
        result_label = ttk.Label(caesar_frame, text="Rezultat:")
        result_label.grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.result_entry = ttk.Entry(caesar_frame, width=50)
        self.result_entry.grid(row=3, column=1, padx=5, pady=5)

        # Butonul pentru a selecta un fișier
        browse_button = ttk.Button(caesar_frame, text="Browse",
                                   command=self.browse_file)
        browse_button.grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky=(tk.W, tk.E))

        # Butonul pentru criptarea fișierului
        encrypt_file_button = ttk.Button(caesar_frame, text="Criptează Fișier",
                                         command=self.encrypt_file)
        encrypt_file_button.grid(row=5, column=0, padx=5, pady=5)

        # Butonul pentru decriptarea fișierului
        decrypt_file_button = ttk.Button(caesar_frame, text="Decriptează Fișier",
                                         command=self.decrypt_file)
        decrypt_file_button.grid(row=5, column=1, padx=5, pady=5)

    def encrypt(self):
        plaintext = self.plaintext_entry.get()
        key = self.get_key()
        if key is not None:
            ciphertext = self.caesar_cipher(plaintext, key)
            self.result_entry.delete(0, tk.END)
            self.result_entry.insert(0, ciphertext)

    def decrypt(self):
        ciphertext = self.plaintext_entry.get()
        key = self.get_key()
        if key is not None:
            plaintext = self.caesar_cipher(ciphertext, -key)
            self.result_entry.delete(0, tk.END)
            self.result_entry.insert(0, plaintext)

    def get_key(self):
        try:
            key = int(self.key_entry.get())
            return key
        except ValueError:
            messagebox.showerror("Eroare", "Cheia trebuie să fie un număr întreg valid.")
            return None

    def caesar_cipher(self, text, shift):
        result = ""
        for char in text:
            if char.isalpha():
                shift_amount = 65 if char.isupper() else 97
                result += chr((ord(char) - shift_amount + shift) % 26 + shift_amount)
            else:
                result += char
        return result

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'r') as file:
                content = file.read()
                self.plaintext_entry.delete(0, tk.END)
                self.plaintext_entry.insert(0, content)
                self.current_file_path = file_path

    def encrypt_file(self):
        key = self.get_key()
        if key is not None and hasattr(self, 'current_file_path'):
            with open(self.current_file_path, 'r') as file:
                plaintext = file.read()
            ciphertext = self.caesar_cipher(plaintext, key)
            result_file_path = self.current_file_path.replace('.txt', '_encrypted.txt')
            with open(result_file_path, 'w') as file:
                file.write(ciphertext)
            messagebox.showinfo("Info", f"Encrypted file saved as {result_file_path}")

    def decrypt_file(self):
        key = self.get_key()
        if key is not None and hasattr(self, 'current_file_path'):
            with open(self.current_file_path, 'r') as file:
                ciphertext = file.read()
            plaintext = self.caesar_cipher(ciphertext, -key)
            result_file_path = self.current_file_path.replace('.txt', '_decrypted.txt')
            with open(result_file_path, 'w') as file:
                file.write(plaintext)
            messagebox.showinfo("Info", f"Decrypted file saved as {result_file_path}")

########################################
    def show_language_detection_interface(self):
        # Crearea unei noi ferestre pentru interfața de detectare a limbii
        lang_window = tk.Toplevel(self.root)
        lang_window.title("Language Detection")

        # Crearea unui frame principal pentru noua fereastră
        lang_frame = ttk.Frame(lang_window, padding="10")
        lang_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configurarea grilei pentru noua fereastră
        lang_window.columnconfigure(0, weight=1)
        lang_window.rowconfigure(0, weight=1)

        # Eticheta și câmpul pentru textul introdus de utilizator
        user_text_label = ttk.Label(lang_frame, text="Introduceți textul:")
        user_text_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        user_text_entry = ttk.Entry(lang_frame, width=50)
        user_text_entry.grid(row=0, column=1, padx=5, pady=5)

        # Butonul pentru a detecta limba textului introdus
        detect_button = ttk.Button(lang_frame, text="Detectează limba",
                                    command=lambda: self.detect_language(user_text_entry.get()))
        detect_button.grid(row=1, column=0, columnspan=2, pady=10)

        # Eticheta pentru afișarea rezultatului
        result_label = ttk.Label(lang_frame, text="Rezultat:")
        result_label.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.result_var = tk.StringVar()
        result_entry = ttk.Entry(lang_frame, textvariable=self.result_var, width=50, state="readonly")
        result_entry.grid(row=2, column=1, padx=5, pady=5)

    def detect_language(self, text):
        try:
            detected_language = detect(text)
            self.result_var.set(f"Limba detectată este: {detected_language}")
        except Exception as e:
            self.result_var.set(f"A intervenit o eroare: {e}")

#######################################

    def show_vigenere_cipher_interface(self):
        # Crearea unei noi ferestre pentru interfața Vigenere Cipher
        vigenere_window = tk.Toplevel(self.root)
        vigenere_window.title("Vigenere Cipher")

        # Crearea unui frame principal pentru noua fereastră
        vigenere_frame = ttk.Frame(vigenere_window, padding="10")
        vigenere_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configurarea grilei pentru noua fereastră
        vigenere_window.columnconfigure(0, weight=1)
        vigenere_window.rowconfigure(0, weight=1)

        # Eticheta și câmpul pentru textul de intrare
        input_text_label = ttk.Label(vigenere_frame, text="Text de intrare:")
        input_text_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        input_text_entry = ttk.Entry(vigenere_frame, width=50)
        input_text_entry.grid(row=0, column=1, padx=5, pady=5)

        # Eticheta și câmpul pentru cheia Vigenere
        vigenere_key_label = ttk.Label(vigenere_frame, text="Cheie Vigenere:")
        vigenere_key_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        vigenere_key_entry = ttk.Entry(vigenere_frame, width=20)
        vigenere_key_entry.grid(row=1, column=1, padx=5, pady=5)

        # Butonul pentru criptare
        encrypt_button = ttk.Button(vigenere_frame, text="Criptează",
                                    command=lambda: self.encrypt_vigenere(input_text_entry, vigenere_key_entry, result_entry))
        encrypt_button.grid(row=2, column=0, padx=5, pady=5)

        # Butonul pentru decriptare
        decrypt_button = ttk.Button(vigenere_frame, text="Decriptează",
                                    command=lambda: self.decrypt_vigenere(input_text_entry, vigenere_key_entry, result_entry))
        decrypt_button.grid(row=2, column=1, padx=5, pady=5)

        # Eticheta și câmpul pentru rezultat
        result_label = ttk.Label(vigenere_frame, text="Rezultat:")
        result_label.grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        result_entry = ttk.Entry(vigenere_frame, width=50)
        result_entry.grid(row=3, column=1, padx=5, pady=5)

    def encrypt_vigenere(self, plaintext_entry, key_entry, result_entry):
        plaintext = plaintext_entry.get()
        key = key_entry.get()
        ciphertext = self.vigenere_cipher(plaintext, key, mode="encrypt")
        result_entry.delete(0, tk.END)
        result_entry.insert(0, ciphertext)

    def decrypt_vigenere(self, plaintext_entry, key_entry, result_entry):
        ciphertext = plaintext_entry.get()
        key = key_entry.get()
        plaintext = self.vigenere_cipher(ciphertext, key, mode="decrypt")
        result_entry.delete(0, tk.END)
        result_entry.insert(0, plaintext)

    def vigenere_cipher(self, text, key, mode="encrypt"):
        result = ""
        key_index = 0
        for char in text:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - 65 if char.isupper() else ord(key[key_index % len(key)]) - 97
                if mode == "encrypt":
                    result += chr((ord(char) + shift - 65) % 26 + 65) if char.isupper() else chr((ord(char) + shift - 97) % 26 + 97)
                elif mode == "decrypt":
                    result += chr((ord(char) - shift - 65) % 26 + 65) if char.isupper() else chr((ord(char) - shift - 97) % 26 + 97)
                key_index += 1
            else:
                result += char
        return result


#########################################

    def show_kasiski_interface(self):
        # Crearea unei noi ferestre pentru interfața algoritmului Kasiski
        kasiski_window = tk.Toplevel(self.root)
        kasiski_window.title("Kasiski Algorithm")

        # Crearea unui frame principal pentru noua fereastră
        kasiski_frame = ttk.Frame(kasiski_window, padding="10")
        kasiski_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configurarea grilei pentru noua fereastră
        kasiski_window.columnconfigure(0, weight=1)
        kasiski_window.rowconfigure(0, weight=1)

        # Eticheta și câmpul pentru textul cifrat
        ciphertext_label = ttk.Label(kasiski_frame, text="Text cifrat:")
        ciphertext_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        ciphertext_entry = ttk.Entry(kasiski_frame, width=50)
        ciphertext_entry.grid(row=0, column=1, padx=5, pady=5)

        # Butonul pentru calculul distanțelor și a lungimii cheii
        analyze_button = ttk.Button(kasiski_frame, text="Analizează Textul",
                                    command=lambda: self.analyze_kasiski(ciphertext_entry.get()))
        analyze_button.grid(row=1, column=0, columnspan=2, pady=10)

        # Eticheta pentru afișarea rezultatului
        result_label = ttk.Label(kasiski_frame, text="Posibile lungimi ale cheii:")
        result_label.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.result_var = tk.StringVar()
        result_entry = ttk.Entry(kasiski_frame, textvariable=self.result_var, width=50, state="readonly")
        result_entry.grid(row=2, column=1, padx=5, pady=5)

    def analyze_kasiski(self, ciphertext):
        try:
            distances = self.get_repeated_distances(ciphertext)
            possible_key_lengths = self.find_possible_key_lengths(distances)
            self.result_var.set(", ".join(map(str, possible_key_lengths)))
        except Exception as e:
            self.result_var.set(f"A intervenit o eroare: {e}")

    def get_repeated_distances(self, ciphertext):
        repeated_distances = []
        for i in range(len(ciphertext)):
            for j in range(i + 3, len(ciphertext)):
                if ciphertext[i:i + 3] == ciphertext[j:j + 3]:
                    repeated_distances.append(j - i)
        return repeated_distances

    def find_possible_key_lengths(self, distances):
        counter = Counter(distances)
        possible_key_lengths = []
        for distance, count in counter.items():
            if count > 1:
                possible_key_lengths.append(distance)
        return possible_key_lengths

###########################################

    def show_one_time_pad_interface(self):
        # Crearea unei noi ferestre pentru interfața One-Time Pad
        one_time_pad_window = tk.Toplevel(self.root)
        one_time_pad_window.title("One-Time Pad")

        # Crearea unui frame principal pentru noua fereastră
        one_time_pad_frame = ttk.Frame(one_time_pad_window, padding="10")
        one_time_pad_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configurarea grilei pentru noua fereastră
        one_time_pad_window.columnconfigure(0, weight=1)
        one_time_pad_window.rowconfigure(0, weight=1)

        # Eticheta și câmpul pentru textul clar
        plaintext_label = ttk.Label(one_time_pad_frame, text="Text clar:")
        plaintext_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        plaintext_entry = ttk.Entry(one_time_pad_frame, width=50)
        plaintext_entry.grid(row=0, column=1, padx=5, pady=5)

        # Eticheta și câmpul pentru cheia
        key_label = ttk.Label(one_time_pad_frame, text="Cheie:")
        key_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        key_entry = ttk.Entry(one_time_pad_frame, width=50)
        key_entry.grid(row=1, column=1, padx=5, pady=5)

        # Butonul pentru criptare
        encrypt_button = ttk.Button(one_time_pad_frame, text="Criptează",
                                    command=lambda: encrypt_one_time_pad(plaintext_entry, key_entry, result_entry))
        encrypt_button.grid(row=2, column=0, padx=5, pady=5)

        # Butonul pentru decriptare
        decrypt_button = ttk.Button(one_time_pad_frame, text="Decriptează",
                                    command=lambda: decrypt_one_time_pad(plaintext_entry, key_entry, result_entry))
        decrypt_button.grid(row=2, column=1, padx=5, pady=5)

        # Eticheta și câmpul pentru rezultat
        result_label = ttk.Label(one_time_pad_frame, text="Rezultat:")
        result_label.grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        result_entry = ttk.Entry(one_time_pad_frame, width=50)
        result_entry.grid(row=3, column=1, padx=5, pady=5)


################################################
    def show_des_interface(self):
        # Crearea unei noi ferestre pentru interfața DES
        des_window = tk.Toplevel(self.root)
        des_window.title("DES")

        # Crearea unui frame principal pentru noua fereastră
        des_frame = ttk.Frame(des_window, padding="10")
        des_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configurarea grilei pentru noua fereastră
        des_window.columnconfigure(0, weight=1)
        des_window.rowconfigure(0, weight=1)

        # Eticheta și câmpul pentru textul de intrare
        input_text_label = ttk.Label(des_frame, text="Text de intrare:")
        input_text_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        input_text_entry = ttk.Entry(des_frame, width=50)
        input_text_entry.grid(row=0, column=1, padx=5, pady=5)

        # Eticheta și câmpul pentru cheia DES
        des_key_label = ttk.Label(des_frame, text="Cheie DES (8 biti):")
        des_key_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        des_key_entry = ttk.Entry(des_frame, width=20)
        des_key_entry.grid(row=1, column=1, padx=5, pady=5)

        # Butonul pentru criptare
        encrypt_button = ttk.Button(des_frame, text="Criptează",
                                    command=lambda: self.encrypt_des(input_text_entry, des_key_entry, result_entry))
        encrypt_button.grid(row=2, column=0, padx=5, pady=5)

        # Butonul pentru decriptare
        decrypt_button = ttk.Button(des_frame, text="Decriptează",
                                    command=lambda: self.decrypt_des(input_text_entry, des_key_entry, result_entry))
        decrypt_button.grid(row=2, column=1, padx=5, pady=5)

        # Eticheta și câmpul pentru rezultat
        result_label = ttk.Label(des_frame, text="Rezultat:")
        result_label.grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        result_entry = ttk.Entry(des_frame, width=50)
        result_entry.grid(row=3, column=1, padx=5, pady=5)

    def encrypt_des(self, plaintext_entry, key_entry, result_entry):
        plaintext = plaintext_entry.get()
        key = key_entry.get().encode()
        cipher = des(key, ECB, padmode=PAD_PKCS5)
        encrypted_data = cipher.encrypt(plaintext)
        result_entry.delete(0, tk.END)
        result_entry.insert(0, encrypted_data.hex())

    def decrypt_des(self, ciphertext_entry, key_entry, result_entry):
        ciphertext = bytes.fromhex(ciphertext_entry.get())
        key = key_entry.get().encode()
        cipher = des(key, ECB, padmode=PAD_PKCS5)
        decrypted_data = cipher.decrypt(ciphertext)
        result_entry.delete(0, tk.END)
        result_entry.insert(0, decrypted_data.decode())

###################################################
# Funcție pentru afișarea interfeței AES
    def show_aes_interface(self):
        # Crearea unei noi ferestre pentru interfața AES
        aes_window = tk.Toplevel(root)
        aes_window.title("AES")

        # Crearea unui frame principal pentru noua fereastră
        aes_frame = ttk.Frame(aes_window, padding="10")
        aes_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configurarea grilei pentru noua fereastră
        aes_window.columnconfigure(0, weight=1)
        aes_window.rowconfigure(0, weight=1)

        # Eticheta și câmpul pentru textul de intrare
        input_text_label = ttk.Label(aes_frame, text="Text de intrare:")
        input_text_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        input_text_entry = ttk.Entry(aes_frame, width=50)
        input_text_entry.grid(row=0, column=1, padx=5, pady=5)

        # Eticheta și câmpul pentru cheia AES
        aes_key_label = ttk.Label(aes_frame, text="Cheie AES (16, 24 sau 32 biti):")
        aes_key_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        aes_key_entry = ttk.Entry(aes_frame, width=50)
        aes_key_entry.grid(row=1, column=1, padx=5, pady=5)

        # Butonul pentru criptare
        encrypt_button = ttk.Button(aes_frame, text="Criptează",
                                    command=lambda: encrypt_aes_action(input_text_entry, aes_key_entry, result_entry))
        encrypt_button.grid(row=2, column=0, padx=5, pady=5)

        # Butonul pentru decriptare
        decrypt_button = ttk.Button(aes_frame, text="Decriptează",
                                    command=lambda: decrypt_aes_action(input_text_entry, aes_key_entry, result_entry))
        decrypt_button.grid(row=2, column=1, padx=5, pady=5)

        # Eticheta și câmpul pentru rezultat
        result_label = ttk.Label(aes_frame, text="Rezultat:")
        result_label.grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        result_entry = ttk.Entry(aes_frame, width=50)
        result_entry.grid(row=3, column=1, padx=5, pady=5)


##############################################

    def show_diffie_hellman_interface(self):
        # Crearea unei noi ferestre pentru interfața Diffie-Hellman
        dh_window = tk.Toplevel(self.root)
        dh_window.title("Diffie-Hellman")

        # Crearea unui frame principal pentru noua fereastră
        dh_frame = ttk.Frame(dh_window, padding="10")
        dh_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configurarea grilei pentru noua fereastră
        dh_window.columnconfigure(0, weight=1)
        dh_window.rowconfigure(0, weight=1)

            # Eticheta și câmpul pentru generator (g)
        generator_label = ttk.Label(dh_frame, text="Generator:")
        generator_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        generator_entry = ttk.Entry(dh_frame, width=20)
        generator_entry.grid(row=0, column=1, padx=5, pady=5)

            # Eticheta și câmpul pentru modul (p)
        modulus_label = ttk.Label(dh_frame, text="Modul:")
        modulus_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        modulus_entry = ttk.Entry(dh_frame, width=20)
        modulus_entry.grid(row=1, column=1, padx=5, pady=5)

            # Eticheta și câmpul pentru cheia privată a utilizatorului A
        private_key_a_label = ttk.Label(dh_frame, text="Cheie privată A:")
        private_key_a_label.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        private_key_a_entry = ttk.Entry(dh_frame, width=20)
        private_key_a_entry.grid(row=2, column=1, padx=5, pady=5)

            # Eticheta și câmpul pentru cheia privată a utilizatorului B
        private_key_b_label = ttk.Label(dh_frame, text="Cheie privată B:")
        private_key_b_label.grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        private_key_b_entry = ttk.Entry(dh_frame, width=20)
        private_key_b_entry.grid(row=3, column=1, padx=5, pady=5)

            # Butonul pentru calculul cheilor comune
        calculate_button = ttk.Button(dh_frame, text="Calculează Cheile Comune",
                                          command=lambda: self.calculate_diffie_hellman(generator_entry.get(),
                                                                                        modulus_entry.get(),
                                                                                        private_key_a_entry.get(),
                                                                                        private_key_b_entry.get(),
                                                                                        result_entry))
        calculate_button.grid(row=4, column=0, columnspan=2, pady=10)

            # Eticheta pentru afișarea rezultatului
        result_label = ttk.Label(dh_frame, text="Cheile Comune:")
        result_label.grid(row=5, column=0, padx=5, pady=5, sticky=tk.W)
        self.result_var = tk.StringVar()
        result_entry = ttk.Entry(dh_frame, textvariable=self.result_var, width=50, state="readonly")
        result_entry.grid(row=5, column=1, padx=5, pady=5)


    def calculate_diffie_hellman(self, generator, modulus, private_key_a, private_key_b, result_entry):
        try:
            generator = int(generator)
            modulus = int(modulus)
            private_key_a = int(private_key_a)
            private_key_b = int(private_key_b)

                # Calcularea cheilor comune
            public_key_a = pow(generator, private_key_a, modulus)
            public_key_b = pow(generator, private_key_b, modulus)
            common_key_a = pow(public_key_b, private_key_a, modulus)
            common_key_b = pow(public_key_a, private_key_b, modulus)

                # Verificarea dacă cheile comune sunt identice
            if common_key_a == common_key_b:
                    self.result_var.set(common_key_a)
            else:
                self.result_var.set("Cheile comune nu coincid!")
        except Exception as e:
            self.result_var.set(f"A intervenit o eroare: {e}")



###########################################

    def show_rsa_interface(self):
        # Crearea unei noi ferestre pentru interfața RSA
        rsa_window = tk.Toplevel(self.root)
        rsa_window.title("RSA")

        # Crearea unui frame principal pentru noua fereastră
        rsa_frame = ttk.Frame(rsa_window, padding="10")
        rsa_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configurarea grilei pentru noua fereastră
        rsa_window.columnconfigure(0, weight=1)
        rsa_window.rowconfigure(0, weight=1)

        # Eticheta și câmpul pentru textul de intrare
        input_text_label = ttk.Label(rsa_frame, text="Text de intrare:")
        input_text_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.input_text_entry = ttk.Entry(rsa_frame, width=50)
        self.input_text_entry.grid(row=0, column=1, padx=5, pady=5)

        # Butonul pentru criptare
        encrypt_button = ttk.Button(rsa_frame, text="Criptează",
                                    command=lambda: self.encrypt_rsa(self.input_text_entry, self.result_entry))
        encrypt_button.grid(row=1, column=0, padx=5, pady=5)

        # Butonul pentru decriptare
        decrypt_button = ttk.Button(rsa_frame, text="Decriptează",
                                    command=lambda: self.decrypt_rsa(self.input_text_entry, self.result_entry))
        decrypt_button.grid(row=1, column=1, padx=5, pady=5)

        # Eticheta și câmpul pentru rezultat
        result_label = ttk.Label(rsa_frame, text="Rezultat:")
        result_label.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.result_entry = ttk.Entry(rsa_frame, width=50)
        self.result_entry.grid(row=2, column=1, padx=5, pady=5)

        # Butonul pentru a selecta un fișier
        browse_button = ttk.Button(rsa_frame, text="Browse",
                                   command=self.browse_rsa_file)
        browse_button.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky=(tk.W, tk.E))

        # Butonul pentru criptarea fișierului
        encrypt_file_button = ttk.Button(rsa_frame, text="Criptează Fișier",
                                         command=self.encrypt_rsa_file)
        encrypt_file_button.grid(row=4, column=0, padx=5, pady=5)

        # Butonul pentru decriptarea fișierului
        decrypt_file_button = ttk.Button(rsa_frame, text="Decriptează Fișier",
                                         command=self.decrypt_rsa_file)
        decrypt_file_button.grid(row=4, column=1, padx=5, pady=5)

        # Generăm o pereche de chei de 512 biți
        (public_key, private_key) = rsa.newkeys(512)

        # Transmiterea cheilor în metodele de criptare și decriptare
        self.public_key = public_key
        self.private_key = private_key

    def encrypt_rsa(self, plaintext_entry, result_entry):
        plaintext = plaintext_entry.get()
        # Criptăm textul folosind cheia publică
        ciphertext = rsa.encrypt(plaintext.encode(), self.public_key)
        result_entry.delete(0, tk.END)
        result_entry.insert(0, ciphertext.hex())  # Convertim rezultatul în format hexazecimal

    def decrypt_rsa(self, ciphertext_entry, result_entry):
        ciphertext = bytes.fromhex(ciphertext_entry.get())  # Convertim textul cifrat din format hexazecimal
        # Decriptăm textul folosind cheia privată
        decrypted_text = rsa.decrypt(ciphertext, self.private_key).decode()
        result_entry.delete(0, tk.END)
        result_entry.insert(0, decrypted_text)

    def browse_rsa_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'r') as file:
                content = file.read()
                self.input_text_entry.delete(0, tk.END)
                self.input_text_entry.insert(0, content)
                self.current_rsa_file_path = file_path

    def encrypt_rsa_file(self):
        if hasattr(self, 'current_rsa_file_path'):
            with open(self.current_rsa_file_path, 'r') as file:
                plaintext = file.read()
            ciphertext = rsa.encrypt(plaintext.encode(), self.public_key)
            result_file_path = self.current_rsa_file_path.replace('.txt', '_encrypted_rsa.txt')
            with open(result_file_path, 'w') as file:
                file.write(ciphertext.hex())
            messagebox.showinfo("Info", f"Encrypted file saved as {result_file_path}")

    def decrypt_rsa_file(self):
        if hasattr(self, 'current_rsa_file_path'):
            with open(self.current_rsa_file_path, 'r') as file:
                ciphertext = bytes.fromhex(file.read())
            decrypted_text = rsa.decrypt(ciphertext, self.private_key).decode()
            result_file_path = self.current_rsa_file_path.replace('.txt', '_decrypted_rsa.txt')
            with open(result_file_path, 'w') as file:
                file.write(decrypted_text)
            messagebox.showinfo("Info", f"Decrypted file saved as {result_file_path}")

########################################
    def show_ecc_interface(self):
        # Crearea unei noi ferestre de dialog pentru ECC
        ecc_window = tk.Toplevel(self.root)
        ecc_window.title("Elliptic Curve Cryptography")

        # Crearea unui frame pentru ECC
        ecc_frame = ttk.Frame(ecc_window, padding="10")
        ecc_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Etichetă și câmp pentru introducerea mesajului
        message_label = ttk.Label(ecc_frame, text="Mesajul:")
        message_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        message_entry = ttk.Entry(ecc_frame, width=50)
        message_entry.grid(row=0, column=1, padx=5, pady=5)

        # Etichetă și câmp pentru afișarea rezultatului criptării sau decriptării
        result_label = ttk.Label(ecc_frame, text="Rezultat:")
        result_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        result_entry = ttk.Entry(ecc_frame, width=50)
        result_entry.grid(row=1, column=1, padx=5, pady=5)

        # Buton pentru criptare
        encrypt_button = ttk.Button(ecc_frame, text="Criptează",
                                     command=lambda: self.encrypt_ecc_action(message_entry, result_entry))
        encrypt_button.grid(row=2, column=0, padx=5, pady=5)

        # Buton pentru decriptare
        decrypt_button = ttk.Button(ecc_frame, text="Decriptează",
                                     command=lambda: self.decrypt_ecc_action(message_entry, result_entry))
        decrypt_button.grid(row=2, column=1, padx=5, pady=5)

    def encrypt_ecc_action(self, message_entry, result_entry):
        message = message_entry.get()

        # Generăm un nonce aleatoriu de 16 octeți
        nonce = os.urandom(16)

        # Generăm o pereche de chei ECC
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        # Generăm o cheie efemeră pentru criptare
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key)

        # Derivăm o cheie pentru criptare folosind PBKDF2
        derived_key = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'salt',
            iterations=100000,
            backend=default_backend()
        ).derive(shared_key)

        # Criptăm mesajul folosind cheia derivată și nonce-ul generat
        cipher = Cipher(algorithms.AES(derived_key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

        # Convertim textul criptat în format hexazecimal pentru a-l afișa în câmpul de rezultate
        result_entry.delete(0, tk.END)
        result_entry.insert(0, ciphertext.hex())

    def decrypt_ecc_action(self, ciphertext_entry, result_entry):
        # Obținem textul criptat din câmpul de intrare
        ciphertext_hex = ciphertext_entry.get()

        try:
            # Convertim textul criptat din format hexazecimal în bytes
            ciphertext = bytes.fromhex(ciphertext_hex)

            # Generăm o pereche de chei ECC
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            public_key = private_key.public_key()

            # Derivăm cheia comună utilizând cheia privată și cheia publică
            shared_key = private_key.exchange(ec.ECDH(), public_key)

            # Derivăm o cheie pentru criptare folosind PBKDF2
            derived_key = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'salt',
                iterations=100000,
                backend=default_backend()
            ).derive(shared_key)

            # Extragem nonce-ul de 16 octeți din textul criptat
            nonce = ciphertext[:16]

            # Decriptăm mesajul folosind cheia derivată și nonce-ul
            cipher = Cipher(algorithms.AES(derived_key), modes.CTR(nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_message = decryptor.update(ciphertext[16:]) + decryptor.finalize()

            # Afisăm mesajul decriptat
            result_entry.delete(0, tk.END)
            result_entry.insert(0, decrypted_message.decode())
        except Exception as e:
            # Dacă apare o eroare în timpul procesului de decriptare, afișăm un mesaj de eroare
            result_entry.delete(0, tk.END)
            result_entry.insert(0, "Eroare la decriptare: " + str(e))


#IMPORTANT - necesita o cheie privata pentru a fi decriptata




###################################################

    def show_hashing_interface(self):
        # Creăm o fereastră pentru algoritmi de hashing
        hashing_window = tk.Toplevel(self.root)
        hashing_window.title("Hashing Algorithms")

        # Frame pentru algoritmi de hashing
        hashing_frame = ttk.Frame(hashing_window, padding="10")
        hashing_frame.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))

        # Etichetă și câmp pentru introducerea textului
        input_label = ttk.Label(hashing_frame, text="Introduceți textul:")
        input_label.grid(row=0, column=0, sticky=tk.W)
        input_entry = ttk.Entry(hashing_frame, width=40)
        input_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        # Etichetă și câmp pentru afișarea rezultatului
        result_label = ttk.Label(hashing_frame, text="Rezultat:")
        result_label.grid(row=1, column=0, sticky=tk.W)
        result_entry = ttk.Entry(hashing_frame, width=40, state="readonly")
        result_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        # Funcție pentru calculul hash-ului
        def calculate_hash(algorithm):
            text = input_entry.get()
            if algorithm == "md5":
                hash_result = hashlib.md5(text.encode()).hexdigest()
            elif algorithm == "sha256":
                hash_result = hashlib.sha256(text.encode()).hexdigest()
            elif algorithm == "sha512":
                hash_result = hashlib.sha512(text.encode()).hexdigest()
            elif algorithm == "ripemd":
                hash_result = hashlib.new('ripemd160', text.encode()).hexdigest()

            # Actualizăm câmpul de rezultat cu hash-ul calculat
            result_entry.config(state="normal")
            result_entry.delete(0, tk.END)
            result_entry.insert(0, hash_result)
            result_entry.config(state="readonly")

        # Buton pentru algoritmul MD5
        md5_button = ttk.Button(hashing_frame, text="MD5", command=lambda: calculate_hash("md5"))
        md5_button.grid(row=2, column=0, pady=(10, 0), sticky=(tk.W, tk.E))

        # Buton pentru algoritmul SHA-256
        sha256_button = ttk.Button(hashing_frame, text="SHA256", command=lambda: calculate_hash("sha256"))
        sha256_button.grid(row=2, column=1, pady=(10, 0), sticky=(tk.W, tk.E))

        # Buton pentru algoritmul SHA-512
        sha512_button = ttk.Button(hashing_frame, text="SHA512", command=lambda: calculate_hash("sha512"))
        sha512_button.grid(row=3, column=0, pady=(10, 0), sticky=(tk.W, tk.E))

        # Buton pentru algoritmul RIPEMD-160
        ripemd_button = ttk.Button(hashing_frame, text="RIPEMD", command=lambda: calculate_hash("ripemd"))
        ripemd_button.grid(row=3, column=1, pady=(10, 0), sticky=(tk.W, tk.E))


####################################
if __name__ == "__main__":
    root = tk.Tk()
    app = InterfataCriptografie(root)
    root.mainloop()
