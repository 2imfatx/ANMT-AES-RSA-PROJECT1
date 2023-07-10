import json
import AES_RSA_SHA
import hashlib
import random
import tkinter as tk
from tkinter import filedialog

def choose_file_encrypt():
    file_path = filedialog.askopenfilename()

    if file_path:
        Ks = AES_RSA_SHA.generate_aes_key()
        public_key, private_key = AES_RSA_SHA.generate_rsa_key_pair(2048)

        #print("private key: ", private_key)

        output_file_path = file_path + ".enc"
        AES_RSA_SHA.encrypt_file_with_aes(file_path, output_file_path, Ks)

        Kx = AES_RSA_SHA.encrypt_rsa(Ks, public_key)
        HKprivate = AES_RSA_SHA.sha1(str(private_key))
        #print("hash private key: ", HKprivate)
        AES_RSA_SHA.save_metadata_to_file(output_file_path + ".metadata", Kx, HKprivate)

        AES_RSA_SHA.save_key_to_file(output_file_path + ".key",private_key[0] , private_key[1])
        
        status_label.config(text="Encryption successful. File saved at: " + output_file_path)
    else:
        status_label.config(text="No file selected.")


def check_key():
    d = input_d.get()
    n = input_n.get()


    output_file_path = file_path + ".dec"

    ciphertext = AES_RSA_SHA.read_hex_file(file_path)
    #print("Ciphertext: ", ciphertext)
    
    metadata = AES_RSA_SHA.read_json_file(file_path + ".metadata")
    Kprivate = (int(d), int(n))
    #print("Kprivate: ", Kprivate)

    #print("Hash value: ", metadata['HKprivate'])
    #print("Hash value: ", sha1(str(Kprivate)))

    if metadata['HKprivate'] == AES_RSA_SHA.sha1(str(Kprivate)):
        #print("Hash value matched.")
        status_label.config(text="Hash value matched.")
    else:
        #print("Hash value not matched.")
        status_label.config(text="Hash value not matched.")
        return
        
    Ks = AES_RSA_SHA.decrypt_rsa(metadata['Kx'], Kprivate)
    #print ("Ks: ", Ks)
    
    decrypted = AES_RSA_SHA.aes_decrypt(ciphertext, Ks)

    str_data = ''.join(chr(i) for i in decrypted)
    #print("Decrypted: ", str_data)

    AES_RSA_SHA.write_file(output_file_path, str_data)
    
    status_label.config(text="Decryption successful. File saved at: " + output_file_path)



def get_user_input():
    user_input = input_box.get()
    while user_input!="1" and user_input!="2":
        user_input = input_box.get()
    global stored_input
    stored_input = user_input
    if stored_input=="1":
        label2 = tk.Label(decryptWindow, text="d ")
        label2.pack()
        global input_d, input_n 
        input_d = tk.Entry(decryptWindow)
        input_d.pack()
        
        label3 = tk.Label(decryptWindow, text="n ")
        label3.pack()
        input_n = tk.Entry(decryptWindow)
        input_n.pack()

        button = tk.Button(decryptWindow, text="Enter", command=check_key)
        button.pack()

        
        
    else:
        output_file_path = file_path + ".dec"
        file_path1 = filedialog.askopenfilename()
        ciphertext = AES_RSA_SHA.read_hex_file(file_path)
        #print("Ciphertext: ", ciphertext)
        
        metadata = AES_RSA_SHA.read_json_file(file_path + ".metadata")

        key_private = AES_RSA_SHA.read_json_file(file_path1)
        Kprivate = (int(key_private['d']), int(key_private['n']))

        #print("Kprivate: ", Kprivate)

        #print("Hash value: ", metadata['HKprivate'])
        #print("Hash value: ", sha1(str(Kprivate)))
        
        if metadata['HKprivate'] == AES_RSA_SHA.sha1(str(Kprivate)):
            #print("Hash value matched.")
            status_label.config(text="Hash value matched.")
        else:
            #print("Hash value not matched.")
            status_label.config(text="Hash value not matched.")
            return

        Ks = AES_RSA_SHA.decrypt_rsa(metadata['Kx'], Kprivate)
        #print ("Ks: ", Ks)
        
        decrypted = AES_RSA_SHA.aes_decrypt(ciphertext, Ks)

        str_data = ''.join(chr(i) for i in decrypted)
        #print("Decrypted: ", str_data)

        AES_RSA_SHA.write_file(output_file_path, str_data)
        
        status_label.config(text="Decryption successful. File saved at: " + output_file_path)


def choose_file_decrypt():
    global file_path
    file_path = filedialog.askopenfilename()

    if file_path:
        global decryptWindow
        decryptWindow=tk.Toplevel(root)
        decryptWindow.title("Decrypt Window")
        decryptWindow.geometry("400x200")

        global label, label1
        label = tk.Label(decryptWindow, text="1. Enter key private")
        label1 = tk.Label(decryptWindow, text="2. Choose from file to get key")
        label.pack()
        label1.pack()
        global input_box
        input_box = tk.Entry(decryptWindow)
        input_box.pack()
        button = tk.Button(decryptWindow, text="Please choose", command=get_user_input)
        button.pack()
        decryptWindow.wait_window(decryptWindow)

    else:
        status_label.config(text="No file selected.")


# B-2
#two one nine two
#plaintext = [0x74, 0x77, 0x6F, 0x20, 0x6F, 0x6E, 0x65, 0x20, 0x6E, 0x69, 0x6E, 0x65] #two one nine two
#Key = [0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75]
NUM_ROUNDS = 10
KEY_SIZE = 16
# B
root = tk.Tk()
root.title("Computer Security - Assignment 1")

frame = tk.Frame(root, padx=100, pady=100)
frame.pack()

choose_button_encrypt = tk.Button(frame, text="Choose file to encrypt", command=choose_file_encrypt)
choose_button_encrypt.pack()

choose_button_decrypt = tk.Button(frame, text="Choose file to decrypt", command=choose_file_decrypt)
choose_button_decrypt.pack()

status_label = tk.Label(frame, text="")
status_label.pack()

root.mainloop()