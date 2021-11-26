import random
import ElGamal
from tkinter import *
from tkinter import ttk, messagebox
from PIL import ImageTk, Image

# setup interface
root = Tk()
root.title('ElGamal Cryptosystem')
root.geometry('820x700')
root.resizable(False, False)

backgound_image = ImageTk.PhotoImage(Image.open('bg.png'))
backgound_label = Label(image=backgound_image, height=700, width=820)
backgound_label.place(x=0, y=0, relwidth=1, relheight=1)

credits_label = Label(text='ElGamal Cryptosystem by Group 5')
credits_label.place(relx=1.0, rely=1.0, anchor='se')

#title UI
title = Label(root, text='Chữ ký ElGamal', font=('TkDefaultFont', 20))
title.place(x=300, y=10)

# keys UI
key_label = Label(root, text='Khóa')
key_label.place(x=40, y=60)

# number of bit label UI
bitNum_label = Label(root, text='Số bit của p')
bitNum_label.place(x=190, y=64)

# OptionMenu for select number of bit
option= [100, 500, 1000]
bitNum_value= IntVar()
bitNum_value.set(option[0])
bitNum_option = OptionMenu(root, bitNum_value, *option)
bitNum_option.place(x=270, y=60)

# anpha input UI
anpha_label = Label(root, text='anpha = ')
anpha_label.place(x=110, y=108)

anpha_text = Text(root, width=65, height=2)
anpha_text.place(x=170, y=100)

# p input UI
p_label = Label(root, text='p = ')
p_label.place(x=135, y=185)

p_text = Text(root, width=65, height=4)
p_text.place(x=170, y=160)

# a input UI
a_label = Label(root, text='a = ')
a_label.place(x=135, y=265)

a_text = Text(root, width=65, height=3)
a_text.place(x=170, y=250)

# generate keys function
def keys_generate():
    # delete old text
    result_text.delete('1.0', END)
    cipher_message_text.delete('1.0', END)
    decrypt_message_text.delete('1.0', END)

    #generate keys
    p = ElGamal.find_prime(bitNum_value.get(), 32)
    p_text.delete('1.0', END)
    p_text.insert(END, p)
    g = ElGamal.find_primitive_root(p)
    anpha_text.delete('1.0', END)
    anpha_text.insert(END, g)
    x = random.randint( 1, (p - 1) // 2 )
    a_text.delete('1.0', END)
    a_text.insert(END, x)

# generate keys button
keys_generate_button = Button(text='Tạo khóa', bg='white', fg='black', command=keys_generate)
keys_generate_button.place(x=500, y=64)

# check keys function
def keys_check():
    messagebox.showerror("Error", "Check keys is not active now, please try again later")

# check keys button
keys_check_button = Button(text='Kiểm tra khóa', bg='white', fg='black', command=keys_check)
keys_check_button.place(x=600, y=64)

#separator
separator = ttk.Separator(root, orient='horizontal')
separator.place(x=70, y=320, relwidth=0.8)

# M UI
original_message_label = Label(root, text='Tin nhắn gốc')
original_message_label.place(x=40, y=365)

original_message_text = Text(root, width=65, height=5)
original_message_text.place(x=170, y=340)

# encrypt function
def encrypt():
    # delete old text
    result_text.delete('1.0', END)
    cipher_message_text.delete('1.0', END)
    decrypt_message_text.delete('1.0', END)
    # get publicKey
    iNumBits = bitNum_value.get()
    p = int(p_text.get('1.0', "end-1c"))
    g = int(anpha_text.get('1.0', "end-1c"))
    x = int(a_text.get('1.0', "end-1c"))
    h = ElGamal.modexp( g, x, p )
    publicKey = ElGamal.PublicKey(p, g, h, iNumBits)
    # get message
    message = original_message_text.get('1.0', "end-1c")
    # encrypt
    cipher_message = ElGamal.encrypt(publicKey, message)
    cipher_message_text.insert(END, cipher_message)


# encrypt button
encrypt_button = Button(text='Mã hóa', bg='white', fg='black', command=encrypt)
encrypt_button.place(x=730, y=365)

# C UI
cipher_message_label = Label(root, text='Bản mã hóa')
cipher_message_label.place(x=40, y=475)

cipher_message_text = Text(root, width=65, height=5)
cipher_message_text.place(x=170, y=450)

# decrypt fuction
def decrypt():
    # delete old text
    result_text.delete('1.0', END)
    decrypt_message_text.delete('1.0', END)
    # get publicKey
    iNumBits = bitNum_value.get()
    p = int(p_text.get('1.0', "end-1c"))
    g = int(anpha_text.get('1.0', "end-1c"))
    x = int(a_text.get('1.0', "end-1c"))
    privateKey = ElGamal.PrivateKey(p, g, x, iNumBits)
    # get cipher message
    cipher_message = cipher_message_text.get('1.0', "end-1c")
    # decrypt
    decrypt_message = ElGamal.decrypt(privateKey, cipher_message)
    decrypt_message_text.insert(END, decrypt_message)

# decrypt button
decrypt_button = Button(text='Giải mã', bg='white', fg='black', command=decrypt)
decrypt_button.place(x=730, y=475)

# decrypt result
decrypt_message_label = Label(root, text='Bản giải mã')
decrypt_message_label.place(x=40, y=590)

decrypt_message_text = Text(root, width=65, height=5)
decrypt_message_text.place(x=170, y=560)

# test function
def test():
    result_text.delete('1.0', END)
    # get original message
    original_message = original_message_text.get('1.0', "end-1c")
    #get decrypt message
    decrypt_message = decrypt_message_text.get('1.0', "end-1c")
    # show result if the original message as same as decrypt message
    if original_message == decrypt_message:
        result_text.insert(END, 'đúng' )
    else:
        result_text.insert(END, 'sai')

test_button = Button(text='Kiểm tra', bg='white', fg='black', command=test)
test_button.place(x=730, y=590)

# result
result_label = Label(root, text='Kết quả')
result_label.place(x=370, y=660)

result_text = Text(root, width=10, height=1)
result_text.place(x=430, y=660)

root.mainloop()