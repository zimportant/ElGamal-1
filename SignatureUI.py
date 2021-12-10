import random
import ElGamal
from tkinter import *
from tkinter import ttk, messagebox
from PIL import ImageTk, Image

import miller_rabin.GenPrime as gp
import miller_rabin.IsPrime as ip

# setup interface
root = Tk()
root.title('ElGamal Cryptosystem')
root.geometry('1200x650')
root.resizable(False, False)

backgound_image = ImageTk.PhotoImage(Image.open('bg.png'))
backgound_label = Label(image=backgound_image, height=650, width=1200)
backgound_label.place(x=0, y=0, relwidth=1, relheight=1)

credits_label = Label(text='ElGamal Cryptosystem by Group 5')
credits_label.place(relx=1.0, rely=1.0, anchor='se')

#title UI
title = Label(root, text='Chữ ký ElGamal', font=('TkDefaultFont', 20))
title.place(x=500, y=10)

# keys UI
key_label = Label(root, text='Khóa')
key_label.place(x=40, y=60)

# số bit của p
bitNum_label = Label(root, text='Số bit của p')
bitNum_label.place(x=180, y=70)

# các lựa chọn cho số bit của p
option= [100, 500, 1000]
bitNum_value= IntVar()
bitNum_value.set(option[0])
bitNum_option = OptionMenu(root, bitNum_value, *option)
bitNum_option.place(x=260, y=65)

# p
p_label = Label(root, text='p = ')
p_label.place(x=40, y=140)

p_text = Text(root, width=51, height=6)
p_text.place(x=80, y=110)

# alpha
alpha_label = Label(root, text='alpha = ')
alpha_label.place(x=25, y=270)

alpha_text = Text(root, width=51, height=6)
alpha_text.place(x=80, y=230)

# a
a_label = Label(root, text='a = ')
a_label.place(x=40, y=390)

a_text = Text(root, width=51, height=6)
a_text.place(x=80, y=350)

# beta
beta_label = Label(root, text='beta = ')
beta_label.place(x=30, y=510)

beta_text = Text(root, width=51, height=6)
beta_text.place(x=80, y=470)

# tạo khóa
def keys_generate():
    
    # xóa khóa cũ
    cipher_message_text.delete('1.0', END)
    p_text.delete('1.0', END)
    alpha_text.delete('1.0', END)
    a_text.delete('1.0', END)
    beta_text.delete('1.0', END)

    # tạo khóa mới
    p = gp.generatePrime(bitNum_value.get(), ElGamal.ATTEMPTS)
    p_text.insert(END, p)
    alpha = ElGamal.find_primitive_root(p)
    alpha_text.insert(END, alpha)
    a = random.randint( 1, (p - 1) // 2 )
    a_text.insert(END, a)
    beta = ElGamal.modexp(alpha, a, p)
    beta_text.insert(END, beta)

keys_generate_button = Button(text='Tạo khóa', bg='white', fg='black', command=keys_generate)
keys_generate_button.place(x=180, y=600)

# kiểm tra khóa đã thỏa mãn điều kiện hay chưa
def keys_check():
    
    # lấy khóa
    p = int(p_text.get('1.0', "end-1c"))
    alpha = int(alpha_text.get('1.0', "end-1c"))
    a = int(a_text.get('1.0', 'end-1c'))
    beta = beta_text.get('1.0', 'end-1c')

    # kiểm tra beta đã được nhập chưa
    # chưa được nhập --> tự động tính
    # đã được nhập --> kiểm tra giá trị
    if beta:
        beta = int(beta)
        # kiểm tra khóa
        if ip.isPrime(p, ElGamal.ATTEMPTS) == False:
            messagebox.showerror("Error", "p phải là số nguyên tố")
        elif ElGamal.is_primitive_root(alpha, p) == False:
            messagebox.showerror("Error", "alpha phải là thành phần nguyên thủy của p")
        elif a < 1 or a > (p-2):
            messagebox.showerror("Error", "a phải có giá trị nằm trong khoảng [1, p-2]")
        elif beta != ElGamal.modexp(alpha, a, p):
            messagebox.showerror("Error", "beta phải bằng alpha ^ a mod p")
        else :
            messagebox.showinfo('Thông tin khóa', "Khóa của bạn hợp lệ")
    else:
        if ip.isPrime(p, ElGamal.ATTEMPTS) == False:
            messagebox.showerror("Error", "p phải là số nguyên tố")
        elif ElGamal.is_primitive_root(alpha, p) == False:
            messagebox.showerror("Error", "alpha phải là thành phần nguyên thủy của p")
        elif a < 1 or a > (p-2):
            messagebox.showerror("Error", "a phải có giá trị nằm trong khoảng [1, p-2]")
        else:
            beta = ElGamal.modexp(alpha, a, p)
            beta_text.insert(END, beta)
            messagebox.showinfo('Thông tin khóa', "Khóa của bạn hợp lệ")

keys_check_button = Button(text='Kiểm tra khóa', bg='white', fg='black', command=keys_check)
keys_check_button.place(x=280, y=600)

# separator
separator = ttk.Separator(root, orient='horizontal')
separator.place(x=500, y=320, relwidth=0.7)

# separator
separator = ttk.Separator(root, orient='vertical')
separator.place(x=500, y=60, relheight=0.9)

# keys UI
signature_label = Label(root, text='Ký văn bản')
signature_label.place(x=520, y=60)

# bản tin gốc
original_message_label = Label(root, text='Văn bản\ncần ký')
original_message_label.place(x=530, y=150)

original_message_text = Text(root, width=65, height=12)
original_message_text.place(x=600, y=80)

# ký văn bản
def encrypt():
    
    # xóa chữ ký cũ
    cipher_message_text.delete('1.0', END)

    # lấy khóa
    p = int(p_text.get('1.0', "end-1c")) # Prime number
    alpha = int(alpha_text.get('1.0', "end-1c")) # Primitive root
    a = int(a_text.get('1.0', "end-1c")) # Random
    beta = int(beta_text.get('1.0', 'end-1c'))

    # kiểm tra khóa
    if ElGamal.check_keys(p, alpha, a, beta) == True:

        privateKey = ElGamal.PrivateKey(a)
        publicKey = ElGamal.PublicKey(p, alpha, beta)
        
        # lấy bản tin gốc
        message = original_message_text.get('1.0', "end-1c")
        
        # mã hóa và hiển thị bản tin mã hóa
        signature_message = ElGamal.sign_message(message, privateKey, publicKey, ElGamal.ALPHABET)
        cipher_message_text.insert(END, signature_message)
        # cipher_message = ElGamal.encrypt(publicKey, message)
    else:
        messagebox.showerror("Error", "Khóa của bạn không hợp lệ, bấm nút Kiểm tra khóa để biết thêm thông tin")

encrypt_button = Button(text='Ký văn bản', bg='white', fg='black', command=encrypt)
encrypt_button.place(x=800, y=285)

# bản tin mã hóa
cipher_message_label = Label(root, text='Chữ ký')
cipher_message_label.place(x=530, y=430)

cipher_message_text = Text(root, width=65, height=12)
cipher_message_text.place(x=600, y=350)

# Kiểm tra chữ ký
def decrypt():

    # lấy khóa
    p = int(p_text.get('1.0', "end-1c"))
    alpha = int(alpha_text.get('1.0', "end-1c"))
    beta = int(beta_text.get('1.0', 'end-1c'))
    publicKey = ElGamal.PublicKey(p, alpha, beta)
    
    # kiểm tra khóa
    if ElGamal.check_publickey(p, alpha, beta) == True:
        # lấy văn bản và chữ ký
        message = original_message_text.get('1.0', "end-1c")
        signature = cipher_message_text.get('1.0', "end-1c")
        print(message, signature)

        sig_num = ElGamal.SigNum.of_text(signature)
        
        # Xác thực chữ ký và hiển thị kết quả xác thực 
        is_verified = ElGamal.verify_message(sig_num, message, publicKey, ElGamal.ALPHABET)
        if is_verified:
            messagebox.showinfo("Chữ ký", "Chữ ký được xác thực")
        else:
            messagebox.showerror("Chữ ký", "Chữ ký không được xác thực")
    else:
        messagebox.showerror("Error", "Khóa của bạn không hợp lệ, bấm nút Kiểm tra khóa để biết thêm thông tin")

decrypt_button = Button(text='Kiểm tra chữ ký', bg='white', fg='black', command=decrypt)
decrypt_button.place(x=800, y=565)


root.mainloop()