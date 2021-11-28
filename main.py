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

# số bit của p
bitNum_label = Label(root, text='Số bit của p')
bitNum_label.place(x=190, y=64)

# các lựa chọn cho số bit của p
option= [100, 500, 1000]
bitNum_value= IntVar()
bitNum_value.set(option[0])
bitNum_option = OptionMenu(root, bitNum_value, *option)
bitNum_option.place(x=270, y=60)

# anpha
anpha_label = Label(root, text='anpha = ')
anpha_label.place(x=110, y=108)

anpha_text = Text(root, width=65, height=2)
anpha_text.place(x=170, y=100)

# p
p_label = Label(root, text='p = ')
p_label.place(x=135, y=185)

p_text = Text(root, width=65, height=4)
p_text.place(x=170, y=160)

# a
a_label = Label(root, text='a = ')
a_label.place(x=135, y=265)

a_text = Text(root, width=65, height=3)
a_text.place(x=170, y=250)

# tạo khóa
def keys_generate():
    # xóa khóa cũ
    result_text.delete('1.0', END)
    cipher_message_text.delete('1.0', END)
    decrypt_message_text.delete('1.0', END)

    # tạo khóa mới
    p = ElGamal.generate_keys(bitNum_value.get())
    p_text.delete('1.0', END)
    p_text.insert(END, p)
    g = ElGamal.find_primitive_root(p)
    anpha_text.delete('1.0', END)
    anpha_text.insert(END, g)
    x = random.randint( 1, (p - 1) // 2 )
    a_text.delete('1.0', END)
    a_text.insert(END, x)

keys_generate_button = Button(text='Tạo khóa', bg='white', fg='black', command=keys_generate)
keys_generate_button.place(x=500, y=64)

# kiểm tra khóa đã thỏa mãn điều kiện hay chưa
def keys_check():
    messagebox.showerror("Error", "Check keys is not active now, please try again later")

keys_check_button = Button(text='Kiểm tra khóa', bg='white', fg='black', command=keys_check)
keys_check_button.place(x=600, y=64)

# separator
separator = ttk.Separator(root, orient='horizontal')
separator.place(x=70, y=320, relwidth=0.8)

# bản tin gốc
original_message_label = Label(root, text='Tin nhắn gốc')
original_message_label.place(x=40, y=365)

original_message_text = Text(root, width=65, height=5)
original_message_text.place(x=170, y=340)

# mã hóa bản tin gốc
def encrypt():
    
    # xóa văn bản mã hóa cũ
    result_text.delete('1.0', END)
    cipher_message_text.delete('1.0', END)
    decrypt_message_text.delete('1.0', END)
    
    # lấy khóa
    iNumBits = bitNum_value.get()
    p = int(p_text.get('1.0', "end-1c"))
    g = int(anpha_text.get('1.0', "end-1c"))
    x = int(a_text.get('1.0', "end-1c"))
    h = ElGamal.modexp( g, x, p )
    publicKey = ElGamal.PublicKey(p, g, h, iNumBits)
    
    # lấy bản tin gốc
    message = original_message_text.get('1.0', "end-1c")
    
    # mã hóa và hiển thị bản tin mã hóa
    cipher_message = ElGamal.encrypt(publicKey, message)
    cipher_message_text.insert(END, cipher_message)

encrypt_button = Button(text='Mã hóa', bg='white', fg='black', command=encrypt)
encrypt_button.place(x=730, y=365)

# bản tin mã hóa
cipher_message_label = Label(root, text='Bản mã hóa')
cipher_message_label.place(x=40, y=475)

cipher_message_text = Text(root, width=65, height=5)
cipher_message_text.place(x=170, y=450)

# giải mã
def decrypt():

    # xóa bản tin giải mã
    result_text.delete('1.0', END)
    decrypt_message_text.delete('1.0', END)

    # lấy khóa
    iNumBits = bitNum_value.get()
    p = int(p_text.get('1.0', "end-1c"))
    g = int(anpha_text.get('1.0', "end-1c"))
    x = int(a_text.get('1.0', "end-1c"))
    privateKey = ElGamal.PrivateKey(p, g, x, iNumBits)
    
    # lấy bản tin mã hóa
    cipher_message = cipher_message_text.get('1.0', "end-1c")
    
    # giải mã và hiển thị bản tin sau khi giải mã 
    decrypt_message = ElGamal.decrypt(privateKey, cipher_message)
    decrypt_message_text.insert(END, decrypt_message)

decrypt_button = Button(text='Giải mã', bg='white', fg='black', command=decrypt)
decrypt_button.place(x=730, y=475)

# bản tin giải mã
decrypt_message_label = Label(root, text='Bản giải mã')
decrypt_message_label.place(x=40, y=590)

decrypt_message_text = Text(root, width=65, height=5)
decrypt_message_text.place(x=170, y=560)

# kiểm tra bản tin giải mã có giống với bản tin gốc hay không
def test():

    # xóa kết quả so sánh cũ
    result_text.delete('1.0', END)
    
    # lấy bản tin gốc
    original_message = original_message_text.get('1.0', "end-1c")
    
    # lấy bản tin giải mã
    decrypt_message = decrypt_message_text.get('1.0', "end-1c")
    
    # so sánh và hiển thị kết quả
    if original_message == decrypt_message:
        result_text.insert(END, 'đúng' )
    else:
        result_text.insert(END, 'sai')

test_button = Button(text='Kiểm tra', bg='white', fg='black', command=test)
test_button.place(x=730, y=590)

# kết quả kiểm tra
result_label = Label(root, text='Kết quả')
result_label.place(x=370, y=660)

result_text = Text(root, width=10, height=1)
result_text.place(x=430, y=660)


root.mainloop()