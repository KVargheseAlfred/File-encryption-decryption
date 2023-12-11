from tkinter import *
from tkinter import filedialog
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

root = Tk()
root.title('AES encryption software')
root.geometry("600x200")
root.minsize(600,200)
root.maxsize(600,200)
root.iconbitmap('favicon.ico')
bg = PhotoImage(file="images1.png")
my_label = Label(root,image=bg)
my_label.place(x=0,y=0,relwidth=1,relheight=1)

def open_file():
    file_path.delete(0,END)
    root.filename = filedialog.askopenfilename(initialdir="C:/", title="select a file",filetypes=(("video files", "*.mp4"), ("all files", "*.*")))
    my_file = root.filename
    file_path.insert(0,my_file)

def key_data():
    key1 = key_entry.get()
    key = key1.encode()
    return key

def enc_data():
    key = key_data()
    h = SHA256.new()
    # key = input("enter the key:").encode()
    h.update(key)
    key = h.hexdigest()
    key = key[0:32].encode()
    # key = get_random_bytes(16)
    # key = b'tttttttttttttttttttttttttttttttt'
    my_file = file_path.get()
    infile = open(my_file, "rb")
    data = infile.read()
    infile.close()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    file_out = open(my_file, "wb")
    [file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
    file_out.close()
    key_entry.delete(0,END)
    file_path.delete(0, END)

def dec_data():
    key = key_data()
    h = SHA256.new()
    h.update(key)
    key = h.hexdigest()
    key = key[0:32].encode()
    my_file = file_path.get()
    file_in = open(my_file, "rb")
    nonce, tag, ciphertext = [file_in.read(x) for x in (16, 16, -1)]

    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    x = open(my_file, "wb")
    x.write(data)
    x.close()
    key_entry.delete(0, END)
    file_path.delete(0, END)

file_path = Entry(root, width=50)
my_btn = Button(root, text="open file", command=open_file)
key_entry = Entry(root, width = 35, borderwidth=5)
key_label = Label(root,text = "Enter the key")
enc_btn = Button(root, text="encrypt",command=enc_data)
dec_btn = Button(root, text="decrypt",command=dec_data)


my_btn.grid(row=0,column=0,padx = 30,pady = 20)
file_path.grid(row=0,column=1,padx=20)
key_entry.grid(row=1,column=1,padx=0)
key_label.grid(row = 1,column=0,padx = 0)
enc_btn.grid(row = 2,column=0,pady = 30,ipadx=20,sticky=E)
dec_btn.grid(row = 2, column=1,ipadx=20)


root.mainloop()



