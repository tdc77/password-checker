import requests
import hashlib
import sys
from tkinter import *

win = Tk()
win.geometry("800x600")
win.title("CHECK PASSWORD SAFETY")


password = StringVar()
msg = StringVar()
msg.set('')


frame = Frame(win)
frame.grid(row=1, column=0, sticky='w')


def request_api_data(query_char):
    global msg
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    
    if res.status_code != 200:
        msg.set(f'Error fetching: {res.status_code}, check api and try again')
    return res

def get_password_leaks_count(hashes, hash_to_check):
    
    hashes = (line.split(':') for line in hashes.text.splitlines()  )
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwnedapi_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    print(first5_char, tail)
    return get_password_leaks_count(response, tail)


def main():
    global password, msg
    password = passwordenter.get()
    if password != None:
        count = pwnedapi_check(password)
        if count:
            msg.set(f'That password was found {count} times...you should change password')
            passwordenter.delete(0, END)
        else:
            msg.set(f'That password was not found.  Carry ON!')
            passwordenter.delete(0, END)
      

   
      
passwordenter = Entry(frame, width=25, textvariable=password, show='*')
passwordenter.grid(row=0, column=1, pady=20, sticky='w')

passwordlabel = Label(frame, text="Enter password:")
passwordlabel.grid(row=0, column=0, padx=20, pady=20, sticky='w') 

checkbtn = Button(frame, text="Check", width=15, command=main)
checkbtn.grid(row=0, column=3, sticky='ew')

title_label = Label(win, text="Check if password has been compromised", font='Arial')
title_label.grid(row=0, column=0, sticky='w')

msglabel = Label(win, font='Arial', textvariable=msg)
msglabel.grid(row=4, column=0, sticky='w')


  
  
 
  
win.mainloop()