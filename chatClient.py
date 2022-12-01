
'''
Created 12 Dec 2021
@author: Paola Gomez Reyna - pgomezr0

Computer Security Assignment 2:
Real Time Chat using Diffie Helmman
Key Exchange and AES encryption algorithm
'''

import socket, threading, easygui
import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter.messagebox import askokcancel
from keyExchange import DiffieHellman
from encryption import AEStandard

class Client:
    def __init__(self, key_size, operation_mode):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Creates client socket object using IPv4 adresess and TCP
        self.host = '127.0.0.1'
        self.port = 9091 # Use any value between 0 and 65535 (TCP)

        self.key_size = key_size
        self.operation_mode = operation_mode   

        # Key Exchange with Diffie Hellman
        self.msg_size = 2048
        self.client_key = DiffieHellman(key_size)
        self.client_public_key = str(self.client_key.create_public_key())

        self.building_gui = 'NF' # NF for not finished building GUI

    def connect_client(self):

        try:
            self.client.connect((self.host, self.port))
            print(f'Sucessful! Connected to server [{self.host}] and port [{self.port}]')
        
        except:
            messagebox.showerror('Connection Error', 'Unable to connect to server [{self.host}] and port [{self.port}]')

        # Enter a username
        self.username = easygui.enterbox('Enter a username', 'Username')

        if self.username != '':
            self.client.send(self.username.encode('utf-8'))
        else:
            messagebox.showerror('Invalid username', 'Username cannot be empty')

        # Exchange of keys
        self.key_exchange()

        threading.Thread(target=self.client_gui).start()
        threading.Thread(target=self.listen).start()
        

    def key_exchange(self):

        # Receive Server's Public Key
        server_public_key = int(self.client.recv(self.msg_size).decode('utf-8'))

        # Create Client's Private Key
        self.client_private_key = self.client_key.create_secretshared_key(server_public_key)

        # Send Client's Public Key
        self.client.send(self.client_public_key.encode('utf-8'))
        
        self.aes_object = AEStandard(self.client_private_key, self.key_size) 

    # Listens for any new message from server
    def listen(self):
        
        while True:
            try:
                message = self.client.recv(self.msg_size) # Receive message from server

                if self.building_gui == 'F':

                    # Decryption of message
                    if self.operation_mode == 'ECB':
                        message = self.aes_object.decrypt_ECB(message)
                    
                    elif self.operation_mode == 'CFB':
                        message = self.aes_object.decrypt_CFB(message)
                    
                    else:
                        message = self.aes_object.decrypt_CBC(message)

                    self.chat_area.config(state='normal') # Set chat screen area to write in it
                    self.chat_area.insert('end', message) # Write in chat area new msgs
                    self.chat_area.yview('end') # auto-scroll to last msgs
                    self.chat_area.config(state='disabled') # Set chat screen area to read-only


            except:
                print('Error: Disconnection from server')
                break
            

    def client_gui(self):

        # Initialize GUI
        self.root = tk.Tk() # Main window object

        self.root.title('ChatRoom')
        self.root.resizable(0, 0)
        self.root.configure(bg = 'SlateBlue1')
        
        # Chat area
        self.chat_area = scrolledtext.ScrolledText(self.root, width=50, height='12', font=('Helvetica', 12), bg='grey1', fg='snow')
        self.chat_area.pack(padx=10, pady=3)
        self.chat_area.insert('end', 'Connected to ChatRoom.\n')
        self.chat_area.config(state='disabled')

        # Message area
        self.msg_area_label = tk.Label(self.root, text='Type a message', font=('Helvetica, 12'), bg='SlateBlue1')
        self.msg_area_label.pack(padx=10, pady=3)

        self.msg_area = tk.Text(self.root, width=50, height=4, font=('Helvetica', 12), bg='grey1', fg='snow')
        self.msg_area.pack(padx=10, pady=3)

        # Send
        # self.msg_area.bind('<Return>', self.send_msg) # Send with keyboard Return button

        self.send_button = tk.Button(self.root, text='Send', font=('Helvetica', 12), command=self.send_msg)
        self.send_button.pack(padx=10, pady=3)

        self.building_gui = 'F'

        # Close window
        self.root.protocol('WM_DELETE_WINDOW', self.close_gui)

        self.root.mainloop()
     

    def send_msg(self):
        
        message = f"{self.msg_area.get('1.0', 'end').strip()}\n"
        
        # Encryption of message
        if self.operation_mode == 'ECB':
            message = self.aes_object.encrypt_ECB(message)
            
        elif self.operation_mode == 'CFB':
            message = self.aes_object.encrypt_CFB(message)
                
        else:
            message = self.aes_object.encrypt_CBC(message)
        
        # Send encoded message to server
        self.client.send(message)

        # Clean message area
        self.msg_area.delete('1.0', 'end') 


    def close_gui(self):
        if askokcancel(title= 'Quit', message='Do yo want to leave ChatRoom?', icon='warning'):
            self.root.destroy()
            self.client.close()
            exit(0)


def get_pre_sets(file):
    pre_sets = []
    with open(file) as f:
        for line in f:
            pre_sets.append(line.strip('\n'))

    return pre_sets

if __name__ == '__main__':
    
    pre_sets = get_pre_sets('chat-presets.txt')
    key_size = int(pre_sets[0])
    operation_mode = pre_sets[1]
    
    chatClient = Client(key_size, operation_mode)
    chatClient.connect_client()