'''
Created 12 Dec 2021
@author: Paola Gomez Reyna - pgomezr0

Computer Security Assignment 2:
Real Time Chat using Diffie Helman
Key Exchange and AES encryption algorithm
'''

import socket, threading
from keyExchange import DiffieHellman
from encryption import AEStandard

class Server:
    def __init__(self, key_size, operation_mode):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Creates server socket object using IPv4 adresess and TCP
        self.host = '127.0.0.1'
        self.port = 9091 # Use any value between 0 and 65535 (TCP)

        self.msg_size = 2048
        self.key_size = key_size
        self.operation_mode = operation_mode

        # Key Exchange with Diffie Hellman
        self.server_key = DiffieHellman(key_size)
        self.server_public_key = str(self.server_key.create_public_key())

        self.clients_names = {}
        self.clients_keys = {}

    # Starts server and listens for any new client connections
    def connection_server(self):
        try:
            self.server.bind((self.host, self.port))
            print(f'Sucessful! Server now runs on host [{self.host}] and port [{self.port}]')

        except:
            print(f'ERROR running server on host [{self.host}] and port [{self.port}]')
        
        
        self.server.listen() # Listen for incoming connections
        print('Listening for new client connections...')

        while True: # Keep listening for new client connections
                
            self.connection, self.address = self.server.accept()

            # Save name in clients_names dictionary
            name_input  = self.connection.recv(self.msg_size).decode('utf-8')
            self.clients_names[self.connection] = name_input

            # Exchange of keys
            self.key_exchange()

            print(f'Connected to client {[name_input]} - {self.address}.')

            # Running multiple clients simultaneously  
            threading.Thread(target=self.receive_client_msgs).start()
        

    def key_exchange(self):
        
        # Send Server's Public Key
        self.connection.send((self.server_public_key).encode('utf-8'))

        # Receive Client's Public Key
        client_public_key = int(self.connection.recv(self.msg_size).decode('utf-8'))

        # Create Client's Private Key
        client_private_key = self.server_key.create_secretshared_key(client_public_key)

        # Save Server's Private Key for that client connection
        self.clients_keys[self.connection] = client_private_key


    # Receiving client messages
    def receive_client_msgs(self):
        
        print('Total active connections:', threading.active_count()-1)

        client_name = self.clients_names[self.connection]

        # Decryption of message
        client_private_key = self.clients_keys[self.connection]
        aes_object = AEStandard(client_private_key, self.key_size) # Create AES object

        while True:
            try:
                
                if self.operation_mode == 'ECB':
                    message = aes_object.decrypt_ECB(self.connection.recv(self.msg_size))

                elif self.operation_mode == 'CFB':
                    message = aes_object.decrypt_CFB(self.connection.recv(self.msg_size))
                
                else:
                    message = aes_object.decrypt_CBC(self.connection.recv(self.msg_size))

                message = f'{client_name}: {message}'

                self.broadcast_messages(message)

            except:
                break
        
        # Close connection
        self.connection.close()

        print(f'Disconnected client {client_name} - {self.address[0]} {self.address[1]}.')

        print('Total active connections:', threading.active_count()-2)
        
        del self.clients_names[self.connection]
        del self.clients_keys[self.connection]
                

    # Sending message to all clients
    def broadcast_messages(self, message):

        client_name = self.clients_names[self.connection]

        for client in self.clients_names:

            # Encryption of message 
            client_private_key = self.clients_keys[client]
            aes_object_client = AEStandard(client_private_key, self.key_size) # Create AES object per client

            if self.operation_mode == 'ECB':
                message = aes_object_client.encrypt_ECB(message)
            
            elif self.operation_mode == 'CFB':
                message = aes_object_client.encrypt_CFB(message)
                
            else:
                message = aes_object_client.encrypt_CBC(message)
            
            print(f'{client_name}: {message}')
            client.send(message)


def menu():
    
    print('\n*******************')
    print('Welcome to ChatRoom!')
    print('This is a secure real time chat.') 
    print('This chat uses Diffie Hellman (DH) key exchange and Advanced Encryption Standard (AES) to protect confidentiality and provide authenticity.')

    key_sizes_options = {
    1: '128 bits or 10 rounds',
    2: '192 bits or 12 rounds',
    3: '256 bits or 14 rounds',
    4: 'Exit',
    }
        
    run_menu_keys = True  # Run menu modes until proper mode selected

    while(run_menu_keys):

        print('\nThese are the key size options:')
        for key in key_sizes_options.keys():
            print (key, '--', key_sizes_options[key]) 

        try:
            option = int(input('\nEnter the option number of your preferred key size or # of rounds: '))

            if option == 1:
                key_size = 16 # bytes or 128 bits
                run_menu_keys = False

            elif option == 2:
                key_size = 24 # bytes or 192 bits
                run_menu_keys = False

            elif option == 3:
                key_size = 32 # bytes or 256 bits
                run_menu_keys = False

            elif option == 4:
                print('Thanks for using ChatRoom!')
                exit()  
            else:
                print('\nInvalid option. Please enter a number between 1 and 4.')
            
        except ValueError:
            print('\nWrong input. Please enter a number ...')
        

    operation_mode_options = {
    1: 'CBC - CipherBlock Chaining',
    2: 'CFB - Cipher Feedback',
    3: 'ECB - Electronic Codebook',
    4: 'Exit',
    
    }
    
    run_menu_modes = True # Run menu modes until proper mode selected

    while(run_menu_modes):

        print('\nThese are the AES modes of operation:')
        for key in operation_mode_options.keys():
            print (key, '--', operation_mode_options[key])  

        try:
            option = int(input('\nEnter the number of your preferred mode of operation: '))

            # Check mode selected and run accordingly
            if option == 1:
                operation_mode = 'CBC'
                run_menu_modes = False

            elif option == 2:
                operation_mode = 'CFB'
                run_menu_modes = False

            elif option == 3:
                operation_mode = 'ECB'
                run_menu_modes = False

            elif option == 4:
                print('Thanks for using ChatRoom!')
                exit()

            else:
                print('\nInvalid option. Please enter a number between 1 and 4.')

        except ValueError:
            print('\nWrong input. Please enter a number ...')
    
    return key_size, operation_mode


if __name__ == '__main__':

    key_size, operation_mode = menu()

    with open('chat-presets.txt', 'w') as f:
        f.write(str(key_size) + '\n' + str(operation_mode))
    f.close
    
    chatServer = Server(key_size, operation_mode)
    chatServer.connection_server()
