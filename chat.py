import socket
from threading import Thread
import argparse
import tkinter
from tkinter import messagebox
from tkinter import font
import pyaes
import hashlib
import binascii


clients = {}                                        # List of connected clients.
addresses = {}                                      # List of connected client addresses.

HOST = "localhost"
PORT = 30000                                        # Default value.
BUFFSIZE = 1024


def server_scope(key, host):

    def broadcast(msg, prefix = ""):    # Prefix is for name identification.
        """Broadcasts a mesage to all the clients."""
        aes = pyaes.AESModeOfOperationCTR(key)
        encrypted = aes.encrypt(prefix + msg)
        for c in clients:
            c.send(encrypted)


    def handle_client(client):
        """Handles a single client connection."""
        name = ""
        while True:
            try:
                aes = pyaes.AESModeOfOperationCTR(key)
                name = aes.decrypt(client.recv(BUFFSIZE)).decode("utf8")
                if name == "{quit}" or name == "":
                    print(addresses[client], "lost connection")
                    client.close()
                    return

                break
            except:
                print("Requesting new client name")
                aes = pyaes.AESModeOfOperationCTR(key)
                client.send(aes.encrypt("Invalid name. Please try another name."))


        welcome = "Welcome " + name + "! If you ever want to quit, type {quit} to exit."
        aes = pyaes.AESModeOfOperationCTR(key)
        client.send(aes.encrypt(welcome))
        msg = name + " has joined the chat!"
        broadcast(msg)
        clients[client] = name
        while True:
            encrypted = client.recv(BUFFSIZE)
            aes = pyaes.AESModeOfOperationCTR(key)
            decrypted = ""
            invalidMessage = False
            try:
                decrypted = aes.decrypt(encrypted).decode("utf8")
            except:
                invalidMessage = True

            if invalidMessage:
                aes = pyaes.AESModeOfOperationCTR(key)
                client.send(aes.encrypt("Invalid message"))
            elif decrypted != "{quit}":
                broadcast(decrypted, name + ": ")
            else:
                client.send(encrypted)
                break

        client.close()
        print(addresses[client], "left the chat")
        del clients[client]
        broadcastString = name + " has left the chat"
        broadcast(broadcastString)


    def clientVerifyPassword(client):
        hashedKey = binascii.unhexlify(hashlib.sha256(stretchedKey).hexdigest())
        client.send(hashedKey)
        clientResponse = client.recv(BUFFSIZE).decode("utf8")
        if clientResponse == "True":
            client.send(bytes("True", "utf8"))
            return True
        else:
            client.send(bytes("False", "utf8"))
            client.close()
            return False


    def accept_incoming_connections(server):
        """Sets up handling for incoming clients."""
        try:
            while True:
                c, addr = server.accept()     # Establish connection with client.
                print("Got connection from", addr)
                if not clientVerifyPassword(c):
                    continue

                aes = pyaes.AESModeOfOperationCTR(key)
                c.send(aes.encrypt("Greetings from the cave! Now type your name and press enter!"))
                addresses[c] = addr
                Thread(target = handle_client, args = (c,)).start()
        finally:
            server.close()
            print("\nServer shutdown")


    def server():
        server = socket.socket()         # Create a socket object.

        print("Server started!")
        print("Host:", host, ", port:", PORT)

        server.bind((host, PORT))        # Bind to the port
        print("Waiting for clients...")
        server.listen(5)                 # Now wait for client connection.

        accept_incoming_connections(server)


    server()



def client_scope(key, host):

    def receive():
        """Handles receiving of messages."""
        while clientActive:
            try:
                encrypted = client_socket.recv(BUFFSIZE)
                aes = pyaes.AESModeOfOperationCTR(key)
                decrypted = aes.decrypt(encrypted).decode("utf8")
                if decrypted != "{quit}" and decrypted != "":
                    msg_list.insert(tkinter.END, decrypted)

            except OSError:     # Possibly client has left the chat.
                break

        print("Exiting")


    def send(event = None):     # Event is passed by binders.
        """Handles sending of messages."""
        msg = my_msg.get()
        aes = pyaes.AESModeOfOperationCTR(key)
        encrypted = aes.encrypt(msg)
        my_msg.set("")      # Clears input field.
        try:                # In case server has shut down.
            client_socket.send(encrypted)
        except:
            print("Could not send message")
            pass

        if msg == "{quit}":
            nonlocal clientActive
            clientActive = False
            try:                         # In case server has shut down.
                client_socket.shutdown(socket.SHUT_RDWR)
            except:
                print("client_socket shutdown call error")
                pass

            client_socket.close()
            top.destroy()


    def on_closing(event = None):
        """This method is to be called when the window is closed."""
        if tkinter.messagebox.askokcancel("Quit", "Do you want to quit?"):
            my_msg.set("{quit}")
            send()

    def verifyPassword():
        serverHashedKey = client_socket.recv(BUFFSIZE)
        hashedKey = binascii.unhexlify(hashlib.sha256(stretchedKey).hexdigest())
        response = (serverHashedKey == hashedKey)
        client_socket.send(bytes(str(response), "utf8"))
        success = client_socket.recv(BUFFSIZE).decode("utf8")
        if success == "True":
            return True
        elif success == "False":
            print("Wrong password")
            return False


    def client():
        if not verifyPassword():
            return

        Thread(target = receive).start()
        tkinter.mainloop()                  # Starts GUI execution.


    clientActive = True

    top = tkinter.Tk()
    top.title("Chatter")

    messages_frame = tkinter.Frame(top)
    my_msg = tkinter.StringVar()                        # For the messages to be sent.
    scrollbar = tkinter.Scrollbar(messages_frame)      # To navigate through past messages.
    msg_list = tkinter.Listbox(messages_frame, height = 15, width = 70, yscrollcommand = scrollbar.set, font = font.Font(size=11))
    scrollbar.pack(side = tkinter.RIGHT, fill = tkinter.Y)
    msg_list.pack(side = tkinter.LEFT, fill = tkinter.BOTH)
    msg_list.pack()

    messages_frame.pack()

    entry_field = tkinter.Entry(top, textvariable = my_msg)
    entry_field.bind("<Return>", send)
    entry_field.pack()
    send_button = tkinter.Button(top, text = "Send", command = send)
    send_button.pack()

    top.protocol("WM_DELETE_WINDOW", on_closing)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, PORT))
    client()



parser = argparse.ArgumentParser(description="Set up new chat server or connect to existing chat server.")
parser.add_argument("command", action="store")
parser.add_argument("key", type=str, help="Key used to encrypt/decrypt chat messages.")
parser.add_argument("host", nargs="?", type=str, help="Host address the client will attempt to connect to.")
args = parser.parse_args()
if args.host is not None:
    HOST = args.host

stretchedKey = binascii.unhexlify(hashlib.sha256(bytes(args.key, "utf8")).hexdigest())

FUNCTION_MAP = { "server" : server_scope,
                 "client" : client_scope, }

func = FUNCTION_MAP[args.command]
func(stretchedKey, HOST)
