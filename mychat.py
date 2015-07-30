#!/usr/bin/python

""" A simple graphical chat client to demonstrate the use of pybluez.

Opens a l2cap socket and listens on PSM 0x1001

Provides the ability to scan for nearby bluetooth devices and establish chat
sessions with them.
"""


import os
import sys
import time
import re
import rsa
import pickle
import gtk
import json
import gobject
import gtk.glade
import subprocess

import bluetooth

GLADEFILE="bluezchat.glade"

# *****************

def alert(text, buttons=gtk.BUTTONS_NONE, type=gtk.MESSAGE_INFO):
    md = gtk.MessageDialog(buttons=buttons, type=type)
    md.label.set_text(text)
    md.run()
    md.destroy()

class header:
    def __init__(self, SRC, DST, flag, checksum, hops_remaining, hop_list):
            self.SRC = SRC
            self.DST = DST
            self.flag = flag
            self.checksum = checksum
            self.hops_remaining = hops_remaining
            self.hop_list = hop_list

class BluezChatGui:
    def __init__(self):
        self.main_window_xml = gtk.glade.XML(GLADEFILE, "bluezchat_window")

        # connect our signal handlers
        dic = { "on_quit_button_clicked"        : self.quit_button_clicked,
                "on_send_button_clicked"        : self.send_button_clicked,
                "on_chat_button_clicked"        : self.chat_button_clicked,
                "on_scan_button_clicked"        : self.scan_button_clicked,
                "on_add_button_clicked"         : self.add_button_clicked,
                "on_friends_button_clicked"     : self.friends_button_clicked,
                "on_devices_tv_cursor_changed"  : self.devices_tv_cursor_changed
                }

        self.main_window_xml.signal_autoconnect(dic)
        self.localaddr = '28:CF:DA:D9:D8:D7'
        self.currentaddr = ''

        # prepare the floor listbox
        self.devices_tv = self.main_window_xml.get_widget("devices_tv")
        self.discovered = gtk.ListStore(gobject.TYPE_STRING, gobject.TYPE_STRING)
        self.devices_tv.set_model(self.discovered)
        self.friends = gtk.ListStore(gobject.TYPE_STRING, gobject.TYPE_STRING)
        
        renderer = gtk.CellRendererText()
        column1=gtk.TreeViewColumn("addr", renderer, text=0)
        column2=gtk.TreeViewColumn("name", renderer, text=1)
        self.devices_tv.append_column(column1)
        self.devices_tv.append_column(column2)

        self.quit_button = self.main_window_xml.get_widget("quit_button")
        self.scan_button = self.main_window_xml.get_widget("scan_button")
        self.chat_button = self.main_window_xml.get_widget("chat_button")
        self.send_button = self.main_window_xml.get_widget("send_button")
        self.add_button = self.main_window_xml.get_widget("add_button")
        self.friends_button = self.main_window_xml.get_widget("friends_button")
        self.main_text = self.main_window_xml.get_widget("main_text")
        self.text_buffer = self.main_text.get_buffer()

        self.input_tb = self.main_window_xml.get_widget("input_tb")

        self.listed_devs = []

        self.chat_button.set_sensitive(False)

        self.peers = {}

        self.nearby = {}
        self.sources = {}
        self.addresses = {}

        # the listening sockets
        self.server_sock = None

# --- gui signal handlers

    def quit_button_clicked(self, widget):
        subprocess.call(["sudo", "hciconfig", "hci0", "name", self.localname])
        gtk.main_quit()

    def scan_button_clicked(self, widget):
        self.devices_tv.set_model(self.discovered)
        self.quit_button.set_sensitive(False)
        self.scan_button.set_sensitive(False)
#        self.chat_button.set_sensitive(False)
   
        ## For each address found in discover devices, append to list of discovered.
        ## Contents of Discovered are shown in tv.
        ## Scans for 3 seconds, can be adjusted.
     
        self.discovered.clear()
        for addr, name in bluetooth.discover_devices (duration = 5, lookup_names = True):
            self.discovered.append ((addr, name))


        self.quit_button.set_sensitive(True)
        self.scan_button.set_sensitive(True)
        self.chat_button.set_sensitive(False)
        
        ## when send is clicked, Scans for devices, connects to them, and adds input text to msg dict. 
        ## serializes the msg and then sends it over the socket.
    def send_button_clicked(self, widget):
        self.scan_button_clicked(widget)
        self.peers.clear()
        for addr, name in self.discovered:
            self.connect(addr, name)

 
        ## do RSA stuff (obviously not implemented)
        text = self.input_tb.get_text()

        if len(text) == 0: return

        self.msg.update({'msg': text})
        serialized_text = json.dumps(self.msg)

        for addr, sock in list(self.peers.items()):
            sock.send(serialized_text)

        self.input_tb.set_text("")
        self.add_text("\nme - %s" % text)


    ## gets info from app screen and sets that info to corresponding fields in msg dictionary.
    ## I included the RSA flag and checksum fields but don't know what they are for

    def chat_button_clicked(self, widget):
        (model, iter) = self.devices_tv.get_selection().get_selected()
        if iter is not None:
            addr = model.get_value(iter, 0)
            name = model.get_value(iter, 1)
            self.msg = {'SRC': self.localaddr, 'DST': addr, 'Flag': '1', 'Checksum': '10', 'hops_remaining': 10, 'hop_list': []}





    def add_button_clicked(self, widget):
        (model, iter) = self.devices_tv.get_selection().get_selected()
        if iter is not None:
            addr = model.get_value(iter, 0)
            name = model.get_value(iter, 1)
            self.friends.append ((addr, name))
            self.add_text("\nPairing with %s..." % name)
            self.connect(addr, name)
            self.add_text("\nAdded %s to friend list.\n" % name)

    
    def friends_button_clicked(self, widget):
        self.chat_button.set_sensitive(False)
        self.devices_tv.set_model(self.friends)


    def devices_tv_cursor_changed(self, widget):
        (model, iter) = self.devices_tv.get_selection().get_selected()
        if iter is not None:
            self.chat_button.set_sensitive(True)
        else:
            self.chat_button.set_sensitive(False)

# --- network events


    def incoming_connection(self, source, condition):
        sock, info = self.server_sock.accept()
        address, psm = info

        self.add_text("\naccepted connection from %s" % str(address))

        # add new connection to list of peers
        # self.peers[address] = sock
        self.addresses[sock] = address

        source = gobject.io_add_watch (sock, gobject.IO_IN, self.data_ready)
        #self.sources[address] = source
        return True


    ## When data is ready on the socket, recv from socket
    ## if no data in msg received, cancel connection (this isn't really relevant to us)
    def data_ready(self, sock, condition):
        address = self.addresses[sock]
        data = sock.recv(1024)

        if len(data) == 0:
            self.add_text("\nlost connection with %s" % address)
            gobject.source_remove(self.sources[address])
            del self.sources[address]
            del self.peers[address]
            del self.addresses[sock]
            sock.close()

        ## If there is data read, deserialize from json and check if DST (destination) matches localaddr
        ## If so, print to screen, else decrement remaining hops, scan, and send out to all discovered devices  
        else:
            decoded = json.loads(data)
            if decoded['DST'] == self.localaddr:
		self.add_text("\nReceived message destined for me")
                self.add_text("\n%s - %s" % (str(decoded['SRC']), str(decoded['msg'])))
            elif decoded['hops_remaining'] > 0:
                print "Hops left on msg with DST:\n", decoded['hops_remaining']
		self.add_text("\nPassing along message for %s" % (str(decoded['DST'])))
                decoded['hops_remaining'] -=1;
                self.scan_button_clicked(0)
                self.peers.clear()
                re_serialized = json.dumps(decoded)
                for addr, name in self.discovered:
                    if addr not in decoded['hop_list']:
                        self.connect(addr, name)
                        for addr, sock in list(self.peers.items()):
                            sock.send(re_serialized)

                return True

# --- other stuff

    def cleanup(self):
        self.hci_sock.close()

    def connect(self, addr, name):
        if 'bluetalk' in name:
            sock = bluetooth.BluetoothSocket (bluetooth.L2CAP)
            try:
                sock.connect((addr, 0x1001))
            except bluetooth.BluetoothError as e:
                self.add_text("\n%s" % str(e))
                sock.close()
                return 

            self.peers[addr] = sock
            source = gobject.io_add_watch (sock, gobject.IO_IN, self.data_ready)
            self.sources[addr] = source
            self.addresses[sock] = addr


    def add_text(self, text):
        self.text_buffer.insert(self.text_buffer.get_end_iter(), text)

    def start_server(self):
        ## newname should reflect local bluetooth name + 'bluetalk'

        namereturn = subprocess.check_output(["sudo", "hciconfig", "hci0", "name"])
        matchobj = re.search('((.{2}:){5}.{2})', namereturn)
        matcher = re.search("Name: '(.{2,48})'", namereturn)
        if matchobj:
            self.localaddr = matchobj.group(1)
            self.localname = matcher.group(1)

        newname = self.localname + '_bluetalk'
        subprocess.call(["sudo", "hciconfig", "hci0", "name", newname])
        self.server_sock = bluetooth.BluetoothSocket (bluetooth.L2CAP)
        self.server_sock.bind(("",0x1001))
        self.server_sock.listen(1)
        gobject.io_add_watch(self.server_sock, gobject.IO_IN, self.incoming_connection)

    def read_public_key(self, address):
        if not os.path.exists('keys/' + address + ".pem"):
            #TODO: Make exception more specific
            raise Exception("Could not find public key for address: " + address)
        else:
            keyfile = open('keys/' + address + '.pem')
            key = keyfile.read()
            keyfile.close()
            return rsa.PublicKey.load_pkcs1(key)
    
    #takes public key in pem format, may change this in the future
    def write_public_key(self, address, pemkey):
        if os.path.exists('keys/' + address + '.pem'):
            print "\nWarning: Overwriting previous public key for address " + address
        keyfile = open('keys/' + address + ".pem", 'wb')
        keyfile.write(pemkey)
        keyfile.close()

    def init_rsa(self):
	self.add_text("\nloading RSA keypair...")
        if os.path.exists('keys/private.pem'):
            keyfile = open('keys/private.pem')
            keypair = keyfile.read()
            self.pubkey = rsa.PublicKey.load_pkcs1(keypair)
            self.privkey = rsa.PrivateKey.load_pkcs1(keypair) 
	    keyfile.close()
            self.add_text(" done")
        else:
            self.add_text(" not found\ngenerating new keypair...")
            keypair = rsa.newkeys(1024)
            self.pubkey = keypair[0]
            self.privkey = keypair[1]
            keyfile = open('keys/private.pem', 'wb')
            keyfile.write(rsa.PublicKey.save_pkcs1(self.pubkey, 'PEM'))
            keyfile.write(rsa.PrivateKey.save_pkcs1(self.privkey, 'PEM'))
            keyfile.close()
            self.add_text(" done")

    def encrypt_for_addr(self, content, address):
        pkey = self.read_public_key(address)
        return rsa.encrypt(content, pkey)

    def decrypt_content(self, content):
        return rsa.decrypt(content, self.privkey)

    def run(self):
        self.text_buffer.insert(self.text_buffer.get_end_iter(), "loading...")
        self.start_server()
        self.init_rsa()
        gtk.main()

if __name__ == "__main__":
    gui = BluezChatGui()
    gui.run()
