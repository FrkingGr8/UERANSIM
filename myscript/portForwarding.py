#!/usr/bin/python

import socket
import threading
import time

'''

+-----------------------------+         +---------------------------------------------+         +--------------------------------+
|     UE (Alice)              |         |            Intermediary Server (Bob)        |         |         gNodeB  (Carol)        |
+-----------------------------+         +----------------------+----------------------+         +--------------------------------+
|     UE with some port       |-------->|  IF 6000: 127.0.0.1  | IF 4997: 127.0.0.1   |-------->|       IF 4997: 127.0.0.1       |
|     generated say(42034)    |         +----------------------+----------------------+         +--------------------------------+
|                             |<-|      |         $ python udp_forwarding.py          |         | 127.0.0.1:4997(gNodeB Server)  |
|                             |  |      |                                             |         +--------------------------------+
+-----------------------------+  |      +---------------------------------------------+                          |
                                 |                                                                               |
                                 |-------------------------------------------------------------------------------|
'''

# Parameters.
FORWARD_TO = 4997
FORWARD_IP = "127.0.0.1"

# This is port number. The socket is binded on the socket.
LISTEN_ON = 6000

TIMEOUT_SECONDS = 180

# Server socket.
# Bind socket to LISTEN_ON port, all interfaces.
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print("Listen on 127.0.0.1:%s with IPv4" % LISTEN_ON)
sock.bind(("127.0.0.1", LISTEN_ON))


# Socket threads.
sock_dict = { }

# Lock.
lock = threading.Lock()


# One thread for each connection.
class ListenThread(threading.Thread):
    def __init__(self, info):
        threading.Thread.__init__(self)
        self.s_client = info['socket']
        # Set timeout to 180 seconds, which is the common UDP gateway timeout.
        self.s_client.settimeout(1)
        self.addr = info['addr']
        self.last_receive = time.time()
        self.should_stop = False

    def run(self):
        while not self.should_stop:
            try: data, r_addr = self.s_client.recvfrom(65536) # buffer size is 65536 bytes
            except:
                if time.time() - self.last_receive > TIMEOUT_SECONDS:
                    break
                else:
                    continue
            # Reset timeout.
            self.last_receive = time.time()
            # Successfully received a packet, forward it.
            sock.sendto(data, self.addr)
        lock.acquire()
        try:
            self.s_client.close()
            sock_dict.pop(self.addr)
        except: pass
        lock.release()
        print("Client released for ", self.addr)

    def stop(self):
        self.should_stop = True

# This function analyse each packet before sending if the packet is of type RRCsetup complete message it changes the security info element.
def changeSecurity(data):
    binary_string = "{:08b}".format(int(data.hex(),16))
    return binary_string

# This function prints the data of the packets in hex format.
def printdata(data):
    # print(type(data))
    # check = '001011100000010011110000111100001111000011110000'
    # check = "001011100000010011110000111100001111000011110000"
    # check = b'\x2E\x04\xF0\xF0\xF0\xF0'
    if(len(data) == 55):
        rlist = [46, 4, 128, 128, 128, 128]
        bytetemp1 = bytes(rlist)
        bytetemp2 = data[:-6]
        print(len(bytetemp2))
        newdata = bytetemp2 + bytetemp1
        print(len(newdata))
        # print(type(check[0]))
        # # print(len(check))
        # count = 0
        # flag = 0
        # for byte in data:
        #     # print(hex(byte), hex(check[count]))
        #     if(count == len(check)):
        #         flag = 1
        #         break;
        #     else:
        #         if(check[count] == byte):
        #             count = count + 1
        #         else:
        #             count = 0
        # print("Out of loop")
        # if(flag == 1):
        #     # print(data[index])
        #     print("bytes found")
    # if(check in data):
    #     print("Found the UE Security element in packet of length: ", len(data));
    #     print("Number of Occurences found is: ", data.count(check))
    # else:
    #     print(len(data))

    # binary_string = "{:08b}".format(int(data.hex(),16))
    # if(len(data) == 55):
        # print("Found the RRC setup complete")
    # if(check in binary_string):
    #     print("Found the UE Security element in packet of length: ", len(binary_string));
    #     print("Number of Occurences found is: ", binary_string.count(check))
    #     print(binary_string[binary_string.find(check, 0, len(binary_string)):binary_string.find(check, 0, len(binary_string))+len(check)])
    #     print("Starting index of the substring in string is: ", binary_string.find(check, 0, len(binary_string)))
    #     print("Ending index of the substring in string is: ", binary_string.find(check, 0, len(binary_string)) + len(check))
    # else:
    # print(len(data))


count = 0;
try:
    while True:
        data, addr = sock.recvfrom(65536) # buffer size is in bytes
        
        printdata(data)
        # count = count + 1;
        # print("Packet Count: ", count)

        lock.acquire()
        try:
            if not addr in sock_dict:
                s_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                item = {
                    "socket": s_client,
                    "addr": addr
                }
                print("Adding client for ", addr)
                s_client.sendto(data, (FORWARD_IP, FORWARD_TO))
                t = ListenThread(item)
                t.start()
                item['thread'] = t
                sock_dict[addr] = item
            else:
                s_client = sock_dict[addr]['socket']
                s_client.sendto(data, (FORWARD_IP, FORWARD_TO))
        except: pass
        lock.release()
except: pass

# Stop all threads.
for addr in sock_dict:
    try: sock_dict[addr]['thread'].stop()
    except: pass