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
    pass

count = 0;
try:
    while True:
        data, addr = sock.recvfrom(65536) # buffer size is 1024 bytes
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
                count = count + 1;
                print("Packet Count: ", count)
        except: pass
        lock.release()
except: pass

# Stop all threads.
for addr in sock_dict:
    try: sock_dict[addr]['thread'].stop()
    except: pass