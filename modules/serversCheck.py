import sys
import os
import socket
import ipaddress
import timeit
import threading
import queue as Queue

on_blacklist = []

class ThreadRBL(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            # Grab hosts from queue
            hostname, root_name = self.queue.get()
            check_host = "%s.%s" % (hostname, root_name)
            start_time = timeit.default_timer()
            try:
                check_addr = socket.gethostbyname(check_host)
            except socket.error:
                check_addr = None
            if check_addr is not None and "127.0.0." in check_addr:
                on_blacklist.append(root_name)

            elapsed = timeit.default_timer() - start_time

            # Signal queue that job is done
            self.queue.task_done()

def checkIp(addr):
    #addr = "[fe80::56a9:e7a7:fea4:e1e9]"  # Dirección IP "hardcodeada"
    #f = open("./blacklists.txt", "r")
    #serverlist = f.read().splitlines()
    #f.close()
    filename="./blacklists.lst"
    #print(os.getcwd())
    if os.path.exists(filename):
        with open(filename, "r") as f:
            serverlist = f.read().splitlines()
        # Continúa con el resto del código que utiliza serverlist
    else:
        print("El archivo blacklists.txt no se encuentra en el directorio actual.")
        return

    queue = Queue.Queue()
    on_blacklist = []
    
    ip = ipaddress.ip_address(addr)
    if (ip.version == 6):
        addr_exploded = ip.exploded
        check_name = '.'.join([c for c in addr_exploded if c != ':'])[::-1]
    else:
        addr_parts = addr.split('.')
        addr_parts.reverse()
        check_name = '.'.join(addr_parts)

    # Spawn a pool of threads then pass them the queue
    for i in range(30):
        t = ThreadRBL(queue)
        t.setDaemon(True)
        t.start()

    # Populate the queue
    for blhost in serverlist:
        queue.put((check_name, blhost))

    # Wait for everything in the queue to be processed
    queue.join()

    if on_blacklist:
        output = '%s on %s blacklist(s): %s' % (
            addr, len(on_blacklist), ', '.join(on_blacklist))
        print('Result:', output)
    else:
        print('Result:', '%s not on any known blacklists' % addr)

