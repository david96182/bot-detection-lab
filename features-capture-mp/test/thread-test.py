"""
Test if features-capture process the packets and
extract the information using scapy that allows
to create and send custom networks packets
"""
import datetime
import random
import threading
import time
from threading import Thread

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, send

THREADS = 25
IFACE = 'br-71258deca73a'
FLAGS = ['F', 'S', 'R', 'P', 'A', 'E', 'C', 'U']


def send_flow():
    print(f'Running from process: {threading.current_thread()}')
    src = f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}'
    dst = f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}'
    sport = random.randint(80, 9000)
    dport = random.randint(80, 9000)
    while True:
        # random flags
        flag = FLAGS[random.randint(0, len(FLAGS) - 1)] if random.uniform(0, 1) else None

        if random.uniform(0, 1) > 0.5:
            packet = Ether() / \
                     IP(dst=dst, src=src, tos=random.randint(0, 3), len=random.randint(50, 300)) / \
                     TCP(sport=sport, dport=dport, flags=flag)
        else:
            packet = Ether() / \
                     IP(dst=src, src=dst, tos=random.randint(0, 3), len=random.randint(50, 300)) / \
                     TCP(sport=dport, dport=sport, flags=flag)
        packet.time = datetime.datetime.now()
        sendp(x=packet, iface=IFACE)

        if random.uniform(0, 1) > 0.99:
            print(f'Sleeping in proc: {threading.current_thread()}')
            time.sleep(18)


if __name__ == '__main__':
    print(THREADS)
    time.sleep(3)
    thread_list = []

    for num in range(0, THREADS):
        new_thread = Thread(target=send_flow, name=f'thread-0{num}')
        thread_list.append(new_thread)
        new_thread.start()


