"""
Test if features-capture process the packets and
extract the information using scapy that allows
to create and send custom networks packets
"""
import datetime
import multiprocessing
import os
import random
import time
from multiprocessing import Process

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, send

PROCS = 25
IFACE = 'br-04bebcffef1f'
FLAGS = ['F', 'S', 'R', 'P', 'A', 'E', 'C', 'U']


def send_flow():
    print(f'Running from process: {multiprocessing.current_process()}')
    src = f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}'
    dst = f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}'
    sport = random.randint(80, 9000)
    dport = random.randint(80, 9000)
    while True:
        # random flags
        flag = FLAGS[random.randint(0, len(FLAGS)-1)] if random.uniform(0, 1) else None

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
            print(f'Sleeping in proc: {multiprocessing.current_process()}')
            time.sleep(18)


if __name__ == '__main__':
    print(os.getgid())
    time.sleep(3)

    proc_list = []

    for num in range(0, PROCS):
        new_process = Process(target=send_flow, name=f'proc-0{num}')
        proc_list.append(new_process)
        new_process.start()


