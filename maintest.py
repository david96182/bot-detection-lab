import datetime
from settings import logger as logging
import random
import threading
import time
from threading import Thread

import pyshark.tshark.tshark


def capture():
    logging.error('Starting capture on interface:')
    # interface = str(config.get_config()['interface']['network_interface'])
    # out_file = str(config.get_config()['pcap']['pcap_file'])
    interface = 'enp0s3'
    logging.error('Starting capture on interface: %s' % interface)
    # check if interface is correct
    interfaces = pyshark.tshark.tshark.get_tshark_interfaces()
    print(interfaces)

    capture = LiveCapture(interface, output_file=out_file)
    capture.sniff(timeout=0)
    for packet in capture.sniff_continuously():
        print('packet')
        print(packet.layers)
        print(packet.frame_info)
        print(packet.length)
        # packet.pretty_print()


class my_thread(Thread):

    def run(self):
        time.sleep(random.uniform(0.5, 1.66))
        print(f'{datetime.datetime.now()}running thread {threading.current_thread().name}')
        times = datetime.datetime.now()
        with open('log.txt', 'a') as f:
            f.write(f'{datetime.datetime.now()}running thread {threading.current_thread().name}\n')
        time.sleep(5)


def test_threads():
    thread1 = my_thread(name='thread1')
    thread2 = my_thread()
    thread3 = my_thread()
    thread4 = my_thread()
    thread5 = my_thread()
    thread6 = my_thread()
    thread7 = my_thread()
    thread8 = my_thread()
    thread9 = my_thread()
    thread10 = my_thread()
    thread11 = my_thread()
    thread12 = my_thread()
    thread13 = my_thread()
    thread14 = my_thread()
    thread15 = my_thread()
    thread16 = my_thread()
    thread17 = my_thread()
    thread18 = my_thread()
    thread19 = my_thread()
    thread20 = my_thread()
    thread21 = my_thread()
    thread22 = my_thread()

    thread1.start()
    thread2.start()
    thread3.start()
    thread4.start()
    thread5.start()
    thread6.start()
    thread7.start()
    thread8.start()
    thread9.start()
    thread10.start()
    thread11.start()
    thread12.start()
    thread13.start()
    thread14.start()
    thread15.start()
    thread16.start()
    thread17.start()
    thread18.start()
    thread19.start()
    thread20.start()
    thread21.start()
    thread22.start()
    # print all threads
    time.sleep(10)
    # kill thread 22

    threadxd = my_thread(name='thread1')
    threadxd.start()
    thread1.start()
    threadss = list(threading.enumerate())
    for thread in threadss:
        print(thread.name)


if __name__ == '__main__':
    # capture()
    arr = ['Dog', 'Cat', 'Bird', 'Fish']

    if 'Monkey' in arr and 'Camel' in arr:
        print('Chirp')
    print(arr)
