import multiprocessing
import os
import time
import settings
from capture import Capture
from settings import logger as logging
from utils import verify_interface
import sys


def main():
    logging.info('Starting application with PID: %s' % os.getpid())
    print('PID: %s' % os.getpid())
    interface = settings.NETWORK_INTERFACE
    out_file = settings.PCAP_FILE
    if verify_interface(interface):
        capture = Capture(interface, out_file)
        capture.start()
    else:
        logging.error(f'Interface {interface} doesnt exists, exiting application')
        sys.exit()


if __name__ == '__main__':
    start = time.perf_counter()
    main()
    # to avoid execution ends if packets to capture is different than 0 ( 0 = forever)
    # if its necessary to measure the execution time
    while multiprocessing.active_children():
        pass
    total = time.perf_counter() - start
    print(total)
