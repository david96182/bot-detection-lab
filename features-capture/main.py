import os
import settings
from capture import Capture
from settings import logger as logging
from utils import verify_interface
import sys


def main():
    logging.info('Starting application with PID: %s' % os.getpid())
    interface = settings.NETWORK_INTERFACE
    out_file = settings.PCAP_FILE
    if verify_interface(interface):
        capture = Capture(interface, out_file)
        capture.start()
    else:
        logging.error(f'Interface {interface} doesnt exists, exiting application')
        sys.exit()


if __name__ == '__main__':
    main()
