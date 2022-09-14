import os
import settings
from capture import Capture
from settings import logger as logging
from utils import verify_interface
import sys


def main():
    logging.info('Starting application')
    configuration = settings.get_config()
    interface = str(configuration['interface']['network_interface'])
    out_file = str(configuration['pcap']['pcap_file'])

    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    if verify_interface(interface):
        capture = Capture(interface, out_file)
        capture.start()
    else:
        logging.error(f'Interface {interface} doesnt exists, exiting application')
        sys.exit()


if __name__ == '__main__':
    main()
