import sys
import config
from capture import Capture
from settings import logger as logging


def main():
    logging.info('Starting application')
    configuration = config.get_config()
    interface = str(configuration['interface']['network_interface'])
    out_file = str(configuration['pcap']['pcap_file'])

    if config.verify_interface(interface):
        capture = Capture(interface, out_file)
        capture.start()
    else:
        logging.error(f'Interface {interface} doesnt exists, exiting application')
        sys.exit()


if __name__ == '__main__':
    main()
