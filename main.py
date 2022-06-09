import pyshark.tshark.tshark
from pyshark import LiveCapture
from settings import logger as logging, get_config, verify_interface

ARGUS_FLOW_STATUS_INTERVAL = 3600


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


def main():
    logging.info('Starting application')
    configuration = get_config()
    interface = str(configuration['interface']['network_interface'])
    out_file = str(configuration['pcap']['pcap_file'])
    if verify_interface(interface):
        pass
    else:
        logging.error(f'Interface {interface} doesnt exists, exiting application')


if __name__ == '__main__':
    main()
