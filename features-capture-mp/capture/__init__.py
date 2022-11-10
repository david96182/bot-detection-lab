from packet import FlowAnalysis
from settings import logger as logging
from pyshark import LiveCapture
from utils import get_processes_names, get_process_by_name


def get_flow_id(packet):
    """
    Returns the flow id of a network packet.
    """
    pkt_protocol = packet.highest_layer
    if pkt_protocol == 'DATA':
        pkt_protocol = packet.layers[len(packet.layers) - 2].layer_name
    try:
        if pkt_protocol == 'ARP':
            src_ip = packet.arp.src_proto_ipv4
            dst_ip = packet.arp.dst_proto_ipv4

            key = '%s;%s;%s' % (src_ip, dst_ip, pkt_protocol)
            inv_key = '%s;%s;%s' % (dst_ip, src_ip, pkt_protocol)
        else:
            if 'IP' in packet:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
            elif 'IPv6' in packet:
                src_ip = packet.ipv6.src
                dst_ip = packet.ipv6.dst

            if 'TCP' in packet:
                src_port = packet.tcp.srcport
                dst_port = packet.tcp.dstport
            elif 'ICMP' in packet:
                src_port = packet.icmp.udp_srcport
                dst_port = packet.icmp.udp_dstport
            else:
                src_port = packet.udp.srcport
                dst_port = packet.udp.dstport

            key = "%s; %s; -> %s; %s; %s" % (src_ip, src_port, dst_ip, dst_port, pkt_protocol)
            inv_key = "%s; %s; -> %s; %s; %s" % (dst_ip, dst_port, src_ip, src_port, pkt_protocol)

    except AttributeError():
        logging.error(f'Packet has no IP layer: {packet.highest_layer}')
        logging.error(packet)
        logging.error(packet.ip.src)

    return key, inv_key


class Capture:
    """
    Class to create the capture and processing flow
    """

    def __init__(self, interface, output):
        self.interface = interface
        self.out_file = output

    def start(self):
        """
        Starts the capture process and create a process for each netflow
        """
        capture = LiveCapture(self.interface, output_file=self.out_file)
        # capture.sniff(timeout=0)
        logging.info('Starting capture on interface %s', self.interface)

        for packet in capture.sniff_continuously(packet_count=20000):   # live capture
            key, inv_key = get_flow_id(packet)
            if key in get_processes_names() or inv_key in get_processes_names():
                if inv_key in get_processes_names():
                    key = inv_key
                logging.info(f'Captured packet with id: {key}')
                thread = get_process_by_name(key)
                thread.on_thread(packet)
            else:
                logging.info(f'Captured packet with id: {key}')
                thread = FlowAnalysis(key, packet)
                thread.start()

