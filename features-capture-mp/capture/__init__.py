from packet import FlowAnalysis
from settings import logger as logging
from pyshark import LiveCapture
from utils import get_processes_names, get_process_by_name


class Capture:
    """
    Class to create the network traffic capture and creates process
    for each netflow
    """

    def __init__(self, interface, output):
        """
        @param interface: name of the interface to capture traffic from
        @param output: output path where to save all captured traffic
        """
        self.interface = interface
        self.out_file = output

    def start(self):
        """
        Starts the capture process and create a process for each netflow
        """
        capture = LiveCapture(self.interface, output_file=self.out_file,)
        logging.info('Starting capture on interface %s', self.interface)
        for packet in capture.sniff_continuously(packet_count=0):
            key, inv_key = self.get_flow_id(packet)
            processes_names = get_processes_names()
            if key in processes_names or inv_key in processes_names:
                if inv_key in processes_names:
                    key = inv_key
                logging.info(f'Captured packet with id: {key}')
                thread = get_process_by_name(key)
                thread.on_thread(packet)
            else:
                logging.info(f'Captured packet with id: {key}')
                thread = FlowAnalysis(key, packet)
                thread.start()

    @staticmethod
    def get_flow_id(packet):
        """
        Extract the key and the inverted key of the netflow from the packet
        @param packet: network packet
        @return: key and inverted key of the netflow
        """
        pkt_protocol = packet.highest_layer
        if 'TCP' in packet:
            pkt_protocol = 'TCP'
        elif 'UDP' in packet:
            pkt_protocol = 'UDP'

        src_port = ''
        dst_port = ''
        if pkt_protocol == 'ARP':
            src_ip = packet.arp.src_proto_ipv4
            dst_ip = packet.arp.dst_proto_ipv4

            key = '%s;%s;%s' % (src_ip, dst_ip, pkt_protocol)
            inv_key = '%s;%s;%s' % (dst_ip, src_ip, pkt_protocol)
        else:
            if 'IP' in packet:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
            elif 'IPV6' in packet:
                src_ip = packet.ipv6.src
                dst_ip = packet.ipv6.dst

            if 'TCP' in packet:
                src_port = packet.tcp.srcport
                dst_port = packet.tcp.dstport
            elif 'ICMP' in packet:
                src_port = packet.icmp.checksum
            elif 'UDP' in packet:
                src_port = packet.udp.srcport
                dst_port = packet.udp.dstport
        try:
            key = "%s; %s; -> %s; %s; %s" % (src_ip, src_port, dst_ip, dst_port, pkt_protocol)
            inv_key = "%s; %s; -> %s; %s; %s" % (dst_ip, dst_port, src_ip, src_port, pkt_protocol)
        except Exception as e:
            print(e)
            print(packet.highest_layer)
            print(packet.layers)

        return key, inv_key
