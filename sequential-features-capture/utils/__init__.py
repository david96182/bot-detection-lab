from datetime import datetime
import pyshark.tshark.tshark
from settings import logger as logging


def get_date_string(date_str):
    """
    Return a date giving the date as string. Patch applied also to remove
    space found in some dates from networks packets
    @return: datetime object
    """
    date_spl = date_str.split(' ')
    if '' in date_spl:
        date_spl.remove('')
    date_str = date_spl[0] + ' ' + date_spl[1] + ' ' + date_spl[2] + ' ' + date_spl[3][:-3] + ' ' + date_spl[4]
    date_str = datetime.strptime(date_str, '%b %d, %Y %H:%M:%S.%f %Z')

    return date_str


def verify_interface(interface):
    """
    Verify if the interface is recognizable and available
    @param interface: interface name
    @return: True if interface is found else False
    """
    interfaces = pyshark.tshark.tshark.get_tshark_interfaces()
    if interface in interfaces:
        return True
    return False


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
