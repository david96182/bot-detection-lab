"""
Test if features-capture process the packets and
extract the information using scapy that allows
to create and send custom networks packets
"""
import datetime
import time

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, send

if __name__ == '__main__':
    iface = "br-518ff7874c35"
    packet = Ether() / IP(dst="1.2.3.4", src="5.6.7.8", tos=2, len=1959) / TCP(sport=1996, dport=1996,
                                                                               flags='FSRPA')
    packet.time = datetime.datetime(2022, 7, 22, 22, 22, 22, 22)

    sendp(x=packet, iface=iface)  # send packets at layer 2

    packet = Ether() / IP(dst="22.22.22.22", src="33.33.33.33", tos=2, len=1959) / TCP(sport=9876, dport=6789,
                                                                                       flags='FA')
    sendp(x=packet, iface=iface)
    time.sleep(3)  # check Dur, must greater than 3 seconds
    packet = Ether() / IP(src="22.22.22.22", dst="33.33.33.33", tos=2, len=1959) / TCP(dport=9876, sport=6789,
                                                                                       flags='RSE')
    sendp(x=packet, iface=iface)

    # send(IP(dst='172.22.0.2')/TCP(dport=53, flags='S'), iface='br-518ff7874c35') # send packets at layer 3
