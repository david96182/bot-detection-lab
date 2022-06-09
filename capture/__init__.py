"""
Packet Analyzer for the Capture Module
 :StartTime
 :Dur
 :Proto
 :SrcAddr
 :Sport
 :Dir
 :DstAddr
 :Dport
 :State
 :sTos
 :dTos
 :TotPkts
 :TotBytes
 :SrcBytes
"""


def get_packet_protocol(packet):
    """
    Returns the protocol of the packet.
    """
    return packet.highest_layer
