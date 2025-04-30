import sys
from io import StringIO
from scapy.layers import inet
from scapy.all import *
from scapy.layers.inet import TCP


packet = sniff(count=1)[0]


print(packet)

packet = sniff(count=1)[0]

def print_packet_attributes(packet):
    print("Packet Summary:")
    packet.summary()
    print("\nPacket Detailed Attributes:")
    packet.show()

print_packet_attributes(packet)
