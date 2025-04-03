import sys
from io import StringIO
from scapy.layers import inet
from scapy.all import *
from scapy.layers.inet import TCP

# capture = sniff(prn=lambda x:x.summary())

packet = sniff(count=1)[0]


print(packet)

packet = sniff(count=1)[0]

# Function to print all the attributes (tags) of the packet
def print_packet_attributes(packet):
    print("Packet Summary:")
    packet.summary()
    print("\nPacket Detailed Attributes:")
    packet.show()

# Print the attributes of the captured packet
print_packet_attributes(packet)
