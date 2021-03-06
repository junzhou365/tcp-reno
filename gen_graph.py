from scapy.all import *
import matplotlib.pyplot as plt

#Change this to be your pcap file
#You can capture a pcap file with wireshark or tcpdump
#https://support.rackspace.com/how-to/capturing-packets-with-tcpdump/
FILE_TO_READ = '/Users/jzhou/code/CMU-15-441/Project-2-Starter-Code/15-441-project-2/utils/client.pcap'

packets = rdpcap(FILE_TO_READ)
packet_list = []
times = []
base = 0
server_port = 15441
num_packets = 0

units = []

seen_seq = 0

for i, packet in enumerate(packets):
    payload = packet[Raw].load

    if(IP in packet and (packet[IP].dport == server_port or packet[IP].sport == server_port) and 15441 == int.from_bytes(payload[:4], byteorder='big')):
        seq = int.from_bytes(payload[8:12], byteorder='big')
        mask = int.from_bytes(payload[20:21], byteorder='big')
        if(mask == 0):
            if seq  > seen_seq:
                num_packets = num_packets + 1
                seen_seq = seq
        elif((mask & 4) == 4):
            num_packets = max(num_packets - 1, 0)
        elif((mask & 2) == 2):
            num_packets = num_packets + 1
        elif((mask & 8) == 8):
            num_packets = num_packets + 1

        time = packet.time

        if base == 0:
            base = time

        packet_list.append(num_packets)
        times.append(time - base)
        units.append((i, times[-1], packet_list[-1]))

#https://matplotlib.org/users/pyplot_tutorial.html for how to format and make a good quality graph.
# print(units)
plt.plot(times, packet_list)
plt.show()
