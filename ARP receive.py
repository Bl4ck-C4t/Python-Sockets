import socket
from struct import unpack_from
import csv


# ARP_FRAME = [
#         pack('!H', 0x0001),  # HRD
#         pack('!H', 0x0800),  # PRO
#         pack('!B', 0x06),  # HLN
#         pack('!B', 0x04),  # PLN
#         pack('!H', 0x0001),  # OP
#         pack('!6B', *local_mac),  # SHA
#         pack('!4B', *local_ip),  # SPA
#         pack('!6B', *(0x00,) * 6),  # THA
#         pack('!4B', *dest_ip),  # TPA
#     ]
def bytes_to_mac(mac_bytes):
    return ':'.join(map(lambda x: '{0:02x}'.format(x), mac_bytes))


opcodes = {}
ether_types = {}
with open("operation.csv", "r") as f:  # make use of ranges
    reader = csv.reader(f)
    for line in reader:
        for num in line[0].split("-"):
            opcodes[int(num)] = line[1]

with open("ether-types.csv", "r") as f:  # make use of ranges
    reader = csv.reader(f)
    for line in reader:
        if reader.line_num == 1:
            continue
        for num in line[1].split("-"):
            ether_types[int(num, 16)] = line[4]

s1 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0806))
while True:
    print("Listening for arp packets...")
    all_data = s1.recv(4096)
    arp_data = all_data[14:]
    print(arp_data)
    print(all_data)
    layer2 = unpack_from("!6B6BH", all_data)
    unpacked = unpack_from("!HHBBH6B4B6B4B", all_data, 14)
    print(f"Layer 2 Header!")
    print(f"Destination MAC: {bytes_to_mac(unpack_from('!6B', all_data))}")
    print(f"Source MAC: {bytes_to_mac(layer2[7:12])}")
    print(f"Type: {ether_types[layer2[12]]}")
    print("-" * 20)
    print(f"\nArp message Received!\nProtocol: {ether_types[unpacked[1]]}\nType: {opcodes[unpacked[4]]}\n"
          f"From {socket.inet_ntoa(arp_data[14:18])} "
          f"MAC: {bytes_to_mac(unpacked[5:11])}\n"
          f"To {socket.inet_ntoa(arp_data[24:28])} "
          f"MAC: {bytes_to_mac(unpack_from('!6B', all_data))}\n")
