import socket
import struct
from struct import pack
from uuid import getnode as get_mac


# refer to man socket and python socket module
# SOCK_RAW - refer to packet man, does not come with data-link header
# SOCK_DGRAM - comes with link-layer header set py addr
# http://www.networksorcery.com/enp/protocol/arp.htm
def main():
    dest_ip = [192, 168, 43, 1]
    # dest_ip = [127, 0, 0, 1]
    local_mac = [int("{0:012x}".format(get_mac())[i:i + 2], 16) for i in range(0, 12, 2)]
    local_ip = [int(x) for x in socket.gethostbyname(socket.gethostname()).split('.')]
    interface = 'ens33'
    # binascii.crc32
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, 0x0806)
    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    # sock.bind(('ens33', 0x0806, socket.PACKET_BROADCAST))

    ARP_FRAME = [
        pack('!H', 0x0001),  # HRD
        pack('!H', 0x0800),  # PRO
        pack('!B', 0x06),  # HLN
        pack('!B', 0x04),  # PLN
        pack('!H', 0x0001),  # OP
        pack('!6B', *local_mac),  # SHA
        pack('!4B', *local_ip),  # SPA
        pack('!6B', *(0x00,) * 6),  # THA
        pack('!4B', *dest_ip),  # TPA
    ]
    print(ARP_FRAME)
    print(b''.join(ARP_FRAME))
    ad1 = b'\x70\x1c\xe7\x5b\x20\xc5'
    addr = (interface, 0x0806, socket.PACKET_BROADCAST, 0x0001, b'\xff\xff\xff\xff\xff\xff')
    sock.sendto(b''.join(ARP_FRAME), addr)
    sock.close()


if __name__ == "__main__":
    main()
