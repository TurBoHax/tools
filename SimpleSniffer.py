#Simpple packet sniffer with raw packet
#Run As root

import socket
import struct
import binascii


print "Start Sniffing ..."
line = "==========================================================================================================="
rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
pkt = rawSocket.recvfrom(2048)

# ETHERNET INFO

eth_hdr = pkt[0][0:14]
eth = struct.unpack('!6s6s2s', eth_hdr)

mac_dst = binascii.hexlify(eth[0])
mac_src = binascii.hexlify(eth[1])
eth_type = binascii.hexlify(eth[2])

# IP INFO

ip_hdr = pkt[0][26:34]
ips = struct.unpack('!4s4s', ip_hdr)
ip_src = socket.inet_ntoa(ips[0])
ip_dst = socket.inet_ntoa(ips[1])

# TCP INFO

tcp_hdr = pkt[0][34:54]
tcp = struct.unpack('!HH16s', tcp_hdr)
src_port = tcp[0]
dst_port = tcp[1]


print line
print "SOURCE INFO"
print line
print "[*] src MAC address : %s" % mac_src
print "[*] src IP address : %s" % ip_src
print "[*] src port : %s\n\n" % src_port
print line
print "DESTINATION INFO "
print line
print "[*] dst MAC address : %s" % mac_dst
print "[*] dst IP address : %s" % ip_dst
print "[*] dst port : %s\n\n" % dst_port

while True:
    pass
