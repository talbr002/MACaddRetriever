import socket, sys, fcntl, ctypes
from struct import *

class ifreq(ctypes.Structure):
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)]

def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0] , a[1] , a[2], a[3], a[4] , a[5])
    return(b)

def MACpacket():
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
    s.bind(('wlp7s1',0))
    IFF_PROMISC = 0x100
    SIOCGIFFLAGS = 0x8913
    SIOCSIFFLAGS = 0x8914
    ifr = ifreq()
    ifr.ifr_ifrn = b'wlp7s1'
    fcntl.ioctl(s.fileno(), SIOCGIFFLAGS, ifr)
    ifr.ifr_flags |= IFF_PROMISC
    fcntl.ioctl(s.fileno(), SIOCSIFFLAGS, ifr)
    while True:
        packet = s.recvfrom(65565)
        packet = packet[0]
        eth_length = 14
        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])
        #print('DestMAC : ' + eth_addr(packet[0:6]) + ' Source MAC : '
        #      + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
        if eth_protocol == 8:
            ip_header = packet[eth_length:20+eth_length]
            iph = unpack('!BBHHHBBH4s4s' , ip_header)
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])
            print ('dAdd: ' + d_addr + ' \t MAC : ' + eth_addr(packet[0:6]))
            print('sAdd: ' + s_addr +  '\t MAC : ' + eth_addr(packet[6:12])
                  + '\n')

    



def main():
    MACpacket()
main()

