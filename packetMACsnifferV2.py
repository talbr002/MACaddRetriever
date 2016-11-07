#! /usr/bin/env python3

import socket, sys, fcntl, ctypes, datetime, time
from struct import *
startTimeDict = {}
lastSeenDict = {}

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
        if eth_protocol == 8:
            ip_header = packet[eth_length:20+eth_length]
            iph = unpack('!BBHHHBBH4s4s' , ip_header)
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])
            print ('dAdd: ' + d_addr + ' \t MAC : ' + eth_addr(packet[0:6]))
            print('sAdd: ' + s_addr +  '\t MAC : ' + eth_addr(packet[6:12])
                  + '\n')
            interpret(s_addr, eth_addr(packet[6:12]))
            interpret(d_addr, eth_addr(packet[0:6]))
            print(startTimeDict)
            
            update(s_addr, eth_addr(packet[6:12]))
            update(d_addr, eth_addr(packet[0:6]))
            print(lastSeenDict)
            


#interpret keeps track of the FIRST time a MAC address was seen
def interpret(address, MAC ):
    global startTimeDict
    networkAdd = (list(address))
    netbuild = networkAdd[0] + networkAdd[1] + networkAdd[2]
    if (netbuild == '192'):
        if MAC  not in startTimeDict:
            t =  datetime.datetime.now().time()
            startTimeDict[MAC] = (str(t)[:7])
            

#update keeps track of the LAST time a MAC address was seen
def update(address, MAC):
    global lastSeenDict
    networkAdd = (list(address))
    netbuild = networkAdd[0] + networkAdd[1] + networkAdd[2]
    if (netbuild == '192'):
            t =  datetime.datetime.now().time()
            lastSeenDict[MAC] = (str(t)[:7])
            checker(MAC)

#checker is used to check to see if a MAC address was seen in the last 10 mins
#If it wasn't then it removes it from the StartTimeDict
def checker(MAC):
    global startTimeDict
    global lastSeenDict
    startHour = int(startTimeDict[MAC].split(':', 2)[0])
    startMinute = int(startTimeDict[MAC].split(':', 2)[1])
    recentHour = int(lastSeenDict[MAC].split(':', 2)[0])
    recentMinute = int(lastSeenDict[MAC].split(':', 2)[1])
    if(startHour == recentHour):
        if((recentMinute - startMinute) > 10):
            del startTimeDict[MAC]
    else:
        recentMinute += 60
        if((recentMinute - startMinute) > 10):
            del startTimeDict[MAC]
            
            
    




def main():
    MACpacket()
main()

#@atexit.register
#def exit():
#    ifr = ifreq()
#    ifr.ifr_ifrn = b'wlp7s1'
#    ifr.ifr_flags &= ~IFF_PROMISC
#    fcntl.ioctl(s.fileno(), SIOCSIFFLAGS, ifr)

