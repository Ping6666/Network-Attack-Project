from scapy.all import *


class attackTemplate():
    '''
    Template attack function.
    '''
    def __init__(self):
        self.counter = 0
        self.nameString = ''
        return

    def setAll(self,
               dstIP=RandIP(),
               srcIP=RandIP(),
               dstPort=RandEnumShort(),
               srcPort=RandEnumShort(),
               dstMAC=RandMAC(),
               srcMAC=RandMAC(),
               mesk=32,
               iface=conf.iface):
        self.dstIP = dstIP
        self.srcIP = srcIP
        self.dstPort = dstPort
        self.srcPort = srcPort
        self.dstMAC = dstMAC
        self.srcMAC = srcMAC
        self.Mesk = mesk
        self.Iface = iface
        return

    def printStatus(self):
        self.counter += 1
        print('\r' + self.nameString + ' : ' + str("%010d" % self.counter),
              end='')
