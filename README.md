# Network-Attack-Project

###### tags: `GitHub`

Use scapy to build packets and lunch attack in local LAN.

## Disclaimer

YOU SHOULD NOT USE THIS TOOL OR ANY PART OF THIS TOOL TO HARM OTHER DEVICES. THE ONLY RECOMMEND WAY TO USE IS IN A LAN WITH ALL DEVICES IS YOURS. \
THE USER NEED TO TAKE FULL RESPONSIBILITY NO MATTER WHAT HAPPENED, AND THE DEVELOPER THEN TAKE NONE. \
CHECK THE LICENSE BEFORE YOU USE THIS TOOL.

## Necessary Python Packages

[Scapy](https://scapy.readthedocs.io/en/latest)

## Functions

1. DomaintoIPAddress : use socket to get host IP by its name
2. TCPSYNFloodAttack : TCP SYN packet flood router or victim host
3. UDPFloodAttack : UDP packet flood router or victim host
4. ICMPFloodAttack : ICMP packet flood router or victim host
5. ARPPing : scan all the IP in the same LAN or under some mask
6. ARPSpoofingAttack : ARP sppof router and victim hosts
7. ~~WirelessDeauthenticationAttack~~ : haven't proof yet

## Testing Result

### Enviroment

![](https://i.imgur.com/pDcjI3B.png)

### TCP SYN Flood

![](https://i.imgur.com/NE1FzPY.png)

#### No attack

![](https://i.imgur.com/v9zdkgX.png)

#### Under attack

![](https://i.imgur.com/lNaLfix.png)

### UDP Flood

![](https://i.imgur.com/rvib8pL.png)

> Same as TCP SYN Flood

### ICMP Flood

![](https://i.imgur.com/KVvknuZ.png)

#### No attack the Netflow in 192.168.1.105

![](https://i.imgur.com/au2h1T4.png)

#### Under attack (Host) the Netflow in 192.168.1.105

![](https://i.imgur.com/iE32pSv.png)

#### Under attack (Router) the Netflow in 192.168.1.105

![](https://i.imgur.com/BEILBKt.png)

#### Under attack (Host) the Netflow in 192.168.1.103 (SmartPhone)

![](https://i.imgur.com/tUuIw6n.png)

#### Under attack (Attacker) the Netflow in 192.168.1.101

![](https://i.imgur.com/Xc4hW04.png)

### ARP Spoofing

![](https://i.imgur.com/NXzbtYb.png)

#### Under attack the Connection in 192.168.1.105

![](https://i.imgur.com/qbV1Jzn.png)

#### Under attack the Connection in  192.168.1.103 (SmartPhone)

![](https://i.imgur.com/nYCxaoZ.png)
