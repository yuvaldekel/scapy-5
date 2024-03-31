from scapy.all import *

def filter_facebook(packet):
    return (IP in packet and packet[IP].dst == Net("www.facebook.com/32"))

def show_packet(packet):
    print(packet.show())
    hexdump(packet[Raw].load)

def main():
#    while True:
    sniff(count=5, lfilter=filter_facebook, prn=show_packet)

if __name__ == "__main__":
    main()