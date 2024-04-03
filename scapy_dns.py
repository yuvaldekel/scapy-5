from scapy.all import *

FILE = r"C:\Users\yonat\Documents\Yuval\devops\networking\scapy-5\DNS_Q.txt"

def print_query_name(dns_packet):
    dns_name = dns_packet[DNSQR].qname.decode()
    print(dns_name)
    with open(FILE, 'a') as open_file:
        open_file.write('{}\n'.format(dns_name))



def filter_dns(packet):
    return (DNS in packet and packet[DNS].opcode == 0 and packet[DNS].qr == 0 and \
            DNSQR in packet and packet[DNSQR].qtype == 1 and packet[DNSQR].qname.decode() == 'www.themarker.com.')

def main():
    packet = sniff(count=1, lfilter=filter_dns, prn= lambda p:print(p.show()))
    packet_dns = packet[0][3]
    print(packet_dns[1].show())

if __name__ == "__main__":
    main()