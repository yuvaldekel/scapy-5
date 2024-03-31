from scapy.all import *

FILE = r"C:\Users\yonat\Documents\Yuval\devops\networking\scapy-5\DNS_Q.txt"

def print_query_name(dns_packet):
    print(dns_packet.show())
    dns_name = dns_packet[DNSQR].qname.decode()
    #print(dns_name)
    with open(FILE, 'a') as open_file:
        open_file.write('{}\n'.format(dns_name))

def filter_dns(packet):
    return (UDP in packet and packet[UDP].dport == 53 and \
            DNS in packet and packet[DNS].opcode == 0 and \
            DNSQR in packet and (packet[DNSQR].qtype == 1 or packet[DNSQR].qtype == 12))

def filter_dns_reply(packet):
    return (DNS in packet and packet[DNS].qr == 1 and \
            DNSQR in packet and (packet[DNSQR].qtype == 1 or packet[DNSQR].qtype == 12))

def print_ip(packet):
    print(packet[DNSRR].rdata)


def main():
#    while True:
    sniff(count=1, lfilter=filter_dns, prn=print_query_name)
    sniff(count=1, lfilter=filter_dns_reply, prn=print_ip)
        
            
if __name__ == "__main__":
    main()