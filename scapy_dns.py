from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR
from scapy.all import *
import random
from socket import gethostbyname, gethostname

FILE = r"C:\Users\yonat\Documents\Yuval\devops\networking\scapy-5\DNS_Q.txt"
DB = r"C:\Users\yonat\Documents\Yuval\devops\networking\scapy-5\DNS_data.txt"
MY_IP = gethostbyname(gethostname())
DNS_SERVER = '213.57.2.5'

def get_name_ip():
    name_ip = {}
    with open(DB, 'r') as open_file:
        for field in open_file:
            name = field.split(' ')[0]
            ip = field.split(' ')[1][:-1]
            ip = ip.replace('\n','')
            name_ip[name] = ip
    return name_ip

def new_name_ip(name,ip, name_ip):
    name_ip[name] = ip
    with open(DB, 'a') as open_file:
        open_file.write("{} {}".format(name, ip))
    return name_ip

def filter_dns_query(packet):
    return (((UDP in packet and packet[UDP].dport == 53) or (TCP in packet and packet[TCP].dport == 53)) and \
            DNS in packet and packet[DNS].opcode == 0 and packet[DNS].qr == 0 and \
            DNSQR in packet and (packet[DNSQR].qtype == 1 or packet[DNSQR].qtype == 12))

def get_query_name(dns_packet):
    return dns_packet[DNSQR].qname.decode(), dns_packet[DNSQR].qtype

def filter_server_reply(packet, q_id):
    return (DNS in packet and packet[DNS].opcode == 0 and packet[DNS].qr == 1 and packet[DNS].id == q_id)

def create_dns_reply(ip, dns_name, packet):
    packet_src = packet[IP].src
    packet_sport = packet[UDP].sport
    if ip == "no such name":
        dns = DNS(
        id=packet[DNS].id,
        qd=packet[DNS].qd,
        aa=1,
        rd=0,
        qr=1,
        rcode=3,
        qdcount=1,
        ancount=0,
        nscount=0,
        arcount=0,)
    else:
        dns = DNS(
            id=packet[DNS].id,
            qd=packet[DNS].qd,
            aa=1,
            rd=0,
            qr=1,
            qdcount=1,
            ancount=0,
            nscount=0,
            arcount=0,
            an=DNSRR(
                rrname=dns_name,
                type='A',
                ttl=600,
                rdata=ip))

    reply_packet = IP(dst = packet_src, src = MY_IP)/UDP(sport = 53 ,dport = packet_sport)/dns
    return reply_packet

def create_query(name,query_type):
    query_id =  random. randint(1,65535)
    dns = DNS(
    id = query_id,
    qr = 0,
    opcode = 0,
    aa = 0,
    tc = 0,
    rd = 1,
    ra = 0 , 
    z = 0,
    ad = 0,
    cd = 0,
    rcode = 'ok',
    qdcount = 1,
    ancount = 0,
    nscount = 0,
    arcount = 0,
    qd = DNSQR(
        qname = name,
        qtype = query_type,
        qclass = 'IN'))
    
    query_packet = IP(dst = DNS_SERVER, src = MY_IP)/UDP(sport = 60000 ,dport = 53 )/dns
    return query_packet, query_id

def get_ip(packet):
    for field in packet:
        if field.isinstance(DNSRR):
            print(field.rdata)

def main():
    print(MY_IP)
    name_ip = get_name_ip()
    while True:
        packet = sniff(count=1, lfilter=filter_dns_query)
        dns_name, query_type = get_query_name(packet[0])
        if dns_name in name_ip:
            ip = name_ip[dns_name]
            reply_packet =create_dns_reply(ip, dns_name, packet[0])
            send(reply_packet)
            break
        else:
            ip = 'no such name'
            query_packet, query_id = create_query(dns_name, query_type)
            send(query_packet)
            server_reply = sniff(count=1, lfilter=filter_server_reply(packet,query_id))
            get_ip(server_reply[0])
            break
            #send(reply_packet)
            
            
if __name__ == "__main__":
    main()