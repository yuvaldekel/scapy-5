from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR
from scapy.all import *
import random
from socket import gethostbyname, gethostname
import datetime

FILE = r"C:\Users\yonat\Documents\Yuval\devops\networking\scapy-5\DNS_Q.txt"
DB = r"C:\Users\yonat\Documents\Yuval\devops\networking\scapy-5\DNS_data.txt"
MY_IP = gethostbyname(gethostname())
DNS_SERVER = '8.8.8.8'

def name_ip_dict():
    name_ip = {}
    with open(DB, 'r') as open_file:
        for field in open_file:
            attributes = field.split(' ')
            ip = attributes[1][:-1]
            name = attributes[0]
            
            if len(attributes) >= 3:
                ttl = " ".join(attributes[2:])
                ttl = ttl.replace('\n','')
                now = str(datetime.datetime.now())
                if ttl >= now:
                    name_ip[name] = ip
            else:       
                name_ip[name] = ip
    return name_ip

def write_db(name, ip, name_ip, expiration):
    with open(DB, 'a') as open_file:
        open_file.write("{} {} {}\n".format(name, ip, expiration))

def filter_dns_query(packet):
    return (((UDP in packet and packet[UDP].dport == 53) or (TCP in packet and packet[TCP].dport == 53)) and \
            DNS in packet and packet[DNS].opcode == 0 and packet[DNS].qr == 0 and \
            DNSQR in packet and (packet[DNSQR].qtype == 1 or packet[DNSQR].qtype == 12))

def get_query_name_type(dns_packet):
    if DNSQR in dns_packet:
        return dns_packet[DNSQR].qname.decode(), dns_packet[DNSQR].qtype

def create_dns_reply(ip, dns_name, query_type, packet, time_to_live = 60):
    if IP in packet:
        packet_src = packet[IP].src
    if UDP in packet:
        packet_sport = packet[UDP].sport
    if TCP in packet:
        packet_sport = packet[TCP].sport

    dns = DNS(
    id=packet[DNS].id,
    qd=packet[DNS].qd,
    aa=1,
    rd=0,
    qr=1,
    rcode='ok',
    qdcount=1,
    ancount=1,
    nscount=0,
    arcount=0)
    if ip == None:
        dns.rcode=3
        dns.ancount=0
    else:
        dns.an=DNSRR(
            rrname=dns_name,
            type=query_type,
            ttl=time_to_live,
            rdata=ip)

    reply_packet = IP(dst = packet_src, src = MY_IP)/UDP(sport = 53 ,dport = packet_sport)/dns
    return reply_packet

def create_query(name,query_type):
    global query_id
    query_id =  random. randint(10000,65535)
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
    return query_packet

def filter_server_reply(packet):
    return (((UDP in packet and packet[UDP].sport == 53) or (TCP in packet and packet[TCP].sport == 53)) and \
              DNS in packet and packet[DNS].opcode == 0 and packet[DNS].qr == 1 and packet[DNS].id == query_id)

def find_ip(packet,name_ip,dns_name):
    answer = packet[DNS].an
    count = packet[DNS].ancount 

    if answer != None:
        answer = answer[count - 1]
        ip = answer.rdata
        expiration = str(datetime.datetime.now() + datetime.timedelta(seconds=answer.ttl))
        write_db(dns_name, ip, name_ip, expiration)
        return ip, answer.ttl
    else:
        return None, 0

def main():
    while True:
        name_ip = name_ip_dict()
        sniffed_packet = sniff(count=1, lfilter=filter_dns_query)
        dns_name, query_type = get_query_name_type(sniffed_packet[0])
        
        if dns_name in name_ip:
            ip = name_ip[dns_name]
            reply_packet =create_dns_reply(ip, dns_name, query_type, sniffed_packet[0])
            send(reply_packet)
            break
        else:
            query_packet = create_query(dns_name, query_type)
            send(query_packet)
            server_reply = sniff(count=1, timeout=20, lfilter=filter_server_reply)
            try:
                ip, ttl = find_ip(server_reply[0], name_ip, dns_name)
                reply_packet =create_dns_reply(ip, dns_name, query_type, sniffed_packet[0], ttl)
                send(reply_packet)
                print(reply_packet.show())
                break     
            except IndexError:
                print("8.8.8.8 reply timed out.")

if __name__ == "__main__":
    main()