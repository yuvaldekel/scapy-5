from scapy.all import *

FILE = r"C:\Users\yonat\Documents\Yuval\devops\networking\scapy-5\DNS_Q.txt"
DB = r"C:\Users\yonat\Documents\Yuval\devops\networking\scapy-5\DNS_data.txt"
MY_IP = '192.168.68.54'

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
    return dns_packet[DNSQR].qname.decode()

def get_src(packet):
    if IP in packet:
        return packet[IP].src

def get_sport(packet):
    if TCP in packet:
        return packet[TCP].sport
    if UDP in packet:
        return packet[UDP].sport

def create_dns_reply(ip, dns_name, packet):
    query_src = get_src(packet)
    query_sport = get_sport(packet)
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
                rdata=ip)
            )

    reply_packet = IP(dst = query_src, src = MY_IP)/UDP(sport = 53 ,dport = query_sport )/dns
    print(reply_packet.show())
    return reply_packet

def main():
    name_ip = get_name_ip()
    while True:
        packet = sniff(count=1, lfilter=filter_dns_query)
        dns_name = get_query_name(packet[0])
        if dns_name in name_ip:
            ip = name_ip[dns_name]
            reply_packet =create_dns_reply(ip, dns_name, packet[0])
            send(reply_packet)
            break
        else:
            ip = 'no such name'
            reply_packet =create_dns_reply(ip, dns_name, packet[0])
            send(reply_packet)
            break
            
if __name__ == "__main__":
    main()