from scapy.all import *

def filter_http(packet):
    return (TCP in packet and Raw in packet and packet[Raw].load.decode(errors= 'ignore').startswith("GET"))

def print_url(http_packet):
    
    request = http_packet[Raw].load.decode()
    host = ''
    
    if 'Host: ' in request:
        host_index = request.index('Host: ')
        end_line = request.index('\r\n', host_index)
        host = request[host_index+6 : end_line]
    
    path = request.split(' ')[1]
    
    url = "http://{}{}".format(host, path)
    print(url)

def main():
    sniff(count=1, lfilter=filter_http, prn=print_url)  
            
if __name__ == "__main__":
    main()
