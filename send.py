from scapy.all import *


def main():
    my_packet =IP( dst ='www.google.com')/TCP(sport =5000,dport = 80 )/Raw("GET / HTTP/1.0\r\n\r\n")
    print(my_packet.show())
    send(my_packet)
  
if __name__ == "__main__":
    main()