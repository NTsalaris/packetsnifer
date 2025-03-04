from scapy.all import sniff, IP, TCP, UDP , DNS
from datetime import datetime

times=int(input("dose poses fores tha ginei sniff: "))

file1 = open('data1.txt','w')  

def packet(pkt):

    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if IP in pkt:
        print(f"[{time}] IP Source : {pkt[IP].src}, Destination IP: {pkt[IP].dst}")
        file1.write(f"[{time}] IP Source : {pkt[IP].src}, Destination IP: {pkt[IP].dst}\n")
        file1.flush()
    
    if TCP in pkt:
        print(f"[{time}] TCP source :{pkt[TCP].sport}, Destination TCP: {pkt[TCP].dport}")
        file1.write(f"[{time}] TCP source :{pkt[TCP].sport}, Destination TCP: {pkt[TCP].dport}\n")
        file1.flush()
    
    if UDP in pkt:
        print(f"[{time}] UDP Source :{pkt[UDP].sport}, Destination UDP: {pkt[UDP].dport}")
        file1.write(f"[{time}] UDP Source :{pkt[UDP].sport}, Destination UDP: {pkt[UDP].dport}\n")
        file1.flush()

    if DNS in pkt and pkt[DNS].qd:
        print(f"[{time}] DNS Query: {pkt[DNS].qd.qname.decode()}")
        file1.write(f"[{time}] DNS Query: {pkt[DNS].qd.qname.decode()}")
        file1.flush()

    print("0" * 20)
    file1.write("0"*20)
    file1.write("\n")
    file1.flush()

    

capture = sniff(iface="Ethernet",count=times,prn=packet) #chanche the Ethernet to Eth0 to work in linux

