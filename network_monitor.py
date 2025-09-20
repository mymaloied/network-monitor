def load_process():
    import sys
    import time
    def check_dependencies():
        try:
            from scapy.all import sniff
            print("Scapy imported successfully")
        except ModuleNotFoundError:
            print("Error: Scapy is not installed")
            return False
        try:
            # try to sniff one testing packet
            sniff(count=1, timeout=1)
            print("Packet capture is working")
            return True
        except (OSError, PermissionError) as e:
            print(f"Packet capture error: {e}")
            print("Possible causes: no npcap, no administrator rights")
            return False
    if not check_dependencies():
        print("Press any key to exit...")
        input()
        sys.exit(1)
    else:
        print("load finished succesfully")

class sniffer():

    def __init__(self):
        self.sniff_packets_count = int(input("Enter the count of packets, you want to sniff: "))
        self.filter_setting = int(input("Enter the the keynumber of your filter: \n" \
        "1. http \n" \
        "2. tcp \n" \
        "3. udp \n" \
        "4. icmp \n" \
        "5. dns \n" \
        "6. arp \n" \
        "7. port 80 \n" \
        "8. port 443 \n" \
        "9. port 53 \n" \
        "10. port 22 \n" \
        "11. tcp and port 80 \n" \
        "12. udp and port 53 \n" \
        "13. not tcp \n" \
        "14. host 8.8.8.8 \n" \
        "15. net 192.168.1.0/24 \n" \
        "16. broadcast \n" \
        "17. multicast \n" \
        "0. no filter \n"))
        
    def simple_sniffer(self):
        from scapy.all import sniff
        packets = sniff(count=self.sniff_packets_count)
        packets_info = [pkt.summary() + "\n" for pkt in packets]
        with open("logs/net_monitor.log", "a") as log:
            log.writelines(packets_info)
        return "Success. Log in logs/net_monitor.log"
    
    def filter_sniffer(self):
        from scapy.all import sniff
        packets = sniff(count=self.sniff_packets_count)
        packets_info = [pkt.summary() + "\n" for pkt in packets]
        with open("logs/net_monitor.log", "a") as log:
            log.writelines(packets_info)
        # filter part
        filter_map = {
            0: "",                    # no filter
            1: "tcp port 80",         # http
            2: "tcp",                 # tcp
            3: "udp",                 # udp
            4: "icmp",                # icmp
            5: "port 53",             # dns
            6: "arp",                 # arp
            7: "port 80",             # port 80
            8: "port 443",            # port 443
            9: "port 53",             # port 53
            10: "port 22",            # port 22
            11: "tcp and port 80",    # tcp and port 80
            12: "udp and port 53",    # udp and port 53
            13: "not tcp",            # not tcp
            14: "host 8.8.8.8",      # host 8.8.8.8
            15: "net 192.168.1.0/24", # net 192.168.1.0/24
            16: "broadcast",          # broadcast
            17: "multicast"           # multicast
        }
        bpf_filter = filter_map.get(self.filter_setting, "")
        packets_filt = sniff(count=self.sniff_packets_count, filter=bpf_filter)
        packets_filt_info = [pkt_f.summary() + "\n" for pkt_f in packets_filt]
        with open("logs/filtered.log", "a") as log:
            log.writelines(packets_filt_info)
        return "Success. Log in logs/net_monitor.log (unfiltered) and filtered.log (filtered)"
    
    

# final start part
load_process()
act = int(input("Actions: \n" \
                "1.Sniffer \n" \
                "2.Clear logs \n"))
if act == 1:
    net_mon = sniffer()
    if net_mon.filter_setting > 0:
        net_mon.filter_sniffer()
    else:
        net_mon.simple_sniffer()
elif act == 2:
    with open("logs/filtered.log", "w") as log:
        pass
    with open("logs/net_monitor.log", "w") as log:
        pass
    print("Done")
    exit(0)