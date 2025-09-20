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
load_process()

class sniffer():

    def __init__(self):
        self.sniff_packets_count = int(input("Enter the count of packets, you want to sniff: "))
    
    def simple_sniffer(self):
        from scapy.all import sniff
        packets = sniff(count=self.sniff_packets_count)
        packets_info = [pkt.summary() + "\n" for pkt in packets]
        with open("logs/net_monitor.log", "a") as log:
            log.writelines(packets_info)
        return "Success. Log in logs/net_monitor.log"

net_mon = sniffer()
net_mon.simple_sniffer()