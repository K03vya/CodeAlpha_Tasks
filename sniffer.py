import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP
from colorama import init, Fore, Style

# Initialize colorama for clean, colorful terminal output
init(autoreset=True)

def process_packet(packet):
    # We only want to analyze packets that have an IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        # 1. Handle TCP Traffic
        if packet.haslayer(TCP):
            print(f"{Fore.CYAN}[TCP]{Fore.RESET} {src_ip} -> {dst_ip} | Port: {packet[TCP].sport} -> {packet[TCP].dport}")
            if packet[TCP].payload:
                payload_data = str(packet[TCP].payload)[:60]
                print(f"   {Fore.LIGHTBLACK_EX}Data: {payload_data}")
                
        # 2. Handle UDP Traffic
        elif packet.haslayer(UDP):
            print(f"{Fore.GREEN}[UDP]{Fore.RESET} {src_ip} -> {dst_ip} | Port: {packet[UDP].sport} -> {packet[UDP].dport}")
            
        # 3. Handle ICMP (Ping) Traffic
        elif packet.haslayer(ICMP):
            print(f"{Fore.YELLOW}[ICMP/Ping]{Fore.RESET} {src_ip} -> {dst_ip}")
            
        # 4. Other Protocols
        else:
            print(f"{Fore.MAGENTA}[PROTO {proto}]{Fore.RESET} {src_ip} -> {dst_ip}")

def main():
    print(Style.BRIGHT + Fore.BLUE + "==================================================")
    print(Style.BRIGHT + Fore.BLUE + "    CODEALPHA - TOP 10% BASIC NETWORK SNIFFER     ")
    print(Style.BRIGHT + Fore.BLUE + "==================================================")
    print(Fore.LIGHTYELLOW_EX + "[*] Initialization complete. Scanning network traffic...")
    print(Fore.LIGHTRED_EX + "[!] Press CTRL+C to safely stop sniffing.\n")
    
    try:
        # Start sniffing traffic (store=False keeps memory usage low)
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print(f"\n{Fore.LIGHTGREEN_EX}[+] Sniffer stopped successfully. Great job!")
        sys.exit(0)
    except PermissionError:
        print(f"\n{Fore.RED}[X] ERROR: Missing Privileges!")
        print(f"{Fore.YELLOW}[i] Network sniffing requires Administrator / Root permissions.")
        print(f"{Fore.YELLOW}[i] Please re-run your terminal as Administrator.")
        sys.exit(1)

if __name__ == "__main__":
    main()