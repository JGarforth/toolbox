import datetime
import socket
from scapy.all import srp, sniff
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
import paramiko
import time
import ftplib
import re


def packet_capture(duration):
    if not duration.isnumeric():
        print("Error: Not a valid time value.")
        return

    active_ips = {}
    start_time = datetime.datetime.now()
    end_time = start_time + datetime.timedelta(seconds=int(duration))

    print(f"Please wait for {duration} seconds...")

    def process_packet(packet):
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if src_ip in active_ips:
                active_ips[src_ip] += 1
            else:
                active_ips[src_ip] = 1

            if dst_ip in active_ips:
                active_ips[dst_ip] += 1
            else:
                active_ips[dst_ip] = 1

        if datetime.datetime.now() > end_time:
            return True

    sniff(prn=process_packet, stop_filter=lambda x: datetime.datetime.now() > end_time, store=False)

    print(f"Packet capture complete. Active IP addresses found:")
    for ip, count in active_ips.items():
        print(f"{ip} : Found {count} times")


def port_scan(target, intensity):
    ports = []
    open_ports = []

    if intensity == 'vulnerable':
        ports = [7, 20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389]
    elif intensity == 'moderate':
        ports = range(1, 1025)  # All well-known ports
    elif intensity == 'intensive':
        ports = range(1, 65536)  # All ports

    port = -1

    try:
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"Port {port}: OPEN")
                open_ports.append(port)
            else:
                print(f"Port {port}: closed")
            sock.close()
    except Exception as exception:
        print(f"At port {port} Error occurred: {exception}")

    if len(open_ports) == 0:
        print("No open ports found.")
    else:
        print("Open ports found:")
        for port in open_ports:
            print(f"Port {port}")


def subnet_scan(subnet):
    if not validate_subnet(subnet):
        print("Subnet is invalid. Please enter in valid format, including CIDR notation.")
        return
    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    for element in answered_list:
        print(f"IP: {element[1].psrc}  MAC: {element[1].hwsrc}")


def ssh_bruteforce(target, username, password_list):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        with open(password_list, 'r') as passwords:
            for password in passwords:
                try:
                    client.connect(target, username=username, password=password.strip(), timeout=5)
                    print(f"Success: {password.strip()}")
                    return
                except paramiko.AuthenticationException:
                    pass
                except Exception as exception:
                    print(f"Error occurred: {exception}")
                    return
                finally:
                    time.sleep(0.5)
    finally:
        client.close()

    print("Bruteforce completed.")


def ssh_bruteforce_full(target, credentials_file):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        with open(credentials_file, 'r') as credentials:
            for line in credentials:
                username, password = line.strip().split(':')
                try:
                    client.connect(target, username=username, password=password.strip(), timeout=5)
                    print(f"Success: Username: {username}, Password: {password.strip()}")
                    return
                except paramiko.AuthenticationException:
                    pass
                except Exception as exception:
                    print(f"Error occurred: {exception}")
                    return
                finally:
                    time.sleep(0.5)
    finally:
        client.close()

    print("Bruteforce completed.")


def ftp_bruteforce(target, username, password_list):
    try:
        with open(password_list, 'r') as passwords:
            for password in passwords:
                try:
                    ftp = ftplib.FTP(target, timeout=5)
                    ftp.login(username, password.strip())
                    print(f"Success: {password.strip()}")
                    ftp.quit()
                    return
                except ftplib.error_perm:
                    pass
                except Exception as exception:
                    print(f"Error occurred: {exception}")
                    return
                finally:
                    time.sleep(0.5)
    except Exception as exception:
        print(f"Error occurred: {exception}")

    print("Bruteforce completed.")


def ftp_bruteforce_full(target, credentials_file):
    try:
        with open(credentials_file, 'r') as credentials:
            for line in credentials:
                username, password = line.strip().split(':')
                try:
                    ftp = ftplib.FTP(target, timeout=5)
                    ftp.login(username, password.strip())
                    print(f"Success: Username: {username}, Password: {password.strip()}")
                    ftp.quit()
                    return
                except ftplib.error_perm:
                    pass
                except Exception as exception:
                    print(f"Error occurred: {exception}")
                    return
                finally:
                    time.sleep(0.5)
    except Exception as exception:
        print(f"Error occurred: {exception}")

    print("Bruteforce completed.")


def validate_subnet(subnet):
    subnet_regex = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/(3[0-2]|[1-2]?[0-9])$")
    if subnet_regex.match(subnet):
        octets = subnet.split('/')[0].split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            return True
    return False
