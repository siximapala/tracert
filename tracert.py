import struct
import socket
import os
import time
import select
import re
import sys

# Check if the address is local to avoid WHOIS queries,
# mark it as local in the output
def is_local_ip(ip_address):
    if not isinstance(ip_address, str):
        return False
    
    octets = ip_address.split('.')
    if len(octets) != 4:
        return False
    
    first_octet = int(octets[0])
    if first_octet == 10 \
            or (first_octet == 172 and 16 <= int(octets[1]) <= 31) \
            or (first_octet == 192 and int(octets[1]) == 168):
        return True
    
    # Check for localhost (127.0.0.1)
    if ip_address == '127.0.0.1':
        return True
    if ip_address == '0.0.0.0':
        return True
    return False

# Required for obtaining information about the IP address.
# If a generic WHOIS server is used, often the necessary information about our IP address will not be there.
# The WHOIS server for the IP address with the most up-to-date information can be found at whois.iana.org
def get_appropiate_whois_server(ip_addr):
    iana_server = "whois.iana.org"  # IANA WHOIS server
    
    # Connect to the IANA WHOIS server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((iana_server, 43))

    # Send a request to the IANA WHOIS server
    s.send((ip_addr + "\r\n").encode())

    # Get the response
    response = b""
    while True:
        data = s.recv(4096)
        if not data:
            break
        response += data

    # Extract the WHOIS server from the IANA response
    lines = response.decode().split("\n")
    for line in lines:
        if line.startswith("whois:"):
            whois_server = line.split(":")[1].strip()
            return whois_server
    return -1
       
# After finding the appropriate WHOIS server for a specific IP, get information about
# AS, NETNAME, COUNTRY from there
def whois_concrete_data(domain, whois_server):
    country = ''
    as_number = ''
    network_name = ''
    try:
        # Connect to the WHOIS server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((whois_server, 43))

        # Send the request
        s.send((domain + "\r\n").encode())

        # Get the response
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data

        for line in response.decode().split("\n"):
            if "country:" in line.lower():
                country = line.split(":")[1].strip()
            elif "origin:" in line.lower():
                as_number = line.split(":")[1].strip()
            elif "netname:" in line.lower():
                network_name = line.split(":")[1].strip()
    except Exception as e:
        return f"Error: {e}"
    return {"Country": country, "AS": as_number, "Network Name": network_name}

def calculate_checksum(source_bytes):
    countTo = (int(len(source_bytes) / 2)) * 2
    sum = 0
    count = 0

    # Handle bytes in pairs (decoding as short ints)
    while count < countTo:
        loByte = source_bytes[count]
        hiByte = source_bytes[count + 1]
        sum = sum + (hiByte * 256 + loByte)
        count += 2

    # Handle last byte if applicable (odd-number of bytes)
    if countTo < len(source_bytes): # Check for odd length
        loByte = source_bytes[len(source_bytes) - 1]
        sum += loByte

    sum &= 0xffffffff # Truncate sum to 32 bits

    sum = (sum >> 16) + (sum & 0xffff)  # Add high 16 bits to low 16 bits
    sum += (sum >> 16)                  # Add carry from above (if any)
    answer = ~sum & 0xffff              # Invert and truncate to 16 bits

    return answer

# Pack data into binary format for socket using struct
def create_icmp_packet():
    icmp_type = 8
    icmp_code = 0
    icmp_id = os.getpid() & 0xFFFF
    icmp_seq = 1
    data = struct.pack("d", time.time())
 
    icmp_header = struct.pack("bbHHh", icmp_type, icmp_code, 0, icmp_id, icmp_seq)

    icmp_checksum = calculate_checksum(icmp_header + data)

    icmp_header_with_checksum = struct.pack("bbHHh", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

    return icmp_header_with_checksum + data


def receive_ping(my_socket, timeout):
    received_data = ["",""]
    while True:
        ready, _, _ = select.select([my_socket], [], [], timeout) # Get data from socket by readiness
        if ready:
            packet_data, addr = my_socket.recvfrom(1024)
            icmp_type, _, _, _, _ = struct.unpack("bbHHh", packet_data[20:28])

            received_data[0] = addr[0]

            whois_request_server = get_appropiate_whois_server(addr[0])
            if whois_request_server != -1:
                received_data[1] = whois_concrete_data(addr[0], whois_request_server)
            else:
                # If the method did not find an optimal WHOIS server in IANA, search in RIPE with extended tag
                received_data[1] = whois_concrete_data(addr[0], "-B whois.ripe.net")

            if icmp_type == 0:
                received_data.append("Trace complete.")
            return received_data
        else:
            return -1
        
def is_valid_address(address):
    # Check for the validity of a domain name
    domain_pattern = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:(?:[A-Za-z0-9-]){0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$", re.IGNORECASE)
    if domain_pattern.fullmatch(address):
        return True
    
    # Check for the validity of an IP address
    ip_pattern = re.compile(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    if ip_pattern.match(address):
        return True
    
    return False



def tracert(ip_addr):

    try:
        try:
            if is_valid_address(ip_addr) == False: # проверка адреса на валидность
                raise Exception
            dest_ip = socket.gethostbyname(ip_addr)
        except:
            print(f"ERROR: {ip_addr} is not valid!")
            return -1
        if is_local_ip(ip_addr):
            print(f"ERROR: {ip_addr} is local")
            return -1
    
        print(f"Tracing route to {ip_addr} {'['+dest_ip+']' if ip_addr != dest_ip else ''}\nover a maximum of 30 hops:\n")
        
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
        max_hops = 30
        timeout = 2

        for ttl in range(1, max_hops + 1):
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)  # Set TTL

            icmp_packet = create_icmp_packet() # Create ICMP packet
            s.sendto(icmp_packet, (dest_ip, 1))  # Send ICMP packet

            received_data = receive_ping(s, timeout) # Receive data into socket

            if received_data == -1: # If no data received, skip and mark the address with a star
                print(f"{ttl}: *\n")
                continue
            else:
                print(f"{ttl}: {received_data[0]}")

            if is_local_ip(received_data[0]): # Check if the address of the node within the trace is local
                print("local\n")
                continue

            if 'AS' in received_data[1]:
                as_number = re.sub(r'\D', '', received_data[1]['AS'])  # Remove all non-numeric characters in AS using regex
                received_data[1]['AS'] = as_number

            try: 
                print(", ".join([f"{key}: {value}" for key, value in received_data[1].items() if value])) # If data available, get from dictionary
                if received_data[2] == "Trace complete.":
                    break
            except:
                pass

            print("")
        print("Trace complete.")
    except KeyboardInterrupt:
        print("Tracert interrupted by user.")
        sys.exit(0)
    except PermissionError: # Uses RAW socket, handling permission requirement
        print("Not enough Permissions: open as Administrator.")
        sys.exit(0)
    except OSError as e:
        print(f"OSError: {e}")
    except Exception as e:
        print(f"Error: {e}")
        
def main():
    if len(sys.argv) != 2: # Handling absence of argument
        print("ERROR: IPv4 address or domain name needed as argument")
        sys.exit(1)
    tracert(sys.argv[1])

if __name__ == "__main__":
    main()