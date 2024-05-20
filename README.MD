## Tracert Script

This script is designed to perform traceroute to a given IP address, displaying the route along with the Autonomous System (AS) numbers of intermediate nodes using WHOIS service responses, similar as tracert script from Windows.

### Input Format
- IP address (or DNS name) passed as a command-line argument.

### Output Format
For each address in the traceroute:
```
N. IP
NETNAME, AS, COUNTRY
```
- N: Host number in the traceroute (starting from 1)
- IP: IPv4 address of the host
- NETNAME: Network name
- AS: Autonomous System number (^\d+$)
- COUNTRY: Country of the network
- If any information is missing, it's not included in the output.
- If the IP address in the traceroute is local, "local" is written in the information line.
- If a node in the traceroute doesn't respond, "*" is written instead of the IP, and the information line disappears.
- If an incorrect address is specified, "ADDRESS is invalid" is written, where ADDRESS is the incorrect parameter.
- If permissions are insufficient, error is displayed.

### Implementation Overview
1. **Validation and Retrieval of IP Address or Domain Name:** Validates the passed address using regular expressions. If the address is invalid, an error message is displayed.
   
2. **Traceroute using ICMP Packets:** Traceroute is performed using ICMP Echo Request packets with gradually increasing TTLs. Each sent packet is remembered for subsequent analysis. Requires administrator privileges to run.
   - **ICMP Packet using struct:** Utilizes the **struct** module to create ICMP Echo Request packets, packing necessary fields into binary format.
   
3. **Analysis of ICMP Responses:** After sending each packet, waits for a response from intermediate nodes or the destination. Analyzes received responses to determine relevant data.
   
4. **Querying WHOIS for Information:** Queries the appropriate WHOIS server for each intermediate node to retrieve additional information such as AS number and country.
   
5. **Formatted Output of Results:** Displays obtained information about intermediate nodes according to the specified format. If data is not received from the server, "*" is shown. If the address is local, "local" is displayed instead of information.

### How to Run
1. Ensure Python environment is set up.
2. Clone the repository.
3. Navigate to the directory containing the script.
4. Run the script with the desired IP address or DNS name as a command-line argument.

### Example Usage
```
python tracert.py 8.8.8.8 # Any latin Domain name (no punycode) or IP address
```

### Additional Notes
- The script requires appropriate permissions to run due to the usage of raw sockets.
- WHOIS server responses may vary based on network configurations and availability.
- Firewall might block ICMP packets, so best practice is
to turn it off while using script