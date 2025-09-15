# Network-Sniffer
This is to demonstrate how to capture live network traffic on a device to identify credentials and suspicious activity 

## Tools Used:
- Kali Linux (OS) 
- TCPDump (CLI packet capture)
- Wireshark (GUI-based packet analysis)
- TShark (CLI-based wireshark) 

## Methodology
### 1. Identify network interface 
```bash
ip a #this command shows the network devices on your device
```

### 2. Capture traffic 
TCPDump to capture live traffic:
```bash
sudo tcpdump -i <interface> -w <filename>.pcap
#example:
sudo tcpdump -i wlan0 -w capture.pcap
```

### 3. Analyze using Wireshark
Open Wireshark in terminal
```bash
wireshark capture.pcap &
```
Apply filters:
-http.request  
-http.request.method == "POST"
-ip.addr == <target IP>

### 4.Extract POST Requests via TShark
```bash
tshark -r pcap/capture.pcap -Y 'http.request.method == "POST"' -T fields -e http.host -e http.request.uri -e http.file_data > analysis/post_requests.txt
# this code will write all the post request detected in the capture.pcap file into a text file 
```
