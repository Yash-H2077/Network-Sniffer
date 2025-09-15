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

### 3. Analyze Traffic using Wireshark
Open Wireshark in terminal
```bash
wireshark capture.pcap &
```
### 4. Apply filters in Wireshark:
i) http.request  
ii) http.request.method == "POST"  
iii) ip.addr == < target ip > 

### 5.Extract POST Requests via TShark
```bash
tshark -r pcap/capture.pcap -Y 'http.request.method == "POST"' -T fields -e http.host -e http.request.uri -e http.file_data > analysis/post_requests.txt
# this code will write all the post request detected in the capture.pcap file into a text file 
```

## Credential Discovery
- Filter:'http.request.method == 'POST'
 - IP: '44.228.249.3'
  - Credentials found:  
   -uname: 'Martin'  
   -Password: 'Martin123'  

## Suspicious IP Connections
- '44.228.249.3' - flagged by VirusTotal as malicious
- '5.161.68.219' - IP is hosted in EU and is not a common CDN
- Recommendation: Block the IP using firewalls(Inbound and Outbound traffic)

## Advice
- POST requests should be encrypted
- Enforce HTTPS on all endpoints  
- Monitor all inbound and outbound traffic  

## Identify Suspicious IP:  
Cross-reference IPs using the below websites:  
-VirusTotal  
-IPinfo.io  
