# ARP Spam
Spamming fake ARP packets to disconnect nodes from the gateway.

A tool for sending ARP spam in a local network.  
Used for network security testing and ARP protocol research.

**This project is Windows-only.**

**Features:**  
- **DHCP listening** – monitors DHCP traffic in the network for adding new targets
- **ARP spoofing** – automatically adds targets for ARP spoofing using ARP scan method
  
# Install
Download ZIP file or use Git

 `$ git clone https://github.com/bassosos/arp_spam`
 
 - Download and install **Npcap** from [https://npcap.com/dist/npcap-1.80.exe](https://npcap.com/dist/npcap-1.80.exe)
 - Download **Npcap SDK** from [https://npcap.com/dist/npcap-sdk-1.13.zip](https://npcap.com/dist/npcap-sdk-1.13.zip)

Extract the SDK and configure **Visual Studio**: 
 - Add the `Include` folder from the SDK to **Include Directories** 
 - Add the `Lib` folder from the SDK to **Library Directories**

# Start
Open solution and compile in x64 debug/release mode
