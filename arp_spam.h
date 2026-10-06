#pragma once

#define WIN32_LEAN_AND_MEAN
#define SPOOFING_MAC "\xBE\xEF\xDE\xAD\xBE\xEF"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>

#include <windows.h>
#include <ws2tcpip.h>
#include <winsock2.h>
#include <iphlpapi.h>

#include <pcap/pcap.h>

#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")

struct node
{
	char ip[4];
	char mac[6];

	node() {}
};
struct arp_packet
{
	char eth_dst[6];
	char eth_src[6];
	char eth_type[2];
	char arp_hw_type[2];
	char arp_proto_type[2];
	char arp_hw_size;
	char arp_proto_size;
	char arp_opcode[2];
	char arp_src[6];
	char sender_ip[4];
	char arp_dst[6];
	char dst_ip[4];

	arp_packet() : arp_proto_size(0x04), arp_hw_size(0x06)
	{
		eth_type[0] = 0x08; eth_type[1] = 0x06;

		arp_proto_type[0] = 0x08; arp_proto_type[1] = 0x00;
		arp_hw_type   [0] = 0x00; arp_hw_type   [1] = 0x01;
	}
};

sockaddr_in       g_gateway_hints;
std::vector<node> g_nodes;

char              g_errbuf[PCAP_ERRBUF_SIZE];

std::atomic<bool> g_stop_asked;
std::mutex        g_nodes_mutex;

void        arp_scan_start(pcap_t* device, const char* device_name, PIP_ADAPTER_ADDRESSES adapter, const std::string& physical_address_string);

std::string retrieve_adapter_name(const std::string& pcap_adapter_name);
std::string raw_mac_bytes_to_string(const char* raw_bytes);

void        thr_dhcp(pcap_t* device);
void        thr_send_arp_packets(pcap_t* device, const char* device_name, PIP_ADAPTER_ADDRESSES adapter);
void        thr_receive_arp_packets(pcap_t* curr_device, const std::string* physical_address_string);

void        h_arpAdd(u_char* user, const struct pcap_pkthdr* pkt_header, const u_char* pkt_data);
void        h_dhcpAdd(u_char* user, const struct pcap_pkthdr* pkt_header, const u_char* pkt_data);
void        restore_nodes_arp(pcap_t* device, char* adapter_physical_address, char* gateway_physical_address);

BOOL WINAPI console_ctrl_handler(DWORD dwCtrlType);