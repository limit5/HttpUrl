#ifndef __HTTP_PACKET_H__
#define __HTTP_PACKET_H__


#include <iostream>
#include <string>
#include <sstream>
#include <pcap.h>

#pragma comment(lib, "wpcap.lib")
#pragma warning(disable: 4996)

#define MAX_HTTP_PACKET_SIZE 65536
#define HTTP_HEADER_SIZE 54

class CHttpPacket
{
public:
	CHttpPacket();
	~CHttpPacket();
	int SetPacket(struct pcap_pkthdr*, const unsigned char*);
	int SetListenPort(int port);
	std::string GetDestinationMacAddress();
	std::string GetSourceMacAddress();
	std::string GetProtocolType();
	std::string GetDestinationIp();
	std::string GetSourceIp();
	int GetSourcePort();
	int GetDestinationPort();
	std::string GetHttpUrl();
	int GetDataLength();
private:
	unsigned char* m_pHeader;
	unsigned char* m_pData;

	pcap_pkthdr* m_pPktHeader;
	const unsigned char* m_pPktData;
	int m_listenPort;

	std::string m_destinationMacAddress;
	std::string m_sourceMacAddress;
	std::string m_destinationIp;
	std::string m_sourceIp;
	std::string m_protocolType;
	std::string m_data;
	int m_sourcePort;
	int m_destinationPort;
	std::string m_httpUrl;
	int m_dataLength;
	int m_payload;
};

#endif