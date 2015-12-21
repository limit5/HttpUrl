#ifndef __HTTP_URL_H__
#define __HTTP_URL_H__

#include <iostream>
#include <stdlib.h>
#include <pcap.h>
#include <string>
#include <vector>
#include <sstream>
#include <map>

//#pragma comment(lib, "wpcap.lib")
//#pragma warning(disable: 4996)


#include "HttpPacket.h"

#define MAX_PACKET_QUEUE 2048
#define MAX_DEVICE_COUNT 128

class CHttpUrl
{
public:
	CHttpUrl();
	~CHttpUrl();
	std::vector<std::pair<std::string, std::string>> GetAllowedDevices();
	int SetListenDevice(int num);
	int SetListenPort(int port);
	int Open();
	int Close();
	CHttpPacket GetPacket(int *status);
private:
	CHttpPacket* m_pPacketQueue;
	CHttpPacket m_currentPacket;
	pcap_if_t* m_pAllowedDevices;
	pcap_if_t* m_device;
	pcap_t* fp;
	std::vector<std::pair<std::string, std::string>> m_devices;

	char m_errorBuffer[PCAP_ERRBUF_SIZE];
	int m_listenDeviceNumber;
	int m_allowedDeviceCount;
};

#endif