#include "stdafx.h"

#include "HttpUrl.h"
#include <pcap.h>
#include <string>
#include <iostream>

#pragma comment(lib, "wpcap.lib")


int main(int argc, char** argv) 
{
	CHttpUrl httpUrl;
	CHttpPacket httpPacket;
	std::vector<std::pair<std::string, std::string>> devices;
	
	devices = httpUrl.GetAllowedDevices();

	for (std::vector<std::pair<std::string, std::string>>::iterator itr = devices.begin(); itr != devices.end(); itr++)
	{
		std::cout << itr->first << " " << itr->second << std::endl;
	}
	std::cout << std::endl;

	int nDevice;
	int nPort;
	std::cout << "Device: ";
	std::cin >> nDevice;
	std::cout << "Port: ";
	std::cin >> nPort;

	httpUrl.SetListenDevice(nDevice);
	httpUrl.SetListenPort(nPort);
	httpUrl.Open();

	while (true)
	{
		int status;
		httpPacket = httpUrl.GetPacket(&status);
		std::string url = httpPacket.GetHttpUrl();
		if (url != "") std::cout << url << std::endl;
	}

	return 0;
}

