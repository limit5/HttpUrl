#include "stdafx.h"
#include "HttpUrl.h"

CHttpUrl::CHttpUrl()
{
	unsigned int _i_device_count = 0;
	this->m_devices.clear();

	try
	{
		if (pcap_findalldevs(&this->m_pAllowedDevices, this->m_errorBuffer) == -1)
		{
			throw - 1;
		}
		
		for (this->m_device = this->m_pAllowedDevices; this->m_device; this->m_device = this->m_device->next)
		{
			//printf("%d. %s\n    ", ++_i_device_count, d->name);
			printf("%d. %s\n    ", ++_i_device_count, this->m_device->name);

			if (this->m_device->description)
				printf(" (%s)\n", this->m_device->description);
			else
				printf(" (No description available)\n");

			std::stringstream ss1, ss2;
			ss1 << this->m_device->name;
			if (this->m_device->description)
			{
				ss2 << this->m_device->description;
			}
			else
			{
				ss2 << "No description available";
			}
			this->m_devices.push_back(std::pair<std::string, std::string>(ss1.str(), ss2.str()));
			//_i_device_count++;
		}
		if (_i_device_count == 0)
		{
			printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
			throw - 2;
		}
	}
	catch (const std::exception& ex)
	{

	}
	catch (int error)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", this->m_errorBuffer);
	}
}

CHttpUrl::~CHttpUrl()
{
	pcap_close(this->fp);
	if (this->m_pAllowedDevices != 0)
	{
		pcap_freealldevs(this->m_pAllowedDevices);
	}
}

std::vector<std::pair<std::string, std::string>> CHttpUrl::GetAllowedDevices()
{
	return this->m_devices;
}

int CHttpUrl::SetListenDevice(int num)
{
	int _i_count;
	for (this->m_device = this->m_pAllowedDevices, _i_count = 0; _i_count < num - 1; this->m_device = this->m_device->next, _i_count++);

	return 0;
}

int CHttpUrl::SetListenPort(int port)
{
	this->m_currentPacket.SetListenPort(port);
	return 0;
}

int CHttpUrl::Open()
{
	/* Open the adapter */
	if ((this->fp = pcap_open_live(this->m_device->name,	
		65536,							
		1,								
		1000,							
		this->m_errorBuffer				
		)) == NULL)
	{
		fprintf(stderr, "\nError opening adapter\n");
		return -1;
	}

	return 0;
}

int CHttpUrl::Close()
{

	pcap_close(this->fp);
	pcap_freealldevs(this->m_pAllowedDevices);
	return 0;
}

CHttpPacket CHttpUrl::GetPacket(int* pStatus)
{
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;

	if ((*pStatus = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		if (*pStatus != 0)
		{
			this->m_currentPacket.SetPacket(header, pkt_data);
		}
	}

	return this->m_currentPacket;
}
