#include "stdafx.h"
#include "HttpPacket.h"

CHttpPacket::CHttpPacket()
{
	this->m_listenPort = 80;
}

CHttpPacket::~CHttpPacket()
{
}

int CHttpPacket::SetPacket(pcap_pkthdr* pHeader, const unsigned char* pData)
{

	std::string s;

	char* pMessage;
	pMessage = (char*)malloc(sizeof(char) * HTTP_HEADER_SIZE);


	memset(pMessage, 0, sizeof(char) * HTTP_HEADER_SIZE);
	sprintf(pMessage, "%02x:%02x:%02x:%02x:%02x:%02x", pData[0], pData[1], pData[2], pData[3], pData[4], pData[5]);
	this->m_destinationMacAddress = pMessage;

	memset(pMessage, 0, sizeof(char) * HTTP_HEADER_SIZE);
	sprintf(pMessage, "%02x:%02x:%02x:%02x:%02x:%02x", pData[6], pData[7], pData[8], pData[9], pData[10], pData[11]);
	this->m_sourceMacAddress = pMessage;

	memset(pMessage, 0, sizeof(char) * HTTP_HEADER_SIZE);
	this->m_payload = (int)((short)(((unsigned char)pData[16]) << 8 | ((unsigned char)pData[17])));
	this->m_dataLength = (this->m_payload > 40 ? this->m_payload - 40 : 0);

	memset(pMessage, 0, sizeof(char) * HTTP_HEADER_SIZE);
	sprintf(pMessage, "%d.%d.%d.%d", pData[26], pData[27], pData[28], pData[29]);
	this->m_sourceIp = pMessage;

	memset(pMessage, 0, sizeof(char) * HTTP_HEADER_SIZE);
	sprintf(pMessage, "%d.%d.%d.%d", pData[30], pData[31], pData[32], pData[33]);
	this->m_destinationIp = pMessage;

	memset(pMessage, 0, sizeof(char) * HTTP_HEADER_SIZE);
	this->m_sourcePort = (int)((short)(((unsigned char)pData[34]) << 8 | ((unsigned char)pData[35])));
	//std::cout << this->m_sourcePort << std::endl;

	memset(pMessage, 0, sizeof(char) * HTTP_HEADER_SIZE);
	this->m_destinationPort = (int)((short)(((unsigned char)pData[36]) << 8 | ((unsigned char)pData[37])));
	//std::cout << this->m_destinationPort << std::endl;

	char* pSegmentData;
	char* pTemp;
	pSegmentData = (char*)malloc(sizeof(char) * this->m_dataLength);
	pTemp = (char*)malloc(sizeof(char) * this->m_dataLength + 1);
	memset(pSegmentData, 0, sizeof(char) * this->m_dataLength);
	memset(pTemp, 0, sizeof(char) * this->m_dataLength);
	memcpy(pSegmentData, &pData[54], sizeof(char) * this->m_dataLength);

	if (this->m_destinationPort == this->m_listenPort || this->m_sourcePort == this->m_listenPort)
	{
		for (int i = 0; i < this->m_dataLength; i++)
		{
			sprintf(&pTemp[i], "%c", pSegmentData[i]);
		}
		this->m_data = std::string(pTemp);
		//std::cout << this->m_data << std::endl;
	}




	if (pMessage)
	{
		free(pMessage);
	}

	if (pSegmentData)
	{
		free(pSegmentData);
	}

	if (pTemp)
	{
		free(pTemp);
	}
	//std::cout << "set packet end" << std::endl << std::endl;

	return 0;
}

int CHttpPacket::SetListenPort(int port)
{
	this->m_listenPort = port;
	return 0;
}

std::string CHttpPacket::GetDestinationMacAddress()
{
	return this->m_destinationMacAddress;
}

std::string CHttpPacket::GetSourceMacAddress()
{
	return this->m_sourceMacAddress;
}

std::string CHttpPacket::GetProtocolType()
{
	return this->m_protocolType;
}

std::string CHttpPacket::GetDestinationIp()
{
	return this->m_destinationIp;
}

std::string CHttpPacket::GetSourceIp()
{
	return this->m_sourceIp;
}

int CHttpPacket::GetSourcePort()
{
	return this->m_sourcePort;
}

int CHttpPacket::GetDestinationPort()
{
	return this->m_destinationPort;
}

std::string CHttpPacket::GetHttpUrl()
{
	std::string tmp = this->m_data;

	int posStart;
	int posEnd;
	posStart = tmp.find("GET");
	posEnd = tmp.find("\r\n");
	if (posEnd < posStart || posStart < 0 || posEnd < 0 || posStart == std::string::npos || posEnd == std::string::npos)
	{
		this->m_httpUrl = "";
	}
	else
	{
		this->m_httpUrl = tmp.substr(posStart, posEnd);
	}
	

	return this->m_httpUrl;
}

int CHttpPacket::GetDataLength()
{
	return this->m_dataLength;
}


