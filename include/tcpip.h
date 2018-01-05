#ifndef TCPIP_H
#define	TCPIP_H

#include "protocolsExpert.h"

struct eth_header
{
	u_char dst[6];
	u_char src[6];
	unsigned short proto;
};

struct ip_header
{
 unsigned char		version;
 unsigned char		tos;
 unsigned short	length;
 unsigned short	id;
 unsigned short	flags;
 unsigned char		ttl;
 unsigned char		proto;
 unsigned short	crc;
 unsigned int		src_addr;
 unsigned int		dst_addr;
};

/** TCP packet header. */
struct tcp_header
{
 unsigned short	src_port;
 unsigned short	dst_port;
 unsigned int		seq_n;
 unsigned int		ack_n;
 unsigned char		offset;
 unsigned char		flags;
 unsigned short	win;
 unsigned short	crc;
 unsigned short	urg_ptr;
};

/** UDP packet header. */
struct udp_header
{
 unsigned short	src_port;
 unsigned short	dst_port;
 unsigned short	length;
 unsigned short	crc;
};

struct pseudo_header
{
 unsigned int		src_addr;
 unsigned int		dst_addr;
 unsigned char		zero;
 unsigned char		proto;
 unsigned short	length;
};

struct pseudo_header_ipv6
{
 u_char		src_addr[16];
 u_char		dst_addr[16];
 unsigned int		length;
 unsigned char		zero[3];
 unsigned char		next;
};

struct icmp_header {

   u_char type;
   u_char code;
   u_short checksum;
   u_short id;
   u_short seq;
};

struct ipv6_header {

	u_char version_class;
	u_char class_label;
	u_char label[2];
	u_short length;
	u_char next;
	u_char hop;
	u_char src_addr[16];
	u_char dst_addr[16];

};

// ATTENTION: must correspond the order in 'IpTcpExpert :: getValues()'
// NOTE: values will be calculated if the following order (it may be important)
enum keyWordsAutoCalcValues
{
	ACV_IPLEN,
	ACV_IPCRC,
	ACV_IPV6CRC,
	ACV_TCPCRC,
	ACV_UDPLEN,
	ACV_UDPCRC,
	ACV_ICMPCRC
};

class IpTcpExpert : public ProtocolsExpert
{
   vector<string> namesOfValues;
   const Fields* fields;

public:

   IpTcpExpert() {
      namesOfValues.push_back(string("IPlen"));
      namesOfValues.push_back(string("IPcrc"));
      namesOfValues.push_back(string("IPv6len"));
      namesOfValues.push_back(string("TCPcrc"));
      namesOfValues.push_back(string("UDPlen"));
      namesOfValues.push_back(string("UDPcrc"));
      namesOfValues.push_back(string("ICMPcrc"));
      // ATTENTION: the order must correspond 'keyWordsAutoCalcValues'
   }

protected:

   // method for work with IP header

	/** returns the position of beginning of IP header or throws Exception */
	int findStartIPHeader();
	void checkCorrectionOfIPHeader(const u_char* contentOfPacket, int sizePacBuf, ip_header** iph);
	void setIPLen(u_char* contentOfPacket, int sizePacBuf);
	void setIPCrc(u_char* contentOfPacket, int sizePacBuf);

	/** methods for work with TCP header */

	int findStartOfTcpHeader();
	void setTCPCrc(u_char* contentOfPacket, int sizePacBuf);

	/** methods for work with UDP header */

	void setUDPcrc(u_char* contentOfPacket, int sizePacBuf);
	void setUDPLen(u_char* contentOfPacket, int sizePacBuf);

	/** methods for work with ICMP */

	void setICMPcrc(u_char* contentOfPacket, int sizePacBuf);

	/** methods for work with IPv6 header */

	void checkCorrectionOfIPv6Header(const u_char* contentOfPacket, int sizePacBuf, ipv6_header** iph);
	void setIPv6Len(u_char* contentOfPacket, int sizePacBuf);

	bool checkIPorIPv6Headers(const u_char* contentOfPacket, int sizePacBuf, ip_header** iph, ipv6_header** ipv6h);

   void checkPacketModificationForTCPcrc(UInt startPositionModifiedBlock, const UChar* contentOfPacket, const UChar* valueToWrite, UInt sizeModifiedBlock, UInt sizePacBuf);

   const vector<string>& getValues() { return namesOfValues; }
   void calcAndSet(const vector<AutoCalcValue>& values, const Fields& fields, u_char* packet, UInt pacSize);
};

/** basic calculation algorithm for ip, tcp. Special sun of 16-bit words from buffer. */
u_short rs_crc(u_short * buffer, int length);

/** calc checksum of tcp and udp, encapsulated in ip header */
unsigned short rs_pseudo_crc(u_char * data, int data_length, unsigned int src_addr,
   unsigned int dst_addr, u_short packet_length, unsigned char proto);

/** calc checksum of tcp and udp, encapsulated in ipv6 header */
unsigned short rs_pseudo_crc_ipv6(u_char * data, int data_length, u_char src_addr[16],
   u_char dst_addr[16], u_int packet_length, u_char next);


#endif	/* TCPIP_H */

