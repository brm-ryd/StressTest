#include "tcpip.h"

void IpTcpExpert :: calcAndSet(const vector<AutoCalcValue>& values, const Fields& fields, u_char* packet, UInt pacSize) {

   this->fields = &fields;

   for (int i = 0; i < namesOfValues.size(); i++) {
      for (int j = 0; j < values.size(); j++) {

         if (namesOfValues[i] == values[j].getName())
         {
            try
            {
            switch (i) {

               case ACV_IPLEN:

                  setIPLen(packet, pacSize);
                  break;

               case ACV_TCPCRC:

                  setTCPCrc(packet, pacSize);
                  break;

               case ACV_IPCRC:

                  setIPCrc(packet, pacSize);
                  break;

               case ACV_UDPCRC:

                  setUDPcrc(packet, pacSize);
                  break;

               case ACV_UDPLEN:

                  setUDPLen(packet, pacSize);
                  break;

               case ACV_ICMPCRC:

                  setICMPcrc(packet, pacSize);
                  break;

               case ACV_IPV6CRC:

                  setIPv6Len(packet, pacSize);
                  break;

               default: Test();
            }
            }
            ADD_TO_ERROR_DESCRIPTION3("calculating \"%s\" : you must specify any own value to avoid this warning, packet size = %u",values[j].getName().c_str(), pacSize);
            break;
         }
      }
   }
}


int IpTcpExpert :: findStartIPHeader() {

	const FieldInfo* fieldParameters;

	try
	{

		if (!(fieldParameters = fields -> getField(MessageString("ip.ver"))))
			throw new Exception("field 'ip.ver' must be defined");
	}

	ADD_TO_ERROR_DESCRIPTION("trying to find the beginning of IP header");

	return fieldParameters -> getPos();
}


void IpTcpExpert :: setIPLen(u_char* contentOfPacket, int sizePacBuf) {

	int beginningIPHeader = findStartIPHeader();

	ip_header* iph;

	if (beginningIPHeader + 20 > sizePacBuf)
		throw new Exception("the packet is too small to contain the full ip header");

	iph = (ip_header*) (contentOfPacket + beginningIPHeader);

	iph -> length = htons((u_short)(sizePacBuf - beginningIPHeader));
}

void IpTcpExpert :: setIPCrc(u_char* contentOfPacket, int sizePacBuf) {

	int beginningIPHeader = findStartIPHeader();
	ip_header* iph;

	if (beginningIPHeader + 20 > sizePacBuf)
		throw new Exception("the packet is too small to contain the full ip header");

	iph = (ip_header*) (contentOfPacket + beginningIPHeader);

	unsigned int iph_len = (u_char)((iph -> version & 0xf) * 4);

	if (beginningIPHeader + iph_len > sizePacBuf)
		throw new Exception("the packet is too small to contain the ip header (length of ip header is considered)");

	iph -> crc = 0;
	iph -> crc = ((rs_crc((u_short*)iph, iph_len)));
}


int IpTcpExpert :: findStartOfTcpHeader() {

	const FieldInfo* field;

	try
	{
		if (!(field = fields -> getField("srcport")))
			throw new Exception("field 'srcport' must be defined");
	}

	ADD_TO_ERROR_DESCRIPTION("trying to find the beginning of TCP header");

	return field -> getPos();
}


void IpTcpExpert :: checkCorrectionOfIPHeader(const u_char* contentOfPacket, int sizePacBuf, ip_header** iph) {

	int beginningIPHeader = findStartIPHeader();

	// works with ip header

	if (beginningIPHeader + 20 > sizePacBuf)
		throw new Exception("the packet is too small to contain the full ip header");

	*iph = (ip_header*) (contentOfPacket + beginningIPHeader);

	// gets the length of header from packet's content

	unsigned int iph_len = (u_char)(((*iph) -> version & 0xf) * 4);

	if (beginningIPHeader + iph_len > sizePacBuf)
		throw new Exception("the packet is too small to contain the full ip header (length of ip header is considered)");

	if (htons((*iph) -> length) + beginningIPHeader > sizePacBuf) {

		throw new Exception("the packet is too small to contain the full ip datagram (may be the length of datagram is incorrect)");
	}

	if (htons((*iph) -> length) - iph_len <= 0) {

		throw new Exception("incorrect lengths specified in IP header");
	}
}


void IpTcpExpert :: checkCorrectionOfIPv6Header(const u_char* contentOfPacket, int sizePacBuf, ipv6_header** iph) {

	const FieldInfo* fieldParameters;

	if (!(fieldParameters = fields -> getField("ip6.ver")))
			throw new Exception("field 'ip6.ver' must be defined");

	int beginningIPv6Header = fieldParameters -> getPos();

	if (beginningIPv6Header + sizeof(ipv6_header) > sizePacBuf)
		throw new Exception("the packet is too small to contain the minimal IPv6 header");

	*iph = (ipv6_header*) (contentOfPacket + beginningIPv6Header);

	//if (htons((*iph) -> length) + beginningIPv6Header + sizeof(ipv6_header) > sizePacBuf) {

	//	throw new Exception("the packet is too small to contain the full ipv6 datagram (may be the length of datagram is incorrect)");
	//}

	/*if (htons((*iph) -> length) > sizeof(ipv6_header)) {

		throw new Exception("too small length of datagram in IPv6 header (less then the size of header)");
	}*/
}

bool IpTcpExpert :: checkIPorIPv6Headers(const u_char* contentOfPacket, int sizePacBuf, ip_header** iph, ipv6_header** ipv6h) {

	bool ipv6IsUsed = true;

	try
	{
		checkCorrectionOfIPv6Header(contentOfPacket, sizePacBuf, ipv6h);
	}
	catch (Exception* e) {

		delete e;
		ipv6IsUsed = false;
	}

	if (!ipv6IsUsed) checkCorrectionOfIPHeader(contentOfPacket, sizePacBuf, iph);

	return ipv6IsUsed;
}


void IpTcpExpert :: checkPacketModificationForTCPcrc(UInt startPositionModifiedBlock, const UChar* contentOfPacket, const UChar* valueToWrite, UInt sizeModifiedBlock, UInt sizePacBuf) {

	int beginningTCPHeader = findStartOfTcpHeader();
	int beginningIPHeader = findStartIPHeader();

	tcp_header* tcph;
	ip_header* iph;
	ipv6_header* ipv6h;

	if (startPositionModifiedBlock % 2 != 0) return;
	if (sizeModifiedBlock % 2 != 0) return;

	// working with ip or ipv6

	bool ipv6IsUsed = checkIPorIPv6Headers(contentOfPacket, sizePacBuf, &iph, &ipv6h);
	//ipv6IsUsed = false;

	// works with TCP header

	if (beginningTCPHeader + sizeof(tcp_header) > sizePacBuf)
		throw new Exception("the packet is too small to contain the full tcp header");

	tcph = (tcp_header*) (contentOfPacket + beginningTCPHeader);

	if (!ipv6IsUsed) {

		unsigned int iph_len = (u_char)((iph -> version & 0xf) * 4);

		UInt crc = (~(tcph -> crc));
		UShort* p;

		for (p = (UShort*)(contentOfPacket + startPositionModifiedBlock);
			  p < (UShort*)(contentOfPacket + startPositionModifiedBlock + sizeModifiedBlock);
			  p++) {

			crc -= *p;
			if (crc > 0x0fffffff) crc--;
			crc &= 0xffff;

			crc += *((UShort*)valueToWrite + (p - (UShort*)(contentOfPacket+startPositionModifiedBlock)));
			crc += (crc >> 16);
			crc &= 0xffff;
		}

		tcph -> crc = ~((UShort)crc);

		//tcph -> crc = rs_pseudo_crc ((u_char*)tcph, htons(iph -> length) - iph_len,
		//	iph -> src_addr, iph -> dst_addr, (u_short)(htons(iph -> length) - iph_len), iph -> proto);
	}
	else {

		//tcph -> crc = 0;
		//tcph -> crc = rs_pseudo_crc_ipv6 ((u_char*)tcph, sizePacBuf - beginningTCPHeader,
		//	ipv6h -> src_addr, ipv6h -> dst_addr, (u_short)(sizePacBuf - beginningTCPHeader), ipv6h -> next);
	}
}


void IpTcpExpert :: setTCPCrc(u_char* contentOfPacket, int sizePacBuf) {

	int beginningTCPHeader = findStartOfTcpHeader();
	int beginningIPHeader = findStartIPHeader();

	tcp_header* tcph;
	ip_header* iph;
	ipv6_header* ipv6h;

	// working with ip or ipv6

	bool ipv6IsUsed = checkIPorIPv6Headers(contentOfPacket, sizePacBuf, &iph, &ipv6h);
	//ipv6IsUsed = false;

	// works with TCP header

	if (beginningTCPHeader + sizeof(tcp_header) > sizePacBuf)
		throw new Exception("the packet is too small to contain the full tcp header");

	tcph = (tcp_header*) (contentOfPacket + beginningTCPHeader);

	if (!ipv6IsUsed) {

		unsigned int iph_len = (u_char)((iph -> version & 0xf) * 4);

		if (htons(iph -> length) < iph_len)
			throw new Exception("enable to count the TCP crc : the length of ip datagram is less than the size of ip header");

		tcph -> crc = 0;
		tcph -> crc = rs_pseudo_crc ((u_char*)tcph, htons(iph -> length) - iph_len,
			iph -> src_addr, iph -> dst_addr, (u_short)(htons(iph -> length) - iph_len), iph -> proto);
	}
	else {

		tcph -> crc = 0;
		tcph -> crc = rs_pseudo_crc_ipv6 ((u_char*)tcph, sizePacBuf - beginningTCPHeader,
			ipv6h -> src_addr, ipv6h -> dst_addr, (u_short)(sizePacBuf - beginningTCPHeader), ipv6h -> next);
	}
}

void IpTcpExpert :: setUDPcrc(u_char* contentOfPacket, int sizePacBuf) {

	ip_header* iph;
	ipv6_header* ipv6h;

	bool ipv6IsUsed = checkIPorIPv6Headers(contentOfPacket, sizePacBuf, &iph, &ipv6h);


	// works with UDP header

	// finds the 'srcport' field

	const FieldInfo* fieldParameters;
	if (!(fieldParameters = fields -> getField("srcport"))) {

		throw new Exception("field with name 'srcport' must be define to calculate the UDP crc");
	}

	int beginningUDPHeader = fieldParameters -> getPos();

	if (beginningUDPHeader + sizeof(udp_header) > sizePacBuf) {

		throw new Exception("the size of packet is too small to contain UDP header");
	}

	udp_header* udph = (udp_header*)(contentOfPacket + beginningUDPHeader);

	if (!ipv6IsUsed) {

		unsigned int iph_len = (u_char)((iph -> version & 0xf) * 4);

		udph -> crc = 0;
		udph -> crc = rs_pseudo_crc( (u_char*) udph, htons(iph -> length) - iph_len,
		iph -> src_addr, iph -> dst_addr, (u_short)(htons(iph -> length) - iph_len), iph -> proto);
	}
	else {

		udph -> crc = 0;
		udph -> crc = rs_pseudo_crc_ipv6 ((u_char*)udph, sizePacBuf - beginningUDPHeader,
			ipv6h -> src_addr, ipv6h -> dst_addr, (u_short)(sizePacBuf - beginningUDPHeader), ipv6h -> next);
	}
}


void IpTcpExpert :: setUDPLen(u_char* contentOfPacket, int sizePacBuf) {

	// finds the 'srcport' field

	const FieldInfo* fieldParameters;
	if (!(fieldParameters = fields -> getField("srcport"))) {

		throw new Exception("field with name 'srcport' must be defined to calculate the UDP length");
	}

	int beginningUDPHeader = fieldParameters -> getPos();

	if (beginningUDPHeader + sizeof(udp_header) > sizePacBuf) {

		throw new Exception("the size of packet is too small to contain UDP header");
	}

	udp_header* udph = (udp_header*)(contentOfPacket + beginningUDPHeader);

	udph -> length = htons(sizePacBuf - beginningUDPHeader);
}



void IpTcpExpert :: setICMPcrc(u_char* contentOfPacket, int sizePacBuf) {

	ip_header* iph;
	checkCorrectionOfIPHeader(contentOfPacket, sizePacBuf, &iph);
	unsigned int iph_len = (u_char)((iph -> version & 0xf) * 4);

	const FieldInfo* fieldParameters;
	if (!(fieldParameters = fields -> getField("icmp.type"))) {

		throw new Exception("field with name 'icmp.type' must be defined to calculate the ICMP checksum");
	}

	int beginningICMPeader = fieldParameters -> getPos();

	if (beginningICMPeader + sizeof(icmp_header) > sizePacBuf) {

		throw new Exception("the size of packet is too small to contain ICMP header");
	}

	icmp_header* icmph = (icmp_header*) (contentOfPacket + beginningICMPeader);

	icmph -> checksum = 0;
   icmph -> checksum = ((rs_crc((u_short*)icmph, htons(iph -> length)
            - iph_len)));
}


void IpTcpExpert :: setIPv6Len(u_char* contentOfPacket, int sizePacBuf) {

	ipv6_header* ipv6h;

	checkCorrectionOfIPv6Header(contentOfPacket, sizePacBuf, &ipv6h);

	ipv6h -> length = htons(sizePacBuf - sizeof(ipv6_header) - ((u_char*)ipv6h - contentOfPacket));
}


u_short rs_crc (u_short * buffer, int length)
{
   unsigned long crc = 0;

   while (length > 1)
   {
      crc += *buffer++;
      length -= sizeof (unsigned short);
   }

   if (length) crc += *(unsigned char*) buffer;

   crc = (crc >> 16) + (crc & 0xffff);
   crc += (crc >> 16);

   return (unsigned short)(~crc);
}

unsigned short rs_pseudo_crc (u_char * data, int data_length, unsigned int src_addr,
   unsigned int dst_addr, u_short packet_length, unsigned char proto)
{
   char * buffer;
   unsigned int full_length;
   unsigned char header_length;
   struct pseudo_header ph;
   unsigned short p_crc;

   ph.src_addr = src_addr;
   ph.dst_addr = dst_addr;
   ph.zero = 0;
   ph.proto = proto;
   ph.length = htons(packet_length);

   header_length = sizeof (struct pseudo_header);
   full_length = header_length + data_length;

   buffer =(char *) calloc (full_length, sizeof (char));

   memcpy (buffer, &ph, header_length);
   memcpy (buffer + header_length, data, data_length);

   p_crc = rs_crc ((unsigned short*) buffer, full_length);
   //p_crc = htons(checksum ((unsigned char*) buffer, full_length));

   free (buffer);
	return p_crc;
}

unsigned short rs_pseudo_crc_ipv6 (u_char * data, int data_length, u_char src_addr[16],
   u_char dst_addr[16], u_int packet_length, u_char next)
{
   char * buffer;
   unsigned int full_length;
   unsigned char header_length;
   struct pseudo_header_ipv6 ph;
   unsigned short p_crc;

   memcpy(ph.src_addr, src_addr, 16);
   memcpy(ph.dst_addr, dst_addr, 16);
	memset(&ph.zero, 0, sizeof(ph.zero));
   ph.next = next;
   ph.length = htonl(packet_length);

   header_length = sizeof (struct pseudo_header_ipv6);
   full_length = header_length + data_length;

   buffer =(char *) calloc (full_length, sizeof (char));

   memcpy (buffer, &ph, header_length);
   memcpy (buffer + header_length, data, data_length);

   p_crc = rs_crc ((unsigned short*) buffer, full_length);

   free (buffer);
	return p_crc;
}
