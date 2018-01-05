#include "stdafx.h"
#include "protocolsExpert.h"
#include "pacbuf.h"
#include "tcpip.h"

//const int sizeAutoCalcValueInitArray = 7;


// ATTENTION: must correspond the 'keyWordsAutoCalcValues'
// NOTE: values will be calculated if the following order (it may be important)
//AutoCalcValue autoCalcValueInitArray[sizeAutoCalcValueInitArray] =
//{
//	{ "IPlen",		2, 0, false },
//	{ "IPcrc",		2, 0, false },
//	{ "IPv6len",	2,	0, false },
//	{ "TCPcrc",		2, 0, false },
//	{ "UDPlen",		2, 0, false },
//	{ "UDPcrc",		2, 0, false },
//	{ "ICMPcrc",	2, 0, false }
//};

void AutocalcManager :: fillValues() {
   for (int i = 0; i < protocolExperts.size(); i++) {

      const vector<string>& names= protocolExperts[i]->getValues();
      for (int j = 0; j < names.size(); j++) {
         AutoCalcValue v(names[j], i);
         values.push_back(v);
      }
   }

//   for (int i = 0; i < sizeAutoCalcValueInitArray; i++)
//	{
//		values.push_back(autoCalcValueInitArray[i]);
//	}

}

AutoCalcValue* AutocalcManager :: searchValue(const char* name) {

	vector<AutoCalcValue>::iterator it = values.begin();
	while ( it != values.end())
	{
		if (!strCaseCompare(name, it -> getName().c_str()))
			return &*it;
		++it;
	}

	return 0;
}


void AutocalcManager :: setValueAsActive(const char* name, const FieldInfo& field) {

	AutoCalcValue* fv = searchValue(name);

	userCheck(fields);
   userCheck(fv);

   fv -> activate(field);
}


//void AutocalcManager :: disactivateAllValues() {
//
//	vector<AutoCalcValue>::iterator it = values.begin();
//
//	while ( it != values.end()) {
//		(it++) -> isActive = false;
//	}
//}

void AutocalcManager :: checkPacketModification(int startPositionModifiedBlock, int sizeModifiedBlock) {

	vector<AutoCalcValue>::iterator it = values.begin();

	while ( it != values.end()) {

		if (it -> isActive()) {

         userCheck(it -> getField().getSize().isDefined());
			if (!
					(
						startPositionModifiedBlock >= it -> getField().getPos() + it -> getField().getSize().num()
						||
						it -> getField().getPos() >= startPositionModifiedBlock + sizeModifiedBlock
					)
				) 
								
				it -> disactivate();
		}	

		++it;
	}
}


void AutocalcManager :: computeAndSetValues(u_char* contentOfPacket, int sizePacBuf) {

//	for (int i = 0; i < values.size(); i++)
//	{
//		if (values.at(i).isActive()) {
//
//			calcValue(i, contentOfPacket, sizePacBuf);
//		}
//	}

   for (int i = 0; i < protocolExperts.size(); i++) {
      vector<AutoCalcValue> val;
      for (int j = 0; j < values.size(); j++) {
         if (values[j].isActive() && values[j].getExpertIndex() == i)
            val.push_back(values[j]);
      }

      if (val.size())
         protocolExperts[i] -> calcAndSet(val, *fields, contentOfPacket, sizePacBuf);
   }
}


