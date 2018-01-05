#pragma once
#ifndef _PROTOCOLSEXPERT_H_
#define _PROTOCOLSEXPERT_H_

#include "stresstest.h"

#include "mbuffer.h"
#include "fields.h"

/**
 * Calculated value with associated status: activity, field for which it's been assigned etc.
 * It's active if it has been specified as value for a field in the description of a packet in script 
 * (then getField() method returns this field).
 * Expert index is internally used by AutocalcManager class.
 */
class AutoCalcValue {

	MString name;
   int expertIndex;
   const FieldInfo* field;

public:

   const string& getName() const { return name; }
   
   boolean isActive() const { return (field != Null ); }
   int getExpertIndex() const {
      return expertIndex;
   }
   
   const FieldInfo& getField() const { userCheck(field); return *field; }
   void activate(const FieldInfo& field) {
      this->field = new FieldInfo(field);
   }
   void disactivate() {
      if (field) { delete field; field=0; }
   }

   AutoCalcValue(const string& name, int expertIndex) {
      this->name = name;
      this->expertIndex=expertIndex;
      field = 0;
   }

   AutoCalcValue(const AutoCalcValue& v) {
      name = v.name;
      expertIndex=v.expertIndex;
      if (v.field)
         field = new FieldInfo(*v.field);
      else
         field=0;
   }

   ~AutoCalcValue() {
      disactivate();
   }
};

/**
 * Base class for classes that are responsible for automatic calculation of some values.
 * @see IpTcpExpert
 * @return
 */
class ProtocolsExpert
{
public:
   /**
    * Returns names of values that are calculated by this expert.
    * If this expert is registered then each of its values may be specified for any field.
    * @return
    */
   virtual const vector<string>& getValues() = 0;
   /**
    * Calculates values from the given set and writes them into given packet's buffer.
    * Contract: each value in given set must be among those returned by getValues.
    * During calculation the method may use the content of given packet and the information about registered fields.
    * @param values set of values that need to be calculated and written
    * @param fields actual fields defined in script (may be used by calculation algorithm)
    * @param packet buffer of packet 
    * @param pacSize size of packet's buffer
    */
   virtual void calcAndSet(const vector<AutoCalcValue>& values, const Fields& fields, u_char* packet, UInt pacSize) = 0;

};

/**

	Class AutocalcManager

   Calculates values of some fields.
   Works with the set of predefined fields whose values may be automatically calculated.
   Method computeAndSetValues calculates and writes values for all active fields.
   Method setValueAsActive is used to activate a field.
   Method checkPacketModification disactivates field if its region overlaps the given modified region.
	
*/
class AutocalcManager
{

	vector<AutoCalcValue> values;
   vector<ProtocolsExpert*> protocolExperts;

public:

	const Fields* fields;

private:

   void fillValues();

public:
	
   AutocalcManager() {      		
      this -> fields = 0;
   }
	~AutocalcManager() {};
	
	void setProtocolExperts(vector<ProtocolsExpert*> givenProtocolExperts) {
		protocolExperts.assign(givenProtocolExperts.begin(), givenProtocolExperts.end());
      fillValues();
	}

	void deleteRecord(int numberRecordToDelete) { Test(); }

	/** returns the value with given name, null otherwise */
	AutoCalcValue* searchValue(const char* name);

	/**
	 the value with given name will be marked as active, and will be calculated while call to 'computeAndSetValues',
	 if not such value then throws Exception
	*/
	void setValueAsActive(const char* name, const FieldInfo& field);

	/**
	void disactivateAllValues();

	 this method must be called when the content of packet is modified
	 if modified block and some value (among already active) overlap then this value will be marked as not active
	*/
	void checkPacketModification(int startPositionModifiedBlock, int sizeModifiedBlock);
	
	/** calculates all values and sets the calculated values in given buffer */
	void computeAndSetValues(u_char* contentOfPacket, int sizePacBuf);
};



#endif //_PROTOCOLSEXPERT_H_
