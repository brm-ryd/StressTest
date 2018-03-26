#ifndef _FIELDVARIABLEVALUES_H_
#define _FIELDVARIABLEVALUES_H_

#include "stresstest.h"
#include "fields.h"
#include "stresstest_functs.h"

class FieldVariableValue {

   /** parameters and value of variable */
//	CommonField* fieldObject;
   FieldValue value;
   FieldInfo* fieldInfo;

	/** name of variable */
	MString name;

	/** true - the variable must be automatically set corresponding to received packet */
	bool autoSet;

public:

   FieldVariableValue(const MString& name, const FieldValue& value, const FieldInfo* givenFieldInfo, boolean autoSet) : name(name), value(value), autoSet(autoSet) {
      fieldInfo = 0;
      if (givenFieldInfo != 0) fieldInfo = new FieldInfo(*givenFieldInfo);
   }

   FieldVariableValue(const FieldVariableValue& v) : name(v.getName()), value(v.getValueConst()), autoSet(v.isAutoSet()) {
      fieldInfo = 0;
      if (v.getFieldInfo() != 0) fieldInfo = new FieldInfo(*v.getFieldInfo());
   }


   const FieldInfo* getFieldInfo() const {
      return fieldInfo;
   }

   // TODO[at] supply size of field info during reading
   FieldValue& getValue() {
      return value;
   }

   const FieldValue& getValueConst() const {
      return value;
   }

   bool isAutoSet() const {
      return autoSet;
   }

   const MString& getName() const {
      return name;
   }
};

/**

	Class FieldVariableValues.

	Represents the array of variables.
	Each variable has the associated field and stores some value
	which type is defined by the type of field.

	Variable may be automatically set the each time after receiving packet,
	or may be used independently.

	Variable may be used as simple number (when the type of field is number).

	There are some operations exist for work with variables (increasing, reducing, multiplying, dividing).
*/


class FieldVariableValues
{

protected:

	MyMutex sharedAccessMutex;
	vector<FieldVariableValue> values;

public:

	/** adds new variable */
	void addValue(const FieldVariableValue& givenValue) {

		sharedAccessMutex.wait();

      FieldVariableValue v(givenValue);

		UInt numFound = (UInt)-1;
		if (getVariable_const(givenValue.getName(), false, &numFound)) {
         values.erase(values.begin() + numFound);
		}

      values.push_back(v);

		sharedAccessMutex.release();
	}

	/**
	 returns info about the variable,
	 return the NULL (or throws an exception) if variable with such name not found
	 returns not copy but the reference to original object
	*/
	const FieldVariableValue* getVariable_const(const MString& name, bool isGenerateException = true, UInt* numVar = Null) const {

		const FieldVariableValue* res = Null;

		sharedAccessMutex.wait();

		for (int i = 0; i < values.size(); i++) {

			if (!strCaseCompare(!name, !values[i].getName())) {

				if (numVar) *numVar = i;
				res = &(values[i]);
				break;
			}
		}

		if (!res && isGenerateException)
			throw new Exception("variable with name '%s' not found", !name);

		sharedAccessMutex.release();

		return res;
	}

	/**
	 see 'getVariable_const',
	 returns the pointer which allows the modification of variable
	*/
	FieldVariableValue* getVariable(const char* name, bool isGenerateException,
		UInt* numVar = Null // index of found variable in total array
		) {

		return const_cast<FieldVariableValue*>(getVariable_const(name, isGenerateException, numVar));
	}

	/** all autoset variable are updating their values from given packet's buffer */
	void setAllVariablesByPacket(u_char* buf, UInt sizeBuf) {

		sharedAccessMutex.wait();

		ADDTOLOG3("FieldVariableValues :: setAllVariablesByPacket -- sizeBuf = %i, buf =\n%s",
         sizeBuf, getStringOfDump(buf, sizeBuf))

		for (int i = 0; i < values.size(); i++) {

			if (!values[i].isAutoSet()) continue;
         CommonField field(*values[i].getFieldInfo());
//         field.setValue(values[i].getValueConst());
			if (field.setByPacket(buf, sizeBuf) == ICR_OK) {
            values[i].getValue() = field.getValue();
				ADDTOLOG2("FieldVariableValues : setAllVariablesByPacket -- successfull for variable %s", values[i].getName().c_str());
			}
		}

		sharedAccessMutex.release();
	}

	/** clears variables set */
	void clear() {
      values.clear();
	}
};

#endif //_FIELDVARIABLEVALUES_H_
