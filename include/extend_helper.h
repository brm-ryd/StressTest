#ifndef EXTEND_HELPER_H
#define	EXTEND_HELPER_H
#include <vector>

class ValueType;
class ProtocolsExpert;
class CommandsProcessor;
class Device;

using std::vector;

/**
 * Returns list of objects that are in charged of something.
 * See the description of each class to know what its doing.
 *
 */
class ExtendHelper {
public:
	static vector<CommandsProcessor*>& getCommandProcessors();
	static vector<ProtocolsExpert*>& getProtocolsExperts();
	static vector<ValueType const*>& getValueTypes();
	static vector<Device*>& getNetworkDevices();
};

#endif	/* EXTEND_HELPER_H */
