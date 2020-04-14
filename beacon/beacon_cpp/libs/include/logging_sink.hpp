#include <string>
#include <vector>

namespace fetch {

bool HasPendingLogs();
int PeekNextLogLevel(); // 0 - Debug, 1 - Info, 2 - Error
std::string PeekNextLogModule();
std::string PeekNextLogMessage();
void PopNextLog();

// for testing only
void SendTestLogMessage(std::string const &message);

} // namespace fetch
