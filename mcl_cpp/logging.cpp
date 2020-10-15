#include "logging.hpp"
#include "logging_sink.hpp"

#include <mutex>
#include <deque>

namespace fetch {
namespace {

struct LogMessage
{
  int        level;
  std::string module;
  std::string text;
};

enum TendermintLogLevel
{
  TENDERMINT_DEBUG = 0,
  TENDERMINT_INFO = 1,
  TENDERMINT_ERROR = 2,
};

using LogMessageQueue = std::deque<LogMessage>;

std::mutex      lock_{};
LogMessageQueue log_queue_{};

int SquashLogLevel(LogLevel level)
{
  int output = TENDERMINT_ERROR;

  switch (level)
  {
  case LogLevel::TRACE:
    output = TENDERMINT_DEBUG;
    break;
  case LogLevel::DEBUG:
    output = TENDERMINT_DEBUG;
    break;
  case LogLevel::INFO:
    output = TENDERMINT_INFO;
    break;
  case LogLevel::WARNING:
    output = TENDERMINT_INFO;
    break;
  case LogLevel::ERROR:
    output = TENDERMINT_ERROR;
    break;
  case LogLevel::CRITICAL:
    output = TENDERMINT_ERROR;
    break;
  }

  return output;
}

} // anon. namespace

bool HasPendingLogs()
{
  std::lock_guard<std::mutex> guard{lock_};
  return !log_queue_.empty();
}

std::string PeekNextLogMessage()
{
  std::lock_guard<std::mutex> guard{lock_};

  if (!log_queue_.empty())
  {
    return log_queue_.front().text;
  }

  return {};
}

int PeekNextLogLevel()
{
  std::lock_guard<std::mutex> guard{lock_};

  if (!log_queue_.empty())
  {
    return log_queue_.front().level;
  }

  return -1;
}

std::string PeekNextLogModule()
{
  std::lock_guard<std::mutex> guard{lock_};

  if (!log_queue_.empty())
  {
    return log_queue_.front().module;
  }

  return {};
}

void PopNextLog()
{
  std::lock_guard<std::mutex> guard{lock_};

  if (!log_queue_.empty())
  {
    log_queue_.pop_front();
  }
}

void SendTestLogMessage(std::string const &message)
{
  Log(LogLevel::ERROR, "test", message);
}

void Log(LogLevel level, std::string name, std::string message)
{
  std::lock_guard<std::mutex> guard{lock_};
  log_queue_.emplace_back(LogMessage{SquashLogLevel(level), name, message});
}

} // namespace fetch
