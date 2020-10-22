
#include <string>
#include <sstream>

namespace fetch {
namespace detail {

template <typename T, typename... Args>
struct Unroll
{
  static void Apply(std::ostream &stream, T &&v, Args &&... args)
  {
    stream << std::forward<T>(v);
    Unroll<Args...>::Apply(stream, std::forward<Args>(args)...);
  }
};

template <typename T>
struct Unroll<T>
{
  static void Apply(std::ostream &stream, T &&v)
  {
    stream << std::forward<T>(v);
  }
};

/**
 * String formatter
 * @tparam Args
 * @param args
 * @return
 */
template <typename... Args>
std::string Format(Args &&... args)
{
  // unroll all the arguments and generate the formatted output
  std::ostringstream oss;
  Unroll<Args...>::Apply(oss, std::forward<Args>(args)...);
  return oss.str();
}

}  // namespace detail

enum class LogLevel
{
  TRACE,
  DEBUG,
  INFO,
  WARNING,
  ERROR,
  CRITICAL,
};

void Log(LogLevel level, std::string name, std::string message);

/// @name Logging Macros
/// @{

// Trace
#if FETCH_COMPILE_LOGGING_LEVEL >= 6
#define FETCH_LOG_TRACE_ENABLED
#define FETCH_LOG_TRACE(name, ...) fetch::LogTraceV2(name, __VA_ARGS__)
#else
#define FETCH_LOG_TRACE(name, ...) (void)name
#endif

// Debug
#if FETCH_COMPILE_LOGGING_LEVEL >= 5
#define FETCH_LOG_DEBUG_ENABLED
#define FETCH_LOG_DEBUG(name, ...) fetch::LogDebugV2(name, __VA_ARGS__)
#else
#define FETCH_LOG_DEBUG(name, ...) (void)name
#endif

// Info
#if FETCH_COMPILE_LOGGING_LEVEL >= 4
#define FETCH_LOG_INFO_ENABLED
#define FETCH_LOG_INFO(name, ...) fetch::LogInfoV2(name, __VA_ARGS__)
#else
#define FETCH_LOG_INFO(name, ...) (void)name
#endif

// Warn
#if FETCH_COMPILE_LOGGING_LEVEL >= 3
#define FETCH_LOG_WARN_ENABLED
#define FETCH_LOG_WARN(name, ...) fetch::LogWarningV2(name, __VA_ARGS__)
#else
#define FETCH_LOG_WARN(name, ...) (void)name
#endif

// Error
#if FETCH_COMPILE_LOGGING_LEVEL >= 2
#define FETCH_LOG_ERROR_ENABLED
#define FETCH_LOG_ERROR(name, ...) fetch::LogErrorV2(name, __VA_ARGS__)
#else
#define FETCH_LOG_ERROR(name, ...) (void)name
#endif

// Critical
#if FETCH_COMPILE_LOGGING_LEVEL >= 1
#define FETCH_LOG_CRITICAL_ENABLED
#define FETCH_LOG_CRITICAL(name, ...) fetch::LogCriticalV2(name, __VA_ARGS__)
#else
#define FETCH_LOG_CRITICAL(name, ...) (void)name
#endif
/// @}

}
