add_executable(mcl-serialisation-tests
	"${PROJECT_ROOT}/mcl_cpp/serialisers.hpp"
	"${PROJECT_ROOT}/mcl_cpp/serialisers.cpp"
	"${PROJECT_ROOT}/mcl_cpp/logging.cpp"
	"${PROJECT_ROOT}/mcl_cpp/logging.hpp"
	"${PROJECT_ROOT}/mcl_cpp/logging_sink.hpp"
	"mcl-serialisation-tests.cpp"
)

target_include_directories(
	mcl-serialisation-tests
	PRIVATE
	"${PROJECT_ROOT}/third_party/catch-2.13.4/"
	"${PROJECT_ROOT}/mcl_cpp/"
)


add_test(mcl-serialisation-tests mcl-serialisation-tests)
