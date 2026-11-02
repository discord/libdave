// built into libdave by CMake for Windows test builds, since a libdave DLL has its own CRT whose
// asserts default to a modal dialog that blocks tests
#ifdef _DEBUG
#include <crtdbg.h>
#include <stdlib.h>

namespace {
[[maybe_unused]] const bool kTestCrtReportingConfigured = [] {
    (void)_set_error_mode(_OUT_TO_STDERR);
    (void)_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    (void)_CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    (void)_set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    return true;
}();
} // namespace
#endif
