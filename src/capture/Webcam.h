#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include "../external/nlohmann/json.hpp"

namespace capture {

nlohmann::json ListWebcamDevices();
std::vector<BYTE> CaptureWebcamJPEG(int deviceIndex, const std::string& nameHint);

} // namespace capture
