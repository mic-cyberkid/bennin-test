#pragma once

#include <string>

namespace http {

class RedirectorResolver {
public:
    RedirectorResolver(const std::string& redirectorUrl);
    std::string resolve();

private:
    std::string redirectorUrl_;
};

} // namespace http
