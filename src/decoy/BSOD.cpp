#include "BSOD.h"
#include <windows.h>
#include <string>

namespace decoy {

namespace {
    LRESULT CALLBACK BSODWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
        switch (message) {
            case WM_PAINT: {
                PAINTSTRUCT ps;
                HDC hdc = BeginPaint(hWnd, &ps);

                // Blue background
                HBRUSH hBrush = CreateSolidBrush(RGB(0, 120, 215));
                FillRect(hdc, &ps.rcPaint, hBrush);
                DeleteObject(hBrush);

                // White text
                SetTextColor(hdc, RGB(255, 255, 255));
                SetBkMode(hdc, TRANSPARENT);

                HFONT hFont = CreateFontA(80, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_OUTLINE_PRECIS,
                    CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
                HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);

                RECT rc;
                GetClientRect(hWnd, &rc);

                RECT rcText = rc;
                rcText.left += 100;
                rcText.top += 150;

                TextOutA(hdc, rcText.left, rcText.top, ":(", 2);

                HFONT hFontSmall = CreateFontA(30, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_OUTLINE_PRECIS,
                    CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
                SelectObject(hdc, hFontSmall);

                rcText.top += 120;
                std::string msg = "Your PC ran into a problem and needs to restart. We're just\ncollecting some error info, and then we'll restart for you.";
                DrawTextA(hdc, msg.c_str(), -1, &rcText, DT_LEFT | DT_WORDBREAK);

                rcText.top += 150;
                std::string info = "0% complete";
                TextOutA(hdc, rcText.left, rcText.top, info.c_str(), (int)info.length());

                rcText.top += 200;
                std::string stopCode = "For more information about this issue and possible fixes, visit https://www.windows.com/stopcode\n\nIf you call a support person, give them this info:\nStop code: CRITICAL_PROCESS_DIED";
                DrawTextA(hdc, stopCode.c_str(), -1, &rcText, DT_LEFT | DT_WORDBREAK);

                SelectObject(hdc, hOldFont);
                DeleteObject(hFont);
                DeleteObject(hFontSmall);

                EndPaint(hWnd, &ps);
                break;
            }
            case WM_KEYDOWN: {
                // Check for CTRL+B
                if (wParam == 'B' && (GetKeyState(VK_CONTROL) & 0x8000)) {
                    DestroyWindow(hWnd);
                }
                break;
            }
            case WM_DESTROY:
                PostQuitMessage(0);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
        }
        return 0;
    }
}

void ShowBSOD() {
    HINSTANCE hInstance = GetModuleHandle(NULL);
    WNDCLASSEXA wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.lpfnWndProc = BSODWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "WindowsBSODDecoy";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    RegisterClassExA(&wc);

    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    HWND hWnd = CreateWindowExA(WS_EX_TOPMOST, wc.lpszClassName, "BSOD", WS_POPUP | WS_VISIBLE,
        0, 0, screenWidth, screenHeight, NULL, NULL, hInstance, NULL);

    if (hWnd) {
        // Hide the cursor
        ShowCursor(FALSE);

        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        ShowCursor(TRUE);
    }
}

} // namespace decoy
