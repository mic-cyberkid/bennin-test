#include "Webcam.h"
#include <string>
#include <vector>
#include <vfw.h>
#include <gdiplus.h>
#pragma comment(lib, "vfw32.lib")
#pragma comment(lib, "gdiplus.lib")

using namespace Gdiplus;

namespace capture {
namespace {
    int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
        UINT num = 0, size = 0;
        GetImageEncodersSize(&num, &size);
        if (size == 0) return -1;
        std::vector<BYTE> buffer(size);
        ImageCodecInfo* pImageCodecInfo = (ImageCodecInfo*)buffer.data();
        GetImageEncoders(num, size, pImageCodecInfo);
        for (UINT j = 0; j < num; ++j) {
            if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0) {
                *pClsid = pImageCodecInfo[j].Clsid;
                return j;
            }
        }
        return -1;
    }

    std::vector<BYTE> ConvertBmpToJpeg(HGLOBAL hDib) {
        std::vector<BYTE> buffer;
        GdiplusStartupInput gdiplusStartupInput;
        ULONG_PTR gdiplusToken;
        if (GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL) != Ok) return {};

        {
            IStream* pStream = NULL;
            if (CreateStreamOnHGlobal(hDib, FALSE, &pStream) == S_OK) {
                Bitmap* bitmap = new Bitmap(pStream);
                if (bitmap && bitmap->GetLastStatus() == Ok) {
                    CLSID encoderClsid;
                    if (GetEncoderClsid(L"image/jpeg", &encoderClsid) != -1) {
                        IStream* pOutStream = NULL;
                        if (CreateStreamOnHGlobal(NULL, TRUE, &pOutStream) == S_OK) {
                            EncoderParameters encoderParameters;
                            encoderParameters.Count = 1;
                            encoderParameters.Parameter[0].Guid = EncoderQuality;
                            encoderParameters.Parameter[0].Type = EncoderParameterValueTypeLong;
                            encoderParameters.Parameter[0].NumberOfValues = 1;
                            ULONG quality = 40;
                            encoderParameters.Parameter[0].Value = &quality;

                            if (bitmap->Save(pOutStream, &encoderClsid, &encoderParameters) == Ok) {
                                LARGE_INTEGER liZero = {};
                                ULARGE_INTEGER uliSize = {};
                                pOutStream->Seek(liZero, STREAM_SEEK_END, &uliSize);
                                pOutStream->Seek(liZero, STREAM_SEEK_SET, NULL);
                                buffer.resize((size_t)uliSize.QuadPart);
                                ULONG bytesRead = 0;
                                pOutStream->Read(buffer.data(), (ULONG)buffer.size(), &bytesRead);
                            }
                            pOutStream->Release();
                        }
                    }
                }
                delete bitmap;
                pStream->Release();
            }
        }
        GdiplusShutdown(gdiplusToken);
        return buffer;
    }
}

    std::vector<BYTE> CaptureWebcamImage() {
        char windowName[] = "CamCap";
        HWND hWebcam = capCreateCaptureWindowA(windowName, WS_CHILD, 0, 0, 320, 240, GetDesktopWindow(), 0);
        if (!hWebcam) return {};

        std::vector<BYTE> buffer;

        if (SendMessage(hWebcam, WM_CAP_DRIVER_CONNECT, 0, 0)) {
            SendMessage(hWebcam, WM_CAP_GRAB_FRAME, 0, 0);

            HGLOBAL hDib = (HGLOBAL)SendMessage(hWebcam, WM_CAP_EDIT_COPY, 0, 0);
            if (hDib) {
                buffer = ConvertBmpToJpeg(hDib);
                GlobalFree(hDib);
            }

            SendMessage(hWebcam, WM_CAP_DRIVER_DISCONNECT, 0, 0);
        }

        DestroyWindow(hWebcam);
        return buffer;
    }

}
