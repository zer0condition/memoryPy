import ctypes
import ctypes.wintypes

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.wintypes.DWORD),
        ("cntUsage", ctypes.wintypes.DWORD),
        ("th32ProcessID", ctypes.wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.wintypes.ULONG)),
        ("th32ModuleID", ctypes.wintypes.DWORD),
        ("cntThreads", ctypes.wintypes.DWORD),
        ("th32ParentProcessID", ctypes.wintypes.DWORD),
        ("pcPriClassBase", ctypes.wintypes.LONG),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("szExeFile", ctypes.wintypes.CHAR * 260),
    ]

class Memory:
    def __init__(self, process_name):
        self.h_handle = None
        self.h_handle = ctypes.windll.kernel32.OpenProcess(
            0x1F0FFF, False, self.get_process_id(process_name)
        )
        print("Handle:", self.h_handle)

    def __del__(self):
        if self.h_handle:
            ctypes.windll.kernel32.CloseHandle(self.h_handle)

    def get_process_id(self, process_name):
        snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x2, 0)
        pe_entry = PROCESSENTRY32()
        pe_entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        
        if ctypes.windll.kernel32.Process32First(snapshot, ctypes.byref(pe_entry)):
            while True:
                if process_name.lower() in pe_entry.szExeFile.decode().lower():
                    process_id = pe_entry.th32ProcessID
                    ctypes.windll.kernel32.CloseHandle(snapshot)
                    return process_id
                if not ctypes.windll.kernel32.Process32Next(snapshot, ctypes.byref(pe_entry)):
                    break
        
        ctypes.windll.kernel32.CloseHandle(snapshot)
        return 0
    
    def get_process_path(self, process_name):
        snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x2, 0)

        if snapshot == None:
            return ""

        process_entry = PROCESSENTRY32()
        process_entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

        if ctypes.windll.kernel32.Process32First(snapshot, ctypes.byref(process_entry)):
            while True:
                if process_name.lower() == process_entry.szExeFile.decode().lower():
                    ctypes.windll.kernel32.CloseHandle(snapshot)

                    h_process = ctypes.windll.kernel32.OpenProcess(
                        0x1000, False, process_entry.th32ProcessID
                    )
                    if h_process:
                        buffer = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
                        buffer_size = ctypes.wintypes.DWORD(ctypes.wintypes.MAX_PATH)

                        if ctypes.windll.kernel32.QueryFullProcessImageNameW(
                            h_process, 0, buffer, ctypes.byref(buffer_size)
                        ):
                            ctypes.windll.kernel32.CloseHandle(h_process)
                            return buffer.value

                        ctypes.windll.kernel32.CloseHandle(h_process)

                    return ""

                if not ctypes.windll.kernel32.Process32Next(snapshot, ctypes.byref(process_entry)):
                    break

        ctypes.windll.kernel32.CloseHandle(snapshot)
        return ""
    
    def get_process_base(self, process_name):
        process_path = self.get_process_path(process_name)
        if process_path:
            base_address = ctypes.windll.kernel32.LoadLibraryW(process_path)
            return ctypes.c_uint64(base_address).value
        return 0