#include "defs.hpp"

IMPORTAPI(L"NTDLL.DLL", NtCreateSection, NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE)
IMPORTAPI(L"NTDLL.DLL", NtMapViewOfSection, NTSTATUS, HANDLE, HANDLE, PVOID, ULONG, ULONG, PLARGE_INTEGER, PULONG, SECTION_INHERIT, ULONG, ULONG)
IMPORTAPI(L"NTDLL.DLL", NtUnMapViewOfSection, NTSTATUS, HANDLE, PVOID)
IMPORTAPI(L"NTDLL.DLL", NtClose, NTSTATUS, HANDLE)
IMPORTAPI(L"NTDLL.DLL", NtProtectVirtualMemory, NTSTATUS, HANDLE, PVOID*, PULONG, ULONG, PULONG)
IMPORTAPI(L"NTDLL.DLL", NtWriteVirtualMemory, NTSTATUS, HANDLE, PVOID*, PVOID, ULONG, PULONG)

//Relocations done this way:
//https://int0xcc.svbtle.com/relocating-baseaddress-agnostic-memory-dumps
// 
//-Read about PE base relocations (and the structure layout), before coding this.
//https://github.com/MrLiamMcQ/simple-64-bit-manual-map-injector/blob/master/ManualInjector.cpp, look reloc block, makes sense?
bool FixBaseRelocations(void* ptrCurrent, void* ptrExternal, HMODULE dll)
{
#ifdef _WIN64
	QWORD delta = (QWORD)((QWORD)ptrExternal - (QWORD)ptrCurrent);
#endif
	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(ptrCurrent);
	PIMAGE_NT_HEADERS ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>((QWORD)ptrCurrent + dosHeader->e_lfanew);
	PIMAGE_BASE_RELOCATION pRelocEntry = reinterpret_cast<PIMAGE_BASE_RELOCATION>(ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + (QWORD)ptrCurrent);
	if (!pRelocEntry) {
		std::printf("pRelocEntry not found, error\n");
		return false;
	}
	
}
//Process of execution:
//1.-Mapping section object.
//2.-Mapping 2 views of the same section (What is a view in the first place -> Windows Internals).
//		-Explain the difference between just doing this, and complete manual mapping, in terms of the address space.
//3.-Base relocate from difference in each base.
// 
//CAREFUL: Make destructor in case of failure!.
bool DllSection::genSectionAndViews(HMODULE dll, PPROCESS_INFORMATION process)
{
	bool result = true;
	LARGE_INTEGER sizeSection;
	NTSTATUS status;
	PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(dll);
	if (dos_header->e_magic != 0x4d5a){
		std::printf("Not valid PE module!\n");
	}
	PIMAGE_NT_HEADERS ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(dll + dos_header->e_lfanew);
	sizeSection.LowPart = ntHeader->OptionalHeader.SizeOfImage;
	status = NtCreateSection(&m_hSection, SECTION_ALL_ACCESS, nullptr, &sizeSection, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);
	if (!NT_SUCCESS(status)){
		std::printf("Can't not create section to use in current and remote process, NTSTATUS = 0x%x\n", status);
		result = false;
		return result;
	}
	status = NtMapViewOfSection(m_hSection, GetCurrentProcess(), &ptrViewCurrent, 0, 0, nullptr, &m_dwSizeMappedView, SECTION_INHERIT::ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status)){
		std::printf("Can't not create view of section in current process, NTSTATUS = 0x%x\n", status);
		result = false;
		return result;
	}
	status = NtMapViewOfSection(m_hSection, process->hProcess, &ptrViewRemote, 0, 0, nullptr, &m_dwSizeMappedView, SECTION_INHERIT::ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status)){
		std::printf("Can't not create view of section in remote process, NTSTATUS = 0x%x\n", status);
		result = false;
		return result;
	}
	//Not sure if base relocations are done the same way for x64, verify.
	//VERY IMPORTANT: x64 != x86 in terms of relocs, be VERY carefull.
	if (memcpy_s(ptrViewCurrent, m_dwSizeMappedView, dll, ntHeader->OptionalHeader.SizeOfImage)
		&& FixBaseRelocations(ptrViewCurrent, ptrViewRemote, dll))
	{
		std::printf("Copy of buffer in current process and base relocation done sucessfull\n");
	}
	return result;
}

const HMODULE& DllSection::getCurrentModule()
{
	 return m_CurrentDll;
}
 const PROCESS_INFORMATION& TargetProcess::getProcInfo()
 {
	 return m_procinfo;
 }

DllSection::DllSection(HMODULE CurrentDll)
{
	m_CurrentDll = CurrentDll;
	m_hSection = NULL;
	ptrViewCurrent = ptrViewRemote = nullptr;
	m_dwSizeMappedView = NULL;
}

TargetProcess::TargetProcess(LPCWSTR processToStart, HMODULE CurrentDll) 
	: DllSection{ CurrentDll }, m_ProcessName{ processToStart }
{
	ZeroMemory(&m_procinfo, sizeof(m_procinfo));
	ZeroMemory(&m_ThreadHookContext, sizeof(m_ThreadHookContext));	
}

//Grab RCX for in memory hooking of entrypoint.
const CONTEXT& TargetProcess::GetMainThreadContext() noexcept
{
	m_ThreadHookContext.ContextFlags = CONTEXT_FULL;
	GetThreadContext(m_procinfo.hThread, &m_ThreadHookContext);
	return m_ThreadHookContext;
}

bool TargetProcess::CreateProcessSuspendedToInject() noexcept 
{
	STARTUPINFOW infoProc;
	ZeroMemory(&infoProc, sizeof(infoProc));
	infoProc.cb = sizeof(infoProc);
	ZeroMemory(&m_procinfo, sizeof(m_procinfo));
	wchar_t path[MAX_PATH];
	//Asumming that binary will be get from SYSTEM32!.
	GetSystemDirectoryW(path, MAX_PATH);
	m_ProcessName.insert(0, L"\\");
	wcscat_s(path, MAX_PATH, m_ProcessName.data());
	return CreateProcessW(NULL, path, NULL, NULL, false, CREATE_SUSPENDED, NULL, NULL, &infoProc, &m_procinfo);
}

