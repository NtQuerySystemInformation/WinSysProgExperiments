#pragma once
#include <Windows.h>
#include <string>
#include <type_traits>

//MISSING:
//1.Make proper destructions that check existance of members(just in case of failure).

typedef enum class _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor; 
	PVOID SecurityQualityOfService; 
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

using QWORD = ULONGLONG;

//Methods.
//1.Create proper hook with disassembler, USE Hacker Disassembler Engine 64 or any other length disassembler.
//	-Learn about encoding of instructions, so its easier to manipulate the code.
class HookFunction 
{
public:

private:
	uint32_t numberHooks;
};

//Methods: 
// 1.-Map view of section for both payload process and target process.
// 2.-Relocate PE in target DLL with the appropiate relocations. (It is time to learn how the fuck to do proper relocations.)
		//Remember, the objective is to calculate.
class DllSection
{
public:
	DllSection() = default;
	DllSection(HMODULE CurrentDll);
	bool genSectionAndViews(HMODULE dll, PPROCESS_INFORMATION process);
	const HMODULE& getCurrentModule();

private:
	void* ptrViewCurrent, *ptrViewRemote;
	HANDLE m_hSection;
	DWORD m_dwSizeMappedView;
	HMODULE m_CurrentDll;
};

//METHODS: 
//1.- Spawn remote process
//2.- get main thread context.
//Use class template to support x86?
class TargetProcess : public DllSection, public HookFunction
{
public:
	TargetProcess() = default;
	TargetProcess(LPCWSTR processToStart, HMODULE CurrentDll);
	const CONTEXT& GetMainThreadContext() noexcept;
	const PROCESS_INFORMATION& getProcInfo();
	bool CreateProcessSuspendedToInject() noexcept;

private:
	PROCESS_INFORMATION m_procinfo;
	CONTEXT m_ThreadHookContext;
	std::wstring m_ProcessName;
};

bool FixBaseRelocations(void* ptrCurrent, void* ptrExternal, HMODULE dll);

using NTSTATUS = LONG;
static constexpr bool NT_SUCCESS(NTSTATUS status) { return status >= 0; }

#define TOKENIZE(x) #x
#define CONCAT( X, Y ) X##Y

using namespace std;

template< typename modHandleType, typename procNameType >
auto getProcAddressOrThrow(modHandleType modHandle, procNameType procName)
{
	auto address = GetProcAddress(modHandle, procName);
	if (address == nullptr) throw std::exception{ ("Error importing: "s + procName).c_str() };
	return address;
}

#define IMPORTAPI( DLLFILE, FUNCNAME, RETTYPE, ... )                                                                        \
   typedef RETTYPE( WINAPI* CONCAT( t_, FUNCNAME ) )( __VA_ARGS__ );                                                        \
   template< typename... Ts >                                                                                               \
   auto FUNCNAME( Ts... ts ){                                                                                              \
      const static CONCAT( t_, FUNCNAME ) func =                                                                            \
       (CONCAT( t_, FUNCNAME )) getProcAddressOrThrow( ( LoadLibraryW( DLLFILE ), GetModuleHandleW( DLLFILE ) ), #FUNCNAME ); \
      return func(  forward< Ts >( ts )... );                                                                           \
}; 