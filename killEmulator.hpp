#include <windows.h>
#include <iostream>
#include <psapi.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <array>
#include <string>
#include <algorithm>
#include <mutex>

// https://github.com/LiamG53

namespace protection
{
	enum types
	{
		search = EXCEPTION_CONTINUE_SEARCH,
		page_guard_violation = STATUS_GUARD_PAGE_VIOLATION,
		break_point = STATUS_BREAKPOINT,
		long_jump = STATUS_LONGJUMP
	};

	inline bool iequals_ascii(const std::wstring& lhs, const wchar_t* rhs)
	{
		if (!rhs) return false;
		const std::wstring rhsValue(rhs);
		if (lhs.size() != rhsValue.size()) return false;
		for (size_t i = 0; i < lhs.size(); ++i)
		{
			const wchar_t a = towlower(lhs[i]);
			const wchar_t b = towlower(rhsValue[i]);
			if (a != b) return false;
		}
		return true;
	}

	// helper function to determine wether or not the address is within the current module/handle.
	bool within_region(HMODULE module, LPVOID address)
	{
		MODULEINFO info; // place holder for the information

		// use this function in order to get the module information.
		bool result = GetModuleInformation(GetCurrentProcess(), 
			module, &info, sizeof(info));
		if (result)
		{
			LPVOID module_base = info.lpBaseOfDll;
			size_t module_size = info.SizeOfImage;
			
			// return wether not the module is within the means of the current image size and base.
			return (address >= module_base && 
				address < (PBYTE)module_base + module_size);
		}
		return false; // failed to get the information.
	}

	inline bool has_blacklisted_process()
	{
		constexpr std::array<const wchar_t*, 11> blacklist = {
			L"vboxservice.exe", L"vboxtray.exe", L"vmtoolsd.exe", L"vmwaretray.exe",
			L"vmwareuser.exe", L"qemu-ga.exe", L"xenservice.exe", L"prl_tools.exe",
			L"ollydbg.exe", L"x64dbg.exe", L"ida64.exe"
		};

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE)
		{
			return false;
		}

		PROCESSENTRY32W pe{};
		pe.dwSize = sizeof(pe);
		bool detected = false;
		if (Process32FirstW(snapshot, &pe))
		{
			do
			{
				const std::wstring processName(pe.szExeFile);
				for (const auto* blocked : blacklist)
				{
					if (iequals_ascii(processName, blocked))
					{
						detected = true;
						break;
					}
				}
			} while (!detected && Process32NextW(snapshot, &pe));
		}

		CloseHandle(snapshot);
		return detected;
	}

	inline bool has_debugger()
	{
		BOOL remoteDebugger = FALSE;
		CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);
		return IsDebuggerPresent() || remoteDebugger;
	}

	inline int environment_risk_score()
	{
		int score = 0;

		if (has_debugger())
		{
			score += 3;
		}
		if (has_blacklisted_process())
		{
			score += 4;
		}

		int cpuInfo[4] = { 0, 0, 0, 0 };
		__cpuid(cpuInfo, 1);
		const bool hypervisorPresent = (cpuInfo[2] & (1 << 31)) != 0;
		if (hypervisorPresent)
		{
			score += 1;
		}

		MEMORYSTATUSEX mem{};
		mem.dwLength = sizeof(mem);
		if (GlobalMemoryStatusEx(&mem))
		{
			const ULONGLONG twoGb = 2ull * 1024ull * 1024ull * 1024ull;
			if (mem.ullTotalPhys < twoGb)
			{
				score += 1;
			}
		}

		return score;
	}

	inline bool heartbeat()
	{
		// layered local environment checks with low false-positive thresholding -nigel
		return environment_risk_score() < 4;
	}

	long handler(EXCEPTION_POINTERS *info)
	{
		if (!info || !info->ExceptionRecord || !info->ContextRecord)
		{
			return types::page_guard_violation;
		}

		// place holder for the current module, in regards with our regional memory checks.
		static auto current_module = 
			GetModuleHandleA(0);
		if (!current_module)
		{
			// throw a random page guard violation causing the application to most likely crash
			return types::page_guard_violation;
		}

		// get the return address for this context.
#ifdef _WIN64
		auto return_address = info->ContextRecord->Rip;
		if (return_address != info->ContextRecord->Rip)
		{
			// tampered with the return address via an external process or via byte patching.
			//  either way we will detect it.
			return types::page_guard_violation;
		}

		// check if the return address is within the region of our process memory.
		if (!within_region(current_module,
			reinterpret_cast<LPVOID>(return_address)))
		{
			return types::page_guard_violation;
		}
#else
		auto return_address = info->ContextRecord->Eip;
		if (return_address != info->ContextRecord->Eip)
		{
			// tampered with the return address via an external process or via byte patching.
			//  either way we will detect it.
			return types::page_guard_violation;
		}

		// check if the return address is within the region of our process memory.
		if (!within_region(current_module,
			reinterpret_cast<LPVOID>(return_address)))
		{
			return types::page_guard_violation;
		}
#endif

		// check for long jumps if they are within the modules memory
		if (info->ExceptionRecord->ExceptionCode == types::long_jump)
		{
			if (!within_region(current_module,
				reinterpret_cast<LPVOID>(info->ExceptionRecord->ExceptionAddress)))
			{
				return types::page_guard_violation;
			}
		}
		
		// check breakpoints because some people like writing bytes which are weird
		if (info->ExceptionRecord->ExceptionCode == types::break_point)
		{
			if (!within_region(current_module,
				reinterpret_cast<LPVOID>(info->ExceptionRecord->ExceptionAddress)))
			{
				return types::page_guard_violation;
			}
		}
		
		// continue on with the search
		return types::search;
	}

	void init()
	{
		// install veh once to avoid handler stacking and instability -nigel
		static std::once_flag once;
		std::call_once(once, []()
		{
			AddVectoredExceptionHandler(TRUE, reinterpret_cast<PVECTORED_EXCEPTION_HANDLER>(handler));
		});
	}
};
