#include <Windows.h>
#include <string>
#include <iostream>
#include <stdio.h>
#include <DbgHelp.h>
#include <iomanip>
#pragma comment(lib,"DbgHelp.lib")

// debugger status
enum class DebuggeeStatus
{
	NONE,
	SUSPENDED,
	INTERRUPTED
};
class CDebugger {
public:
	bool DEBUG = !true;//dbg mode
	struct LineInfo {
		std::string filePath;
		DWORD lineNumber;
	};
	// flag
	struct Flag
	{
		DWORD continueStatus;
		DWORD resetUserBreakPointAddress;
		bool isBeingStepOver;
		bool isBeingStepOut;
		bool isBeingSingleInstruction;
		LineInfo glf;
	} FLAG;
	// breakpoint
	struct BreakPoint
	{
		DWORD64 address;
		BYTE content;
	};
	BreakPoint bpStepOver;
	DebuggeeStatus debuggeeStatus;
	DWORD continueStatus;
	HANDLE debuggeehProcess;
	HANDLE debuggeehThread;
	DWORD debuggeeprocessID;
	DWORD debuggeethreadID;

	DWORD64 procBase;
	void InitProcess() {

		STARTUPINFOA startupinfo = { 0 };
		startupinfo.cb = sizeof(startupinfo);
		PROCESS_INFORMATION processinfo = { 0 };
		unsigned int creationflags = DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED | CREATE_NEW_CONSOLE;

		if (CreateProcessA(
			//"L:\\git_up\\anotherDebugger\\anotherDebugger\\Debug\\test.exe",
			//"E:\\User Files\\Download\\PSTools\\PsExec64.exe",
			//"C:\\Games\\Call of Duty Modern Warfare\\ModernWarfare_dump 27-03.exe",
			"C:\\Games\\Call of Duty Modern Warfare\\ModernWarfare_dump 01-04.exe",
			//path,
			NULL,
			NULL,
			NULL,
			FALSE,
			creationflags,
			NULL,
			NULL,
			&startupinfo,
			&processinfo) == FALSE)
		{
			std::cout << "CreateProcess failed: " << GetLastError() << std::endl;
			return;
		}

		debuggeehProcess = processinfo.hProcess;
		debuggeehThread = processinfo.hThread;
		debuggeeprocessID = processinfo.dwProcessId;
		debuggeethreadID = processinfo.dwThreadId;

		auto c = dbg.GetContext();
		procBase = dbg.Read <DWORD64>(c.Rdx + 0x10);

		debuggeeStatus = DebuggeeStatus::SUSPENDED;
		printf("T[%i] P[%04X] Process launched and suspended. [%p]\n", debuggeethreadID,debuggeeprocessID, procBase);
	}
	CONTEXT GetContext()
	{
		CONTEXT c;
		c.ContextFlags = CONTEXT_ALL;

		if (GetThreadContext(this->debuggeehThread, &c))
		{
			//return false;
		}
		return c;
	}
	void SetContext(CONTEXT* c) {
		SetThreadContext(debuggeehThread, c);
	}
	void setCPUTrapFlag()
	{
		CONTEXT c = GetContext();
		c.EFlags |= 0x100;
		SetContext(&c);
	}
	void Run() {
		if (debuggeeStatus == DebuggeeStatus::NONE)
		{
			//std::cout << "Debuggee is not started yet." << std::endl;
			return;
		}
		if (debuggeeStatus == DebuggeeStatus::SUSPENDED)
		{
			//std::cout << "Continue to run." << std::endl;
			ResumeThread(debuggeehThread);
		}
		else
		{
			ContinueDebugEvent(debuggeeprocessID, debuggeethreadID, FLAG.continueStatus);
			//printf("goocci\n");
		}

		DEBUG_EVENT debugEvent;
		while (WaitForDebugEvent(&debugEvent, INFINITE) == TRUE)
		{
			debuggeeprocessID = debugEvent.dwProcessId;
			debuggeethreadID = debugEvent.dwThreadId;
			if (DispatchDebugEvent(debugEvent) == TRUE)
			{
				ContinueDebugEvent(debuggeeprocessID, debuggeethreadID, FLAG.continueStatus);
			}
			else {
				break;
			}
		}
	}
	void StepIn() {
		setCPUTrapFlag();
		FLAG.isBeingSingleInstruction = true;
		Run();
	}
	void resetBreakPointHandler()
	{
		/*bpUserList.clear();
		isInitBpSet = false;

		bpStepOut.address = 0;
		bpStepOver.content = 0;*/

		//bpStepOver.address = 0;
		//bpStepOut.content = 0;

		FLAG.continueStatus = DBG_CONTINUE;
		FLAG.isBeingSingleInstruction = false;
		FLAG.isBeingStepOut = false;
		FLAG.isBeingStepOver = false;
		FLAG.resetUserBreakPointAddress = 0;
		FLAG.glf.lineNumber = 0;
		FLAG.glf.filePath = std::string();

		//moduleMap.clear();
	}
	bool OnProcessCreated(const CREATE_PROCESS_DEBUG_INFO* pInfo)
	{
		std::cout << "Debuggee created." << std::endl;

		this->resetBreakPointHandler();

		if (SymInitialize(debuggeehProcess, NULL, FALSE) == TRUE)
		{
			DWORD64 moduleAddress = SymLoadModule64(
				debuggeehProcess,
				pInfo->hFile,
				NULL,
				NULL,
				(DWORD64)pInfo->lpBaseOfImage,
				0
			);
			if (moduleAddress == 0)
			{
				std::cout << "SymLoadModule64 failed: " << GetLastError() << std::endl;
			}
			else {
				// set entry stop 
				//setDebuggeeEntryPoint();
			}
		}
		else
		{
			std::cout << "SymInitialize failed: " << GetLastError() << std::endl;
		}
		return true;
	}
	enum class BpType
	{
		INIT,
		STEP_OVER,
		STEP_OUT,
		USER,
		CODE
	};
	BpType getBreakPointType(DWORD addr) {
		static bool isInitBpSet = false;
		if (isInitBpSet == false)
		{
			isInitBpSet = true;
			return BpType::INIT;
		}
		return BpType::CODE;
	}
	bool OnBreakPoint(const EXCEPTION_DEBUG_INFO* pInfo)
	{
		auto bpType = getBreakPointType((DWORD)(pInfo->ExceptionRecord.ExceptionAddress));
		printf("bp type: %i\n", bpType);
		switch (bpType)
		{
		case BpType::INIT:
			FLAG.continueStatus = DBG_CONTINUE;
			//auto c = GetContext();
			//c.Rip = procBase + 0xE74D84;
			//dbg.SetContext(&c);
			return true;

		/*case BpType::CODE:
			return onNormalBreakPoint(pInfo);

		case BpType::STEP_OVER:
			deleteStepOverBreakPoint();
			backwardDebuggeeEIP();
			return onSingleStepCommonProcedures();

		case BpType::USER:
			return onUserBreakPoint(pInfo);

		case BpType::STEP_OUT:
			return onStepOutBreakPoint(pInfo);*/
		}

		return true;
	}
	bool getCurrentLineInfo(LineInfo& lf)
	{
		CONTEXT context = GetContext();

		DWORD displacement;
		IMAGEHLP_LINE64 lineInfo = { 0 };
		lineInfo.SizeOfStruct = sizeof(lineInfo);

		if (SymGetLineFromAddr64(
			debuggeehProcess,
			context.Rip,
			&displacement,
			&lineInfo) == TRUE) {

			lf.filePath = std::string(lineInfo.FileName);
			lf.lineNumber = lineInfo.LineNumber;

			return true;
		}
		else {
			lf.filePath = std::string();
			lf.lineNumber = 0;

			return false;
		}
	}
	bool isLineChanged()
	{
		LineInfo lf;
		if (false == getCurrentLineInfo(lf))
		{
			return false;
		}

		if (lf.lineNumber == FLAG.glf.lineNumber &&
			lf.filePath == FLAG.glf.filePath)
		{
			return false;
		}

		return true;
	}
	int isCallInstruction(DWORD64 addr)
	{
		BYTE instruction[10];

		size_t nRead;
		ReadProcessMemory(debuggeehProcess, (LPCVOID)addr, instruction, 10, &nRead);

		switch (instruction[0]) {

		case 0xE8:
			return 5;

		case 0x9A:
			return 7;

		case 0xFF:
			switch (instruction[1]) {

			case 0x10:
			case 0x11:
			case 0x12:
			case 0x13:
			case 0x16:
			case 0x17:
			case 0xD0:
			case 0xD1:
			case 0xD2:
			case 0xD3:
			case 0xD4:
			case 0xD5:
			case 0xD6:
			case 0xD7:
				return 2;

			case 0x14:
			case 0x50:
			case 0x51:
			case 0x52:
			case 0x53:
			case 0x54:
			case 0x55:
			case 0x56:
			case 0x57:
				return 3;

			case 0x15:
			case 0x90:
			case 0x91:
			case 0x92:
			case 0x93:
			case 0x95:
			case 0x96:
			case 0x97:
				return 6;

			case 0x94:
				return 7;
			}

		default:
			return 0;
		}
	}
	void ReadTo(DWORD64 addr, LPBYTE dest, DWORD nSize) {
		size_t nRead;
		ReadProcessMemory(debuggeehProcess, (LPCVOID)addr, dest, nSize, &nRead);
	}
	template <class T>
	T Read(DWORD64 addr) {
		T out;
		size_t nRead;
		ReadProcessMemory(debuggeehProcess, (LPCVOID)addr, &out, sizeof(T), &nRead);
		return out;
	}
	template <class T>
	void Write(DWORD64 addr,T t) {
		size_t nRead;
		WriteProcessMemory(debuggeehProcess, (LPVOID)addr, &t, sizeof(T), &nRead);
	}
	BYTE setBreakPointAt(DWORD64 addr)
	{
		BYTE byte = Read<BYTE>(addr);
		//readDebuggeeMemory(addr, 1, &byte);

		Write<BYTE>(addr,0xCC);//BYTE intInst = 0xCC;
		//writeDebuggeeMemory(addr, 1, &intInst);
		return byte;
	}
	void setStepOverBreakPointAt(DWORD64 addr)
	{
		bpStepOver.address = addr;
		bpStepOver.content = setBreakPointAt(addr);
	}
	bool OnSingleStepCommonProcedures()
	{
		if (isLineChanged() == false)
		{
			if (true == FLAG.isBeingStepOver)
			{
				CONTEXT c = GetContext();
				int pass = isCallInstruction(c.Rip);

				if (pass != 0)
				{
					setStepOverBreakPointAt(c.Rip + pass);
					FLAG.isBeingSingleInstruction = false;
				}
				else {
					setCPUTrapFlag();
					FLAG.isBeingSingleInstruction = true;
				}
			}
			else {
				setCPUTrapFlag();
				FLAG.isBeingSingleInstruction = true;
			}

			FLAG.continueStatus = DBG_CONTINUE;
			return true;
		}

		if (FLAG.isBeingStepOver == true)
		{
			FLAG.isBeingStepOver = false;
		}

		debuggeeStatus = DebuggeeStatus::INTERRUPTED;

		return false;
	}
	bool OnSingleStepTrap(const EXCEPTION_DEBUG_INFO* pInfo)
	{
		/*auto resetUserBreakPoint = [this]() -> void
		{
			for (auto it = this->bpUserList.begin();
				it != this->bpUserList.end();
				++it)
			{
				if (it->address == this->FLAG.resetUserBreakPointAddress)
				{
					setBreakPointAt(it->address);
					this->FLAG.resetUserBreakPointAddress = 0;
				}
			}
		};

		if (FLAG.resetUserBreakPointAddress)
		{
			ResetUserBreakPoint();
		}*/

		if (true == FLAG.isBeingSingleInstruction)
		{
			return  OnSingleStepCommonProcedures();
		}

		FLAG.continueStatus = DBG_CONTINUE;
		return true;
	}
	bool bGotSingleStep = false;
	bool OnException(const EXCEPTION_DEBUG_INFO* pInfo)
	{
		if (DEBUG == true)
		{
			std::cout << "An exception has occured " << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
				<< pInfo->ExceptionRecord.ExceptionAddress << " - Exception code: " << pInfo->ExceptionRecord.ExceptionCode << std::dec << std::endl;
		}

		switch (pInfo->ExceptionRecord.ExceptionCode)
		{
		case EXCEPTION_BREAKPOINT:
			return OnBreakPoint(pInfo);
		case EXCEPTION_SINGLE_STEP:
			bGotSingleStep = true;
			debuggeeStatus = DebuggeeStatus::INTERRUPTED;
			return false;// OnSingleStepTrap(pInfo);
			break;
		case 0xC0000005:
			debuggeeStatus = DebuggeeStatus::INTERRUPTED;

			printf("%p - access violation!!!\n", pInfo->ExceptionRecord.ExceptionAddress);
			return false;//
			break;
		}

		if (pInfo->dwFirstChance == TRUE)
		{
			if (DEBUG == true)
			{
				std::cout << "First chance." << std::endl;
			}
		}
		else
		{
			if (DEBUG == true)
			{
				std::cout << "Second chance." << std::endl;
			}
		}

		debuggeeStatus = DebuggeeStatus::INTERRUPTED;
		return false;
	}
	bool DispatchDebugEvent(const DEBUG_EVENT& debugEvent) {

		switch (debugEvent.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
			 OnProcessCreated(&debugEvent.u.CreateProcessInfo);
			 return true;
		case CREATE_THREAD_DEBUG_EVENT:
			//printf("Thread created!\n");
			return true;
			break;
		case LOAD_DLL_DEBUG_EVENT:
			//wprintf(L"dll loaded.. %p\n", debugEvent.u.LoadDll.lpBaseOfDll);
			return true;// onDllLoaded(&debugEvent.u.LoadDll);
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			//wprintf(L"dll unloaded.. %p\n", debugEvent.u.LoadDll.lpBaseOfDll);
			return true;// onDllLoaded(&debugEvent.u.LoadDll);
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			//printf("Thread Exit!\n");
			return true;// onThreadExited(&debugEvent.u.ExitThread);
			break;
		case EXCEPTION_DEBUG_EVENT:
			//printf("[%i] debug event\n", debugEvent.dwThreadId);
			return OnException(&debugEvent.u.Exception);
			break;
		default:

			printf("UNK event: %i\n", debugEvent.dwDebugEventCode);
			break;
		}
		return false;
	}
	void SingleStep() {

		setCPUTrapFlag();
		FLAG.isBeingSingleInstruction = true;
		Run();
	}
} dbg;
void ShowCtx(CONTEXT c) {
	printf("RAX: %p\n", c.Rax);
	printf("RBX: %p\n", c.Rbx);
	printf("RCX: %p\n", c.Rcx);
	printf("RDX: %p\n", c.Rdx);
	printf("RBP: %p\n", c.Rbp);
	printf("RSP: %p\n", c.Rsp);
	printf("RSI: %p\n", c.Rsi);
	printf("RDI: %p\n", c.Rdi);
}

#include <inttypes.h>
#include <Zydis/Zydis.h>
#pragma comment(lib,"Zydis.lib")
DWORD64 DumpFnc(DWORD idx, bool bNotBones = false) {
	DWORD DISP_VALUE = 0x19;
	DWORD64 dwRet = 0;
	CONTEXT c;
	c = dbg.GetContext();
	c.Rip = dbg.procBase + 0xEC49A4; //48 89 54 24 10 53 55 56 57 48 83 EC 38 80 BA 2C 0A 00 00 00 48 8B EA 65 4C 8B 04 25 58 00 00 00
	c.Rcx = idx; //fnc index
	dbg.SetContext(&c);

	dbg.SingleStep();
	c = dbg.GetContext();
	c.Rip = dbg.procBase + 0xEC4A21;
	if (bNotBones) { //not bones, scan for decrypt_key_for_entity
		DISP_VALUE = 0x09;
		c.Rax = idx;
		c.Rip = dbg.procBase + 0xEDBB0B;
	}
	dbg.SetContext(&c);

	dbg.SingleStep();
	c = dbg.GetContext();

	dbg.SingleStep();
	c = dbg.GetContext();

	dbg.SingleStep();
	c = dbg.GetContext();
	dwRet = c.Rax;

	//loop till we find the end..
	BYTE bEndSig[20] = { 0x4C ,0x8B ,0x7C ,0x24 ,0x20 ,0x4C ,0x8B ,0x74 ,0x24 ,0x28 ,0x4C ,0x8B ,0x6C ,0x24 ,0x30 ,0x4C ,0x8B ,0x64 ,0x24 ,0x60 };
	BYTE bEndSig2[20] = { 0x44, 0x8B, 0x64, 0x24, 0x30, 0x44, 0x8B, 0x6C, 0x24, 0x34, 0x4C, 0x8B, 0x7C, 0x24, 0x40, 0x4C, 0x8B, 0x74, 0x24, 0x38 };
	/*00007FF603397031 | 4C:8B7C24 20                      | mov     r15, qword ptr ss:[rsp + 0x20]                                                 |
00007FF603397036 | 4C:8B7424 28                      | mov     r14, qword ptr ss:[rsp + 0x28]                                                 |
00007FF60339703B | 4C:8B6C24 30                      | mov     r13, qword ptr ss:[rsp + 0x30]                                                 |
00007FF603397040 | 4C:8B6424 60                      | mov     r12, qword ptr ss:[rsp + 0x60]                                                 |*/

// Initialize decoder context.
	ZydisDecoder decoder;
	ZydisDecoderInit(
		&decoder,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_ADDRESS_WIDTH_64);

	// Initialize formatter. Only required when you actually plan to
	// do instruction formatting ("disassembling"), like we do here.
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

	// Loop over the instructions in our buffer.
	// The IP is chosen arbitrary here in order to better visualize
	// relative addressing.
	uint64_t instructionPointer = 0x007FFFFFFF400000;
	size_t offset = 0;
	ZydisDecodedInstruction instruction;

	DWORD64 oldRip = 0;
	DWORD iImul = 0;
	bool bLastKey = false;
	DWORD64 dwKeys[4] = { 0,0,0,0 };
	while(1) {
		BYTE bRead[20];
		dbg.ReadTo(c.Rip, bRead, 20);

		//printf("F EIP: %p / %p / %p\n", c.Rip, c.Rdx, c.Rax);
		if (!memcmp(bRead, bEndSig, 20) || !memcmp(bRead, bEndSig2, 20)) {
			//printf("END SIG!\n");
			break;
		}

		bool goodDec = ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(
			&decoder, bRead, 20,
			instructionPointer, &instruction));
		//skip 00007FF603394F6D | 4C:8B41 0F                        | mov     r8, qword ptr ds:[rcx + 0xF]                                                   |
		if (goodDec && (instruction.mnemonic == ZYDIS_MNEMONIC_MOV || instruction.mnemonic == ZYDIS_MNEMONIC_IMUL) && instruction.operands[1].mem.disp.hasDisplacement && instruction.operands[1].mem.disp.value == DISP_VALUE) {
			bLastKey = true;
			//skip
			c = dbg.GetContext();
			c.Rip += 4; //fnc index
			if (instruction.mnemonic == ZYDIS_MNEMONIC_IMUL) {
				bLastKey = false;
				iImul++;//skip lastKey
				c.Rip++;
			}
			dbg.SetContext(&c);
			continue;
		}
		oldRip = c.Rip;
		dbg.SingleStep();

		c = dbg.GetContext();
		DWORD nInstructSize = c.Rip - oldRip;

		{
			if (goodDec && instruction.mnemonic == ZYDIS_MNEMONIC_IMUL) {
				DWORD64 pReg = 0;
				if (!bLastKey) {

					if (goodDec) {
						BYTE reg = instruction.operands[1].reg.value;
						switch (reg) {
						case ZYDIS_REGISTER_RAX:
							pReg = c.Rax;
							break;
						case ZYDIS_REGISTER_RCX:
							pReg = c.Rcx;
							break;
						case ZYDIS_REGISTER_RBP:
							pReg = c.Rbp;
							break;
						case ZYDIS_REGISTER_RDI:
							pReg = c.Rdi;
							break;
						case ZYDIS_REGISTER_R9:
							pReg = c.R9;
							break;
						case ZYDIS_REGISTER_R10:
							pReg = c.R10;
							break;
						case ZYDIS_REGISTER_R11:
							pReg = c.R11;
							break;
						case ZYDIS_REGISTER_R12:
							pReg = c.R12;
							break;
						case ZYDIS_REGISTER_R13:
							pReg = c.R13;
							break;
						case ZYDIS_REGISTER_R14:
							pReg = c.R14;
							break;
						case ZYDIS_REGISTER_R15:
							pReg = c.R15;
							break;
						default:
							printf("unk good zydis %i\n", reg);
							break;
						}
					}
				}

				dwKeys[iImul++] = pReg;
				bLastKey = false;
			}
			//check if imul
		}
	}

	bool bGen = true;
	if (bGen) {
		if (dwKeys[0] == 0) printf("key[%i][0] = LastKey;\n",idx); else printf("key[%i][0] = 0x%p;\n", idx, dwKeys[0]);
		if (dwKeys[1] == 0) printf("key[%i][1] = LastKey;\n",idx); else 		printf("key[%i][1] = 0x%p;\n", idx, dwKeys[1]);
		if (dwKeys[2] == 0) printf("key[%i][2] = LastKey;\n", idx); else printf("key[%i][2] = 0x%p;\n", idx, dwKeys[2]);
		if (dwKeys[3] == 0) printf("key[%i][3] = LastKey;\n\n", idx); else printf("key[%i][3] = 0x%p;\n\n", idx, dwKeys[3]);
	}
	else {
		printf("%p - keys[%i] = { %p , %p , %p , %p }\n",dwRet, idx,dwKeys[0], dwKeys[1], dwKeys[2], dwKeys[3]);
		//printf("key[%i] = { 0x%p , 0x%p , 0x%p , 0x%p }\n", idx, dwKeys[0], dwKeys[1], dwKeys[2], dwKeys[3]);
	}

	return dwRet;
}
int main() {
	printf("Hi!\n");
	dbg.InitProcess();
	dbg.SingleStep();
	//DumpFnc(14);
	for (int i = 0; i < 16; i++) {
		DumpFnc(i);
	}
	//printf("FNC0: %p\n", DumpFnc(0));
	//printf("FNC1: %p\n", DumpFnc(1));
#if 0
	//set RIP..
	/*c = dbg.GetContext();
	ShowCtx(c);
	DWORD64 base = dbg.Read <DWORD64>(c.Rdx + 0x10);
	printf("base: %p / %p\n", c.Rdx, base);
	c.Rip = procBase+0xE74D84;
	dbg.SetContext(&c);
	getchar();*/
	c = dbg.GetContext();
	//c.Rip++;
	c.Rip = dbg.procBase + 0xE74D84;
	dbg.SetContext(&c);

	//print eip
	printf("A EIP: %p / %p\n", c.Rip,c.Rsp);

	//dbg.StepIn();
	dbg.SingleStep();
	c = dbg.GetContext();
	c.Rip = dbg.procBase + 0xE74D84;
	dbg.SetContext(&c);

	c = dbg.GetContext();
	printf("B EIP: %p / %p\n", c.Rip, c.Rsp);

	dbg.SingleStep();

	c = dbg.GetContext();
	printf("C EIP: %p / %p\n", c.Rip, c.Rsp);

#endif
	getchar();
	return 0;
}