:: compile the no obfuscation version
cl.exe no-obfuscation.c /Fe:no-obfuscation.exe
del no-obfuscation.obj

:: compile the obfuscated api version
cl.exe obfuscated-apis.c /Fe:obfuscated-apis.exe
del obfuscated-apis.obj

:: compile the encrypted api version
cl.exe encrypted-apis.c /Fe:encrypted-apis.exe 
del encrypted-apis.obj