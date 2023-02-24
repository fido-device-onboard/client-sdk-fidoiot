call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" x86
REM call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x86
del build\win-client.exe
SET CL=/DECDSA_PRIVKEY#\"C:\\ProgramData\\Intel\\FDO\\data\\ecdsa384privkey.pem\"
msbuild WinClientBuild.sln /p:MyConstants="ECDSA384_DA;AES_MODE_GCM_ENABLED;REUSE_SUPPORTED;RESALE_SUPPORTED" /p:configuration=debug /t:Rebuild /p:platform=x86
copy Debug\win-client.exe build\