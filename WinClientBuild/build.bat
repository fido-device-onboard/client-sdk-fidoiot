call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" x86
#call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x86
cd 3rdParty\openssl-1.1.1s
perl Configure VC-WIN32
nmake
cd 3rdParty\curl-7.87.0\winbuild
del ..\builds\* /F /Q
nmake /f Makefile.vc mode=static ENABLE_WINSSL=yes
cd ..\..\..
cd 3rdParty\safestringlib-1.2.0\WinBuild
msbuild WinBuild.sln /p:configuration=debug /t:Rebuild /p:platform=x86
cd ..\..\..
cd 3rdParty\tinycbor-0.6.0\WinCbor
msbuild WinCbor.sln /p:configuration=debug /t:Rebuild /p:platform=x86

