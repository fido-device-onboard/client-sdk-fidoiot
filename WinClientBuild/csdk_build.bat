call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" x86
#call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x86
msbuild WinClientBuild.sln /p:MyConstants="SELF_SIGNED_CERTS_SUPPORTED" /p:configuration=debug /t:Rebuild /p:platform=x86