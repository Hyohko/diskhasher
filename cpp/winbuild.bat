call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\Tools\VsDevCmd.bat"

mkdir winbuild
cd winbuild

cmake -G "Visual Studio 16 2019" ..

REM Build Debug mode
msbuild .\dkhash.sln /p:Configuration=Debug;Platform=x64 /t:Rebuild /m

REM Build Release mode
msbuild .\dkhash.sln /p:Configuration=Release;Platform=x64 /t:Rebuild /m