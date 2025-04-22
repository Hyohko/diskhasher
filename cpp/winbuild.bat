REM call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\Tools\VsDevCmd.bat"

call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"

mkdir winbuild
cd winbuild

cmake -G "Visual Studio 17 2022" ..

REM Build Debug mode
msbuild .\dkhash.sln /p:Configuration=Debug;Platform=x64 /t:Rebuild /m

REM Build Release mode
msbuild .\dkhash.sln /p:Configuration=Release;Platform=x64 /t:Rebuild /m