set INCLUDE_PATH=C:\TCC\INCLUDE
set LIB_PATH=C:\TCC\LIB
set PATH=C:\TCC\BIN

rem Extract the filename without extension from the parameter

rem Compile the C file to an .obj file
tcc -I%INCLUDE_PATH% -c -mt %1.c
tcc -I%INCLUDE_PATH% -S -mt %1.c

rem Link the .obj file to create a .com file
tlink -t -L%LIB_PATH% %LIB_PATH%\c0t.obj %1.obj ,%1.com,%1.map,%LIB_PATH%\cs.lib

exit
