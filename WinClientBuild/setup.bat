REM Generte Keys
call keys_gen.bat .

REM Copy keys and other required files in C:\ProgramData\Intel\FDO\data folder
mkdir C:\ProgramData\Intel\FDO\data
copy  data\ C:\ProgramData\Intel\FDO\data