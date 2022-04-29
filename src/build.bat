jwasm -bin -nologo -Fo virus64.bin /I "D:\wininc\Include" -10p -zf0 -W2 -D_WIN64 main_sc.asm
jwasm -bin -nologo -Fo virus32.bin /I "D:\masm32\include" -W2 main_sc.asm

rem python bin2asm.py