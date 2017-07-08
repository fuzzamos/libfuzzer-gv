all: libFuzzer.a

libFuzzer.a: FuzzerCrossOver.o FuzzerDriver.o FuzzerExtFunctionsDlsym.o FuzzerExtFunctionsDlsymWin.o FuzzerExtFunctionsWeakAlias.o FuzzerExtFunctionsWeak.o FuzzerExtraCounters.o FuzzerIO.o FuzzerIOPosix.o FuzzerIOWindows.o FuzzerLoop.o FuzzerMain.o FuzzerMerge.o FuzzerMutate.o FuzzerSHA1.o FuzzerShmemPosix.o FuzzerShmemWindows.o FuzzerTracePC.o FuzzerTraceState.o FuzzerUtil.o FuzzerUtilDarwin.o FuzzerUtilLinux.o FuzzerUtilPosix.o FuzzerUtilWindows.o
	ar r libFuzzer.a FuzzerCrossOver.o FuzzerDriver.o FuzzerExtFunctionsDlsym.o FuzzerExtFunctionsDlsymWin.o FuzzerExtFunctionsWeakAlias.o FuzzerExtFunctionsWeak.o FuzzerExtraCounters.o FuzzerIO.o FuzzerIOPosix.o FuzzerIOWindows.o FuzzerLoop.o FuzzerMain.o FuzzerMerge.o FuzzerMutate.o FuzzerSHA1.o FuzzerShmemPosix.o FuzzerShmemWindows.o FuzzerTracePC.o FuzzerTraceState.o FuzzerUtil.o FuzzerUtilDarwin.o FuzzerUtilLinux.o FuzzerUtilPosix.o FuzzerUtilWindows.o
	ranlib libFuzzer.a

FuzzerCrossOver.o: FuzzerCrossOver.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerCrossOver.cpp
FuzzerDriver.o: FuzzerDriver.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerDriver.cpp
FuzzerExtFunctionsDlsym.o: FuzzerExtFunctionsDlsym.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerExtFunctionsDlsym.cpp
FuzzerExtFunctionsDlsymWin.o: FuzzerExtFunctionsDlsymWin.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerExtFunctionsDlsymWin.cpp
FuzzerExtFunctionsWeakAlias.o: FuzzerExtFunctionsWeakAlias.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerExtFunctionsWeakAlias.cpp
FuzzerExtFunctionsWeak.o: FuzzerExtFunctionsWeak.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerExtFunctionsWeak.cpp
FuzzerExtraCounters.o: FuzzerExtraCounters.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerExtraCounters.cpp
FuzzerIO.o: FuzzerIO.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerIO.cpp
FuzzerIOPosix.o: FuzzerIOPosix.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerIOPosix.cpp
FuzzerIOWindows.o: FuzzerIOWindows.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerIOWindows.cpp
FuzzerLoop.o: FuzzerLoop.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerLoop.cpp
FuzzerMain.o: FuzzerMain.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerMain.cpp
FuzzerMerge.o: FuzzerMerge.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerMerge.cpp
FuzzerMutate.o: FuzzerMutate.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerMutate.cpp
FuzzerSHA1.o: FuzzerSHA1.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerSHA1.cpp
FuzzerShmemPosix.o: FuzzerShmemPosix.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerShmemPosix.cpp
FuzzerShmemWindows.o: FuzzerShmemWindows.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerShmemWindows.cpp
FuzzerTracePC.o: FuzzerTracePC.cpp FuzzerTracePC.h
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerTracePC.cpp
FuzzerTraceState.o: FuzzerTraceState.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerTraceState.cpp
FuzzerUtil.o: FuzzerUtil.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerUtil.cpp
FuzzerUtilDarwin.o: FuzzerUtilDarwin.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerUtilDarwin.cpp
FuzzerUtilLinux.o: FuzzerUtilLinux.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerUtilLinux.cpp
FuzzerUtilPosix.o: FuzzerUtilPosix.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerUtilPosix.cpp
FuzzerUtilWindows.o: FuzzerUtilWindows.cpp
	clang++ -Wall -c -g -O2 -std=c++11 FuzzerUtilWindows.cpp

clean:
	rm *.o libFuzzer.a

