# TOCTOU-disabled
### 
We highly recommend reading the scientific article before diving into this report!

Following, there is a list of instructions and broad guidelines on how to compile, run and test TOCTOU-disabled. Depending on the board used for this evaluation, on the programming environment and the tools used, the behaviour of this implementation might change. 

**Disclaimer**: *The following is a working proof of concept. There might be bugs and inconsistencies which were not addressed. Furthermore, the code might damage your MCU board, erasing its memory or degrading its hardware. Use it at your own risk, we do not assume any responsibility for the use of this code, or for the damage it can cause.*

## Folders Description
- `UpdateApplication/`: this folder contains all of the required files for compiling a single application for TOCTOU-disabled. Specifically, it should be populated with the source files of the application.
    - `Makefile`: makefile for compiling the application to be deployed. The result is a file `deployable.out` which is ready for deployment.
    - `src/`: this folder should contain all of the source files of the user application to be compiled (both '.c' and '.s' files). 
- `TCM/`: this folder contains the source code of TOCTOU-disabled TCM. Morevoer, it contains the source files of a user application (untrusted) that can be deployed alongside it without going over remote update.
    - `Makefile`: makefile for compiling both the untrusted application and the core of TCM. The result is the file `deployable.out` which is ready to be deployed on the MCU.
    - `app/`: folder containing all of the files required for the compilation of the untrusted application
        - `src/`: folder containing all of the source files, both '.c' and '.s' of the untrusted application
        - `Makefile.include`: makefile to be included, containing some directives for the compilation of the application by the main Makefile
    - `core/`: folder containing all of the files required for the TOCTOU-disabled compilation.
        - `src/`: folder containing all of the source files, both '.c' and '.s' of TOCTOU-disabled.
            - `core.c|.h`: file containing the source code for the main TOCTOU-disabled functions. It is usually used in Measurement stage and Runtime evidence collection .
            - `virt_fun.s`: assembly file containing the definitions of the various trampoline functions. It is usually used in Measurement stage.
            - `virt_fun_withoutMeasurement.s`: version without Measurement.
            - `protected_isr.s`: assembly file containing the protected Interrupt Service Routines for the secure interrupt management.
            - `secureContextSwitch.c|.h`: source files for the secure context switch operations which allow the backup and restoration of the RAM, or any other hook operation during a safe context switch.
            - `RAhook.h`: header file needed by the application (needs to be included in the source files with the '#include' directive) in order to setup for receiving challenges and a function notifying Vrf when app is stopped. This file get automatically copied to the `app/src/` directory of the application.
        - `ext_modules/`: folder containing the source files of the various extensions. These files are copied in the `core/src/` folder by the makefile if specified.
            - `KeyGen.c|.h`: source file for the address-key generatation used in call\ret trampoline functions.
            - `secureUpdate.c|.h`: source file for the secure update over serial communication. It is usually used in Measurement stage.
            - `XorCompute.c|.h`: source files for the Xor computation to collect control flow evidence.
            - `sha256_msp430.c|.h`: source files for the hash computation to collect control flow evidence.
            - `secureValue.c|.h: source files for the memory read instructions to collect data read evidence.
            
        - `Makefile.include`: makefile to be included, containing some directives for the compilation of the TCM by the main Makefile
- `toolchain/`: folder containing all of the scripts required by the makefile and the deployment process
    - `linkerScript.ld`: modified linker scripts containing the directives for the linker when compiling ONLY the application. Used exclusively by the Makefile.
    - `linkerScriptWithCore.ld`: modified linker scripts containing the directives for the linker when compiling both the application and the TCM. Used exclusively by the Makefile.
    - `loadProgram.py`: python script used to load the program onto the MCU via UART interface (serial port), in compliance with the TOCTOU-disabled secure update protocol.
    - `metadata.py`: python script in charge of adding the required metadata to the output file. Used exclusively by the Makefile.
    - `modifier.py`: python script in charge of replacing unsafe instructions. Used exclusively by the Makefile.
    - `postprocessor.py`: python script in charge of rejecting the application in case of unsafe instructions (compile-time). Used exclusively by Makefile.
    - `ReceiveData.py`: python script in charge of receiving the measurement result from Prv. 
    - `Send.py`: python script in charge of sending challenge from Vrf to Prv.
    - `database_verify.py`: python script to verify the measurement result. Checking whether the result from Prv are matching with the Vrf local database.
    - `gccLibraries/`: contains all of the statically linked libraries used by GCC and adapted to our toolchain (insertion of NOP slides and reserved registers). The `*.small` files inside refer to libraries using ret and call instead of reta and calla.
        - `libcrt.a`: statically linked library of gcc, compiled from the gcc source folder with the instrumented file `newlib/libgloss/msp430/crt0.S|crt_bss.S` which generates the compiled file `msp430-elf/large/full-memory-range/libgloss/msp430/libcrt.a`. The new file must be placed in `compilerGCCRoot/msp430-elf/lib/large/full-memory-range`. **crt0_movedata** and **crt0_init_bss** have been instrumented (adding the NOP slides). Others, such as call_main and call_exit are not but we should not need them.
        - `libgcc.a`: statically linked library compiled with a modified makefile (to prevent use of reserved registers '*-ffixed-r4 -ffixed-r5 -ffixed-r6*') `sourceGCC/gcc/libgcc/Makefile.in` yielding the file `build/gcc/msp430-elf/large/full-memory-range/libgcc/libgcc.a` to be placed in `compilerGCCRoot/lib/gcc/msp430-elf/9.2.0/large/full-memory-range`
        - `libnosys.a` and `libsim.a`: statically compiled files obtained from the modified makefile (to prevent use of reserved registers '*-ffixed-r4 -ffixed-r5 -ffixed-r6*') `sourceGCC/newlib/libgloss/msp430/Makefile.ini` yielding the files `build/gcc/msp430-elf/large/full-range-memory/libgloss/msp430/libnosys.a|libsim.a`. To be placed in `compiler//msp430-elf/lib/large/full-memory-range`
        - `libc.a`: statically linked library compiled with a modified makefiles (to prevent use of reserved registers '*-ffixed-r4 -ffixed-r5 -ffixed-r6*') `sourceGCC/newlib/newlib/libc/string/Makefile.in`,`sourceGCC/newlib/newlib/libc/string/Makefile.in`,`sourceGCC/newlib/newlib/libc/string/Makefile.in`  yielding the file `build/gcc/msp430-elf/large/full-memopry-range/newlib/libc.a`. 
        The new file must be placed in `compiler/msp430-elf/lib/large/full-memory-range`
    - `helperScripts/`: contains all of the scripts that are helpful in the creation of a proper application image
        - `auxGccPaser.py`: python script that parses a portion of mspdump code and performs the following operations:
            - Format the files to assembly standard.
            - Locates the relevant functions and labels, renaming them so that they can be compiled.
            - Replaces all of the jumps offsets, branches arguments and calla destinations with the correct label so that they can be relocated.
        - `getSizeData.py`: compiles every single test application and retrieves the size info of the various files.
        - `objToHex.py`: python script that parses an object file - created by the `metadata.py` script with the 'debugFiles' set to true - and outputs its content byte by byte so that it can be used in an `injectData.c` source file. 
        - `powerConsumption/`: contains all of the scripts for getting the battery consumption with its graphs.
            - `Battery.java`: simulates the battery consumption at various execution rates.
            - `getConsumptions.sh`: script to get all of the power measures via the java script.
            - `getGraph.py`: script to generate graphs for the power measures obtained with the above script.    
    - `compiler/`: contains the various compilers used by TOCTOU-disabled, with some compilation libraries and some backups.
        - `include_gcc/`: contains some of the includes files required by the compiler and provided by TI.
        - `msp430-gcc-9.2.0.50_linux_instrumented/`: contains the instrumented GCC compiler used by TOCTOU-disabled.
        - `msp430-gcc-9.2.0.50_linux64_original/`: contains the origin GCC compiler used by TOCTOU-disabled.
    - `symbolic_exe/`: contains the angr symbolic execution used by TOCTOU-disabled.
        - `DF_attack_global/`: contains source file and binary file which does not inject DF attack.
        - `DF_attack_local/`: contains source file and binary file which does not inject DF attack.
        - `symbolic_exe.py`: angr symbolic execution script to analyze binary file.
        
- `App/`: folder containing all of the test applications used during the evaluation of the proposed TOCTOU-disabled implementation.
    - `ACFA_modified_app/`: instrumented and correctly working
    - `attack_app/`: instrumented and correctly working
    - `Bitcount/`: instrumented and correctly working
    - `CopyDMA/`: instrumented and correctly working. The Application copies the content of the flash into RAM with memcpy and with the DMA. In both cases, it checks whether the result is correct. The DMA triggers an interrupt when finished.
    - `DIALED_modified_app/`: instrumented and correctly working
    - `F5529-serial/`: instrumented and correctly working
    - `OAT_modified_app/`: instrumented and correctly working
    - `SerialMSP/`: instrumented and correctly working
    - `SpecCFA/`: instrumented and correctly working
    - `XorCypher/`: instrumented and correctly working
    - `Verify&Revive_modified/`: instrumented and correctly working
    - `TiBenchmark/`: folder containing all of the benchmark applications used by TI and during the evalution of the proposed TOCTOU-disabled implementation.
        - `matrixMultiplication/`: instrumented and correctly working.
        - `floatingPointMath/`: instrumented and correctly working.
        - `firFilter/`: instrumented and correctly working.
        - `8bitSwitchCase/`: instrumented and correctly working.
        - `16bitSwitchCase/`: instrumented and correctly working.
        - `8bitMath/`: instrumented and correctly working.
        - `16bitMath/`: instrumented and correctly working.
        - `32bitMath/`: instrumented and correctly working.
        - `8bit2dimMatrix/`: instrumented and correctly working.
        - `16bit2dimMatrix/`: instrumented and correctly working.
        - `DMA/`: instrumented and correctly working.
- `clang_app/`: folder containing all of the test applications' `.bc` form used during the `Collecting input set of untrusted application` step.
- `frama-c/`: folder containing files used during the verification for the code of TOCTOU-disabled implementation.
- `nuXmv/`: folder containing files used during the verification for the security property of TOCTOU-disabled implementation.


## Pre requisites
- **linux**: build-essential python3 pip3
- **pip3**: pyserial [matplotlib] [pandas]
- MSP430F5529 board with USB cable (we use a MSP-EXP430F5529LP)
- Code Composer Studio with msp430 libraries [official link](https://www.ti.com/tool/CCSTUDIO)
- nuXmv for verify security property of TOCTOU-disabled
- Frama-c for verify code of TOCTOU-disabled
- KLEE for TOCTOU-disabled input set symbolic exection
- Clang 13+ for compiling application to `.bc` file 
- Angr for TOCTOU-disabled memory read variable valid ranges symbolic exection
- (optional) MSP430 debugger (e.g. MSP430F5529Launchpad version) [board link](https://www.ti.com/tool/MSP-EXP430F5529LP)
- (optional) Java for the execution of powerConsumption measurement scripts.

## Original APP
In order to generate original application's unmodified binary, please copy `.c` file to a new build folder and execute the following commands in sequence:
- `path_to_original_gcc/bin/msp430-elf-gcc-9.2.0 -c -mmcu=msp430f5529 -mhwmult=f5series -I"../toolchain/compiler/include_gcc" -I"." -I"path_to_original_gcc/msp430-elf/include" -O3 -w -mlarge -mcode-region=none -mdata-region=none -ffixed-R4 -ffixed-R5 -ffixed-R6 -ffixed-R8 -Wl,--gc-sections -Wl,--no-relax -Wl,--disable-sec-transformation -S -ffunction-sections -o"*.s" "*.c"`(in this step please replace `*.c` and `*.s` with your app)
- `path_to_original_gcc/bin/msp430-elf-gcc-9.2.0 -c -mmcu=msp430f5529 -mhwmult=f5series -I"../toolchain/compiler/include_gcc" -I"." -I"path_to_original_gcc/msp430-elf/include" -O3 -w -mlarge -mcode-region=none -mdata-region=none -ffixed-R4 -ffixed-R5 -ffixed-R6 -ffixed-R8 -Wl,--gc-sections -Wl,--no-relax -Wl,--disable-sec-transformation -ffunction-sections -o"*.o" "*.s"`(in this step please replace `*.s` and `*.o` with your app)
- `path_to_original_gcc/bin/msp430-elf-gcc-9.2.0 -mhwmult=f5series -mmcu=msp430f5529 -O3 -w -mcode-region=none -mdata-region=none -mlarge -Wl,-Map,"deployable.map" -Wl,--gc-sections -L"../toolchain/compiler/include_gcc" -Wl,--no-relax -Wl,--disable-sec-transformation  -T"../toolchain/compiler/include_gcc/msp430f5529.ld" -Wl,--start-group -lgcc -lc -Wl,--end-group -o"deployable.out" *.o -Wl,--whole-archive `


if you don't want to use these commands to compile original binary, please use Code Composer Studio(ccs) to do it, and ensure that the compilation options are consistent with the above commands. For the use of Code Composer Studio(ccs), please refer to the official website of TI.[official link](https://www.ti.com/tool/CCSTUDIO)

## Collecting input set of untrusted application
In order to collect input set of untrusted application, please `cd clang_app` and use `clang-13 -emit-llvm -c -g your_program.c -o your_program.bc` and `klee your_program.bc` for get the input set. The result will be found in `klee-last/` and use `ktest-tool klee-last/test00000*.ktest` to check the input set. 

## Collecting variable valid ranges of application
In order to variable valid ranges of untrusted application, please `cd toolchian/symbolic_exe` and use `python3 symbolic_exe.py your_program.out` for getting variable valid ranges. The result will be found in `toolchian/symbolic_exe/database-DF.txt`. 

## Loading TOCTOU-disabled TCM (with the default untrusted application)
In order to secure the microcontroller, the TCM (i.e. the root of trust for our architecture) needs to be loaded before any other program. The folder `TCM/` contains all of the required files for the compilation of TOCTOU-disabled TCM. Although it is possible to also load an untrusted application right away, to be loaded with the TCM, currently the toolchain does not fully support it. The first initialisation should be perfomed with the default application. 
The following steps must be performed:
- (optional) Copy all of the required untrusted application's source files inside the `TCM/app/src/` folder. The default application only calls the *receiveUpdate()* function from the RAhooks to initiate a secure update. If such function is not required, or the secureupdate module is not loaded, it should be changed. If no application is loaded, the default one will be. This will initiate a secure update and thus wait for any deployable on the UART communication.
- (optional) Modify the `TCM/Makefile` file to update the binaries paths. By default the toolchain will use the self-contained compiler in this repository.
- Generate the secure deployable image of the TCM using the `make` command from inside the `TCM/` folder. This will generate a `deployable.out` binary (if curious, you can check it with *readelf* to see how it is structured).
- Load the `TCM/deployable.out` image on the device, e.g. using Code Composer Studio 'load' function. If everything was loaded correctly, you should see the following:
    1. The red LED blinks 10 times
    2. The red LED turns on for verification (a few seconds)
    3. The green LED turns on --> ready for incoming updates
- You can also reset the board to start the verification from the beginning.


If you see any other combination of LED check section "LED Signals" for debugging.


## Measurement
In order to get Vrf local database, The following steps must be performed:
- Change the version of `virt_fun.s` to Mearsurement version. In `TCM/core` folder, modify the correct version of each module to be loaded into the TCM in `Makefile.include` file.
- Use input set in `Collecting input set of untrusted application` step and Generate the secure deployable image of the TCM using the `make` command from inside the `TCM/` folder. This will generate a `deployable.out` binary.
- Load the `TCM/deployable.out` image on the device, e.g. using Code Composer Studio 'load' function. 
- Under `toolchain/` path, execute the `python3 Send.py` command. This comman will open serial port and notify Prv to start application's execution. And then use `python3 ReceiveData.py`, this will open serial port and wait for coming data from Prv.
- After receiving data from Prv, the file `data.txt` wili be created in `toolchain/` folder, this file contains the measurement result of Prv.

## Runtime evidence collection
In order to get Prv runtime evidence, The following steps must be performed:
- Change the version of `virt_fun.s` to runtime version. In `TCM/core` folder, modify the correct version of each module to be loaded into the TCM in `Makefile.include` file.
- Generate the secure deployable image of the TCM using the `make` command from inside the `TCM/` folder. This will generate a `deployable.out` binary.
- Load the `TCM/deployable.out` image on the device, e.g. using Code Composer Studio 'load' function. 
- Under `toolchain/` path, execute the `python3 Send.py` command. This comman will open serial port and notify Prv to start application's execution.
- Under `toolchain/` path, modify the `Send.py` and choose one challenge to send.(more challenge details will be found in this script) After that, execute the `python3 Send.py` command. This command will open serial port and call API for sending evidence we want to Vrf(The default content of file will notify Prv to start appliaction's execution). 
- Under `toolchain/` path, execute the `python3 ReceiveData.py` command. This command will open serial port and wait for coming data from Prv.
- After receiving data from Prv, the file `data.txt` wili be created in `toolchain/` folder, this file contains the runtime evidence of Prv.

## Verify
In order to Verify Prv runtime evidence, The following steps must be performed:
- Under `toolchain/` path, execute the `python3 database_verify.py` command. This command will ask for two files to get start to CF verify and ask for three files to get start to DF verify. If you have finished **Measurement** and **Runtime evidence collection**, please give two files you got to this script and wait for matching CF result. If you have finished **Collecting variable valid ranges of application** , **Measurement** and **Runtime evidence collection**, please give three files you got to this script and wait for matching DF result.  More detalis please use `python3 database_verify.py -h` to check.

## Attestation with hash function
We also provide hash function to assist Control flow attestation(its implementation is under `TCM/core/ext_modules/sha256_msp430.c|.h` and `TCM/core/src/virt_fun_hash.s`), if you wanna use hash function instead of Xor compute, please carry out the following steps:
- Modify the components in `TCM/core/Makefile.include`
- In `TCM/` folder, use command `make` to get the map file 
- Modify the various `virt_fun` addresses in `core.h` and `core.c` with map file 
- Modify the address of `virt_fun` in the `toolchain/linkerScriptWithCore.ld` file with map file 
- Modify the address of `virt_fun` in the `toolchain/modifier.py` file with map file 
- Modify the address of API in `TCM/core/src/RAhook.h` with map file 
- Modify the address of API check address in `toolchain/postprocessor.py` file with map file 
- Finally In `TCM/` folder, use command `make` to get the bianry of use Hash function and re-deploy this TCM binary with ccs on MSP430F5529LP.

## Applications updates / Remote deployments
### Compiling the update/application 
In order to securely deploy an application via TOCTOU-disabled, a properly crafted update must be compiled. To automate this process, TOCTOU-disabled offers the folder `UpdateApplication/` which contains the Makefile that must be used. Precisely, the following steps are required to compile the untrusted update:
- Copy all of the source files of the application ('*.c' and '*.s') to the `UpdateApplication/src/` folder. If the folder does not exist it should be created. These are the files that will be compiled.
- Execute the `make` command. This will generate the first executable `deployable.out`. 
- Execute the `make libraries` command to generate some helper files for the instrumentation of the standard library code (check section "Library instrumentation" for more details).
- Execute the `make clean && make` command to generate the final executable `deployable.out` containing the instrumented code for both the application and the standard libraries used by it. NB: this executable is not an ELF file because it contains extra metadata added for TOCTOU-disabled. To check the original ELF file you can inspect `appWithoutMetadata.out`.
- Proceed with the deployment



### Deploying untrusted update
An application update can only be performed if the MCU is in the receiving update state (see Section **LED signals**). In order to enter this state, the running program must call the `callReceiveUpdate()` function from the `RAhook.h` header file (as is the case when loading the TCM with the default application). When the MCU is ready to receive the update execute the `/toolchain/loadProgram.py` python script, passing as arguments the final application binary (e.g. `deployable.out`) and the serial port name (e.g. `/dev/ttyACM1` on Linux or `COM4` on Windows). NB: The serial port might change across executions or systems, please check the serial ports available on your system (especially those that become available as soon as the MCU board is plugged through the USB port).

If the serial port is correct, the script will start uploading the various chunks of the application, waiting for some acknowledgments. As soon as the upload is finished, the script will output a *File sent* to the terminal and the TCM will begin its deployment operations.
As soon as the TCM receives the image it will verify it. If the image is verified with success and the binary does not contain unsafe code (as should be the case if properly compiled using DFA-disabled TOCTOU-disabled toolchain), then it should be waitting for challenge from Vrf and start launch application after receive challenge. Sending challenge is also in this script and send a challenge after send application binary.
If the image is verified with falied, the TCM will restart the update process and wait for another valid image. 


Be aware that the code in this repository is compatible with the MSP430 family of microcontroller. However, the code, along with some of the toolchain components, needs to be updated to work with anything different than an MSP430f5529 MCU.


## LED signals
The following table shows the current TOCTOU-disabled' usage of the various LEDs.

| Green LED | Red LED | Description |
| --------- | ------- | ----------- |
|   ON      | OFF     | The TCM is waiting for an income update or The TCM gets control from APIs     |
|   ON      | ON      | *reserved*       |
|   OFF     | OFF     | Application started       |
|   OFF     | ON      | Verification of code in progress       |
|   OFF     | blink*10      | MCU has been reset, starting secure boot       |




# Technical details
## Memory Map
|Address|Name|Description|
|------|-----|-----------|
|0x000-fff|MMIO|Registers for pheripherals|
|0x1000-17ff|BSL| BSL |
|0x1800-19ff|Information Memory|Hardware info used for calibration of the board|
|0x1c00-2aff|TCM Ram|Ram used by TOCTOU-disabled Trusted Applications|
|0x2c00-43ff|App RAM|Ram used by the untrusted application |
|0x4400-c3ff|App Code|Where the untrusted yet verified code of the application resides|
|0xc400-f7ff|TCM code|Code of the TCM|
|0xf800-fbff|TCM Secure ISRs|Trampoline for App ISRs. Each entry will load the right App ISR pointer|
|0xfc00-ff7f|TCM trampoline functions|Trampoline for indirect control flow event and memory write/read event|
|0xff80-ffff|TCM ISRs trampoline|Trampoline for TCM ISRs. Interrupts will trigger a lookup of this table, which will lead to the TCM Secure ISRs entries.|
|0x10000-101ff| TCM backup data|Where the PC and status register are saved during interrupts |
|0x10200-103ff| TAs backup data|Where the CPU context (i.e. the registers) are saved during interrupts of TAs|
|0x10400-105ff| App ISRs | Where the app stores the pointers to the ISRs. Each entry stores the address of the APP ISR|
|0x10600-143ff|TCM code|Code of the TCM|
|0x14400-1c3ff|App RoData| Read Only data for the application|
|0x1c400-243ff|Reserved|Used for incoming data|
