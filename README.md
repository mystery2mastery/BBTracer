# BBTracer

BBTracer is a [frida](https://frida.re/) (Dynamic Binary Instrumentation framework) based basic block execution tracer. Even though written specifically for Windows OS and malware analysis, it can be easily extended for other OSes that frida supports.

## How to use BBTracer:

### Generate Trace:

1. Install frida for python:

   ```cmd
   cmd> pip install frida-tools
   ```

2. Execute the program and collect the trace using:

   ```cmd
   cmd> BBTracer.py "C:\windows\system32\notepad.exe"
   ```

   ```cmd
   cmd> BBTracer.py "C:\windows\system32\rundll32.exe" "path\to\some.dll",someexport
   ```


3. Press `Ctrl+C` to stop the execution of the process and save the trace. Sometimes the script fails to terminate the process after .log file generation, in such cases you need to manually terminate the process.
3. The trace is collected and saved to `[out]bb_trace.log` file.

### Apply Trace: 

I wrote an IDC script [IDA_apply_bbtrace.idc](IDA_script_to_apply_bbtrace\IDA_apply_bbtrace.idc) to export the basic block trace into IDA. Since the script is written in .idc (IDC is embedded in IDA core), it can be used in IDA Free also.

1. Open the program you want to view the trace for in IDA Free or IDA Pro. 
2. Once the program is loaded, select `File -> Script file... -> IDA_apply_bbtrace.idc`
3. The script will ask you to select the .log file. Select the  `[out]bb_trace.log` file generated earlier.
4. You can see the executed blocks turned to green.
5. Also, all the basic blocks are printed in the `Output` window in the order of execution. You can click on an address and the corresponding block will be highlighted in the `Disassembly` window.

### Trace format:

The `[out]bb_trace.log` file contains the following:

```c
* ======================== HEADER START ========================= *
* Module_Name         	Module_Base 	Module_Size 	Module_Path
* -----------------------------------------------------------------
* MSCTF.dll           	0x1db8c6b0000	0x114000    	C:\Windows\System32\MSCTF.dll
* notepad.exe         	0x7ff6fb950000	0x38000     	C:\Windows\System32\notepad.exe
* efswrt.dll          	0x7ffb09260000	0xdd000     	C:\Windows\System32\efswrt.dll
* oleacc.dll          	0x7ffb15fd0000	0x66000     	C:\Windows\System32\oleacc.dll
* TextShaping.dll     	0x7ffb16e40000	0xac000     	C:\Windows\System32\TextShaping.dll
* textinputframework.dll	0x7ffb188f0000	0xf9000     	C:\Windows\SYSTEM32\textinputframework.dll
* MrmCoreR.dll        	0x7ffb1cec0000	0xf4000     	C:\Windows\System32\MrmCoreR.dll
* MPR.dll             	0x7ffb1e100000	0x1d000     	C:\Windows\System32\MPR.dll
... 
... <removed for brevity>
...
* combase.dll         	0x7ffb2d150000	0x354000    	C:\Windows\System32\combase.dll
* ADVAPI32.dll        	0x7ffb2d860000	0xaf000     	C:\Windows\System32\ADVAPI32.dll
* USER32.dll          	0x7ffb2d990000	0x19d000    	C:\Windows\System32\USER32.dll
* ntdll.dll           	0x7ffb2db70000	0x1f8000    	C:\Windows\SYSTEM32\ntdll.dll
* ========================= HEADER END ========================== *
[ntdll.dll] 0x526d0 , 0x526e3 [ntdll.dll]
[ntdll.dll] 0x526e3 , 0x526f1 [ntdll.dll]
[ntdll.dll] 0x8c780 , 0x8c79d [ntdll.dll]
[ntdll.dll] 0x8c79d , 0x8c7a3 [ntdll.dll]
... 
... <removed for brevity>
...
```

All the module info is present in between the HEADER section's START and END. Beyond the header section is the actual basic blocks collected from execution of the program.

#### Basic Block format:

```c
[ntdll.dll] 0x526d0 , 0x526e3 [ntdll.dll]
//module_name 'start_offset of basic_block' , 'end_offset of basic_block' module_name
```

The start and end addresses are relative to the module's base.

The HEADER information is NOT used by the `IDA_apply_bbtrace.idc` to apply the trace. The .idc file uses the info from above basic block lines. The script gets the currently loaded module name in IDA and goes through each line, checks the module name, extracts the basic blocks info and colors them accordingly. So, make sure that the module name is matching!

The basic blocks for ALL the modules that got executed are collected. This is intentional. There is no processing done on the JavaScript side. JavaScript side simply sends the modules info and basic blocks executed directly to Python side. All the processing is done on Python side. So, the tracing is very fast, almost instantaneous.

The basic blocks are collected and shown in the order of execution.

> Note: Since these are basic blocks, if a block gets executed multiple times, it is recorded only once (for the first execution only). So, if you are trying to use the basic block trace as substitute for instruction execution trace, it may not make complete sense.

## BBTracer in [Lighthouse](https://github.com/gaasedelen/lighthouse):

Lighthouse is a nice code coverage plugin for IDA Pro. Plugins with GUI are not supported by IDA Free. So, you MUST have IDA Pro to use Lighthouse plugin.

Lighthouse has nice feature to compare and contrast multiple coverage logs. Look at the [Coverage Shell](https://github.com/gaasedelen/lighthouse#coverage-shell) section for more info.

As per Lighthouse, it supports multiple coverage formats, unfortunately none of them worked for me as my `.log` format is different from [other coverage formats](https://github.com/gaasedelen/lighthouse/tree/master/coverage#other-coverage-formats) mentioned. The format closer to my requirement was [modoff](https://github.com/gaasedelen/lighthouse/tree/master/coverage#module--offset-modoff) but it was coloring only the first line of the basic block. So, I wrote a new parser ([bbtparser.py](custom_parser_for_lighthouse\bbtparser.py)) to support my custom `.log` format.

Go through [this](custom_parser_for_lighthouse\README.md) to know how to use my custom parser in lighthouse plugin.

## Limitations (if any):

1. This tracer is written specifically for malware analysis. So, I intentionally restricted it to trace only Primary/Main thread.
2. I wanted to capture full trace for malware analysis, so the script will always launch a new process and start collecting the basic blocks for all the modules.
3. Code executed from dynamically allocated locations (Ex: HeapAlloc, VirtualAlloc'ed blocks) don't belong to a specific module, so the basic blocks executed from these locations are collected with the module name [None]. For these blocks, absolute addresses are captured instead of relative offsets. However there is no such limitation on dynamically loaded modules.
