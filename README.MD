# kernel_payload_comms ⚡💻
The code is released under the MIT license. Bugs will be addressed as soon I've got time available if any are found, all the code in the repo was written in about a morning and an afternoon, so some oversights might be present. PRs are welcome. 🧐

## What is it?
This repository contains a proof of concept demonstrating communication via mapped shared memory structures between a user-mode process and a kernel-mode payload on Windows 10 20H2. The usermode component of this repository, [kdmapper](https://github.com/z175/kdmapper), was originally created by z195, kdmapper is a driver mapper that exploits a vulnerability in a signed intel driver to map a kernel payload and execute it. This project, however, *started* from a slightly modified version of [kdmapper](https://github.com/TheCruZ/kdmapper-1803-20H2) from TheCruZ. This project's kdmapper has also been largely refactored to follow the snake_case convention as closely as possible without, however, editing windows' structures.

## PoC's features
Now on to the actual proof of concept. This solution contains two projects: kdriver and kdmapper.

## kdmapper
This proof of concept's kdmapper is not like the ordinary one. It contains some extra features to aid in remaining stealthy and overall avoiding detection via traditional memory scans after the kernel payload has been mapped, namely:

- Kernel payload PE header randomization
- The vulnerable intel driver's removal from memory
- Extra parameters are passed to the entry point to make communication possible
- An entire comms namespace to setup and maintain communication with the kernel payload in the kdmapper namespace

## kdriver
kdriver is a driver that was specifically designed to work with this project's kdmapper. It takes the memory structure's virtual address in the kdmapper process' address space, takes its physical address, maps it and instaurates communication with the usermode process, making virtual memory read and write operations without a handle from/to the process you want to read and write frmo/to trivial. kdriver is designed to work as "driverless" without a PDRIVER_OBJECT assigned to it, therefore it is more of a payload than a proper driver. Mapped drivers have some limitations: for instance, they cannot be unloaded by simply stopping their service, since they don't have own (this is solved by simply jumping to ExFreePool in unmap.asm), PatchGuard (windows' kernel patch protection) won't let the payload register callbacks regularly and will cause the system to crash with a blue screen of death (bsod) in case the payload tries doing so. To get around the callbacks issue that may be needed to get other processes' modules, the utils.hpp file in the project comes in handy, implementing PEB walking. 

## Cases of use
This project can be used if, for any reason, it is necessary to conduct research on processes that may have had their memory protected by a driver in kernel-mode via a callback that strips handles to the process registered via ObRegisterCallbacks. It can also be easily re-worked to work as a .dll and, with a hooking library, ReadProcessMemory and WriteProcessMemory could be hooked, bringing back to life analysis tools that rely on usermode APIs for their functioning by re-writing the implementation of said APIs in the kernel payload. 

## Detection vectors
This project, as stealthy as it tries to be via very simple and straightforward methods, can easily be detected by anti-virus and anti-cheating solutions quite easily, it takes a few tricks to be able to map a kernel payload and go undetected which, unfortunately, I can't share on GitHub for ethical reasons. The methods via which detection could be achieved are, for example:

- System thread enumeration (We're starting a system thread with a start address that is not backed by any real module).
- Stackwalking (Even if the start address is spoofed either via DKOM or via code-caves, APCs can be issued to the thread, and the stack can be walked, revealing code execution in addresses that are not backed by any real module).
- MmUnloadedDrivers & PiDDBCacheTable (Unloading the intel driver is not stealthy at all, it will leave traces in the MmUnloadedDrivers array and in the undocumented PiDDBCacheTable linked list).
- The windows system evt logs (Unloading the intel driver will leave logs in there).

## Getting started.
- Install VS2019
- Install the WDK (Windows driver kit) + the WDK extension for VS2019
- Build as-is, release mode in x64 already has what needs set-up to build a working kdmapper payload (A custom entry point).
- Open a CMD prompt as admin.
- cd into the directory containing the files that were just built.
- Run `kdmapper.exe kdriver.sys`
