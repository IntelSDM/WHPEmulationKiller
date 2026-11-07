# WHPEmulationKiller
Built for LLVM 19.1 - Windows x64 <br> <br>
[Windows Hypervisor Platform](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform) Is a commonly used system for either environment emulation, CPU emulation, and as a symbolic executors' backend. These types of emulators have become increasingly more common due to the misconception that WHP is essentially the Hyper-V shipped on HVCI. Hyper-V in itself is known as easily one of the best hypervisors implementations due to the sheer capability of HVCI and its awareness of most errata based attacks; and therefore its use in production.<br>
The reality for WHP is very different, its a full virtual machine which isn't aware of execution environment, Isn't aware of any erratas, and simply doesn't even set up CPUID properly! <br>
This over confidence is what we exploit here. The expectation that WHP is functionally the same as HVCI Hyper-V is what has given a recent rise in people using it for reverse engineering projects. <br>

Conventionally WHP is not useful for reverse engineering any self defending application.  Its use case is very clearly made for automated malware analysis where doing such CPUID and Hypervisor attestation would get you detected on heuristics. <br>
WHP does have support for custom VMExit handling, this can prevent this form of attack, but its still environment unaware. Handling the VMExit conditions manually simply isn't worth it when production hypervisors already do so without requiring you to have a signed custom driver for interacting with WHP. <br>
Simply put WHP is so flawed, it doesn't make sense to handle 1000s of erratas in custom VMExit handling. Use any other production hypervisor and build the symbolic execution side yourself, its much easier than making WHP genuinely undetected to basic anti emulation. <br>
WHP's intended usage was never reverse engineering, it was in production secure and safe symbolic execution for anti malware purposes.

## The Attack
The CPUID [hypervisor feature leaves "0x40000000 - 0x4000000A"](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery) tells us what the hypervisor's actual feature set is. <br>
On a normal machine it will be 0ed out, but the hypervisor present and hypervisor vendor name will be that of bre metal. <br>
WHP will set the hypervisor present bit to 1, it will set the hypervisor name to “Microsoft Hv”; It then populates the following in an impossible configuration for a legitimate hyperv machine:
* 0x40000003.EDX[27] : 0 
* 0x40000003.EAX bits 1-5 : 1
* 0x40000004.EAX : Nonzero
* 0x40000005.EAX : Nonzero
* 0x40000006.EAX bits 0+3 : 1
* QueryPerformanceFrequency is always 10000000
* KUSER_SHARED_DATA[0x3C7] : 1
* KUSER_SHARED_DATA[0x308] : Nonzero

Setting up an impossible environment as it is simply refusing hypervisor functionality or Windows system functionality that would be available on a normal Hyper-V machine. <br>
So we know the real possible Hyper-V values, the WHP's values will be incorrect, so by checking the 0x40000000 for “Microsoft Hv” and decrypting our constants against the known values in the CPUID registers and KUSER_SHARED_DATA, we can make the symbolic executors using a WHP backend spit out impossible values. <br>

<img width="1968" height="504" alt="image" src="https://github.com/user-attachments/assets/29bf8da0-73e3-423c-8192-92fb746a1011" />

<img width="480" height="52" alt="image" src="https://github.com/user-attachments/assets/0ef1102a-a5f3-42ea-b157-037bd659fc51" />

As you can see v54 is now an encryption key to decrypt the constants in the binary, By simply xoring with it we can do very lightweight anti emulation binary wide.

## Annotations
```c
__attribute__((annotate("whpkill")))
``` 
* Applies protection to constants to prevent their emulation in WHP environments

## How To Build
* Download [LLVM 19.1](https://github.com/llvm/llvm-project/releases/tag/llvmorg-19.1.0)
* Download [VCPKG](https://github.com/microsoft/vcpkg)
* VCPKG install asmjit
* Open build.bat in a text editor.
* Find the LLVM 19.1 references in the command line, Change them to your file path.
* Find the VCPKG references in the command line, Change them to your file path.
* Run the build script
* Build your application with the ``` -load-pass-plugin ``` Param to the FunctionPass.dll
