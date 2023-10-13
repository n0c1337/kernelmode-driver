# kernelmode-driver
Kernel Driver for x64 Window System which allows you to read/write Virtual/Physical Memory hooking Win32k

## Info:
- I tried to keep the project as clean as possible so I adapted Microsoft Syntax for 
Kernel Mode functions [KE](https://learn.microsoft.com/de-de/windows-hardware/drivers/ddi/wdm/nf-wdm-kesetsystemaffinitythreadex)
- Mostly used "conventional" data types like void* instead of "typedef" data types like PVOID 
- Why am I releasing this? I'm currently rewritting the whole Driver in Rust
