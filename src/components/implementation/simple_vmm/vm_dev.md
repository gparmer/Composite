# VM Development Guide
## Branches

### Composite Hypervisor branch
Use this branch to develop hypervisor features:
https://github.com/betahxy/composite/tree/cos_vmx

### Linux VM branch
This is the stock Linux 5.15 used as the VM within Composite hypervisor
https://github.com/betahxy/vmx-linux-5.15.107

## How to build the system

### Build guest Linux VM

This Linux kernel source code is hacked a little bit at the booting stage because we would like to use our simplified guest bootloader to load the Linux image. We simpily added another booter in the code base under `arch/x86/vmxbooter/`. We also removed all other archtectural code except x86 to keep simplicity. Note that this new simple booter can also be booted by any multiboot2 compatible boot loader and then boot the Linux image. Thus, you can also directly use Qemu to boot this code base to test the Linux kernel code. 

- **Prepare the initramfs directory**

	The initfamfs directory is a ram disk used by the kernel to load the `init` user space process (the first process in the disk). We just need to create the directory and a `init.c` file within it and compile it.

	```c 
	// init.c
	#include <stdio.h>
	int main()
	{
		printf("Hello Initramfs in special bootloader!\n");

		sleep(10);

		return 0;
	}
	```
	```shell
	# Note that this needs to be statically compiled as it cannot include your host system's dependencies
	gcc -o init -static -s init.c
	```
	Within the directory we also need to create a virtual console device to enable the user space print something via console.
	```shell
	mkdir dev
	sudo mknod dev/console c 5 1
	sudo mknod dev/null c 1 3
	sudo mknod dev/random c 1 8
	sudo mknod dev/urandom c 1 9
	```

	That's it. Just leave this initramfs here and go to build the Linux kernel. You will then need to tell the Linux build system this directory and it will automatically include this initramfs. See the `CONFIG_INITRAMFS_SOURCE` keyword in the config file. You will finally see the output above in your terminal.
- **Build the stock Linux kernel**

	We need to build the Linux kernel as normal. We will disable a lot unused features and keep the kernel as simple as possible. Here we will use this `.config` file as it contains only the necessary features of the Linux kernel (just copy this file into the root directory of the code base once downloaded it). You can expand it as the hypervisor becomes more powerful. 

	In case that you would like to custimize the config file, here are the simple steps to config it.
	```shell
	# Use this first to generate a config file that disable all unused features
	make allnoconfig 
	# This will enable you to select features you want, note that we will want to enable serial output driver for debugging usage
	# We also enable the initramfs to be contained into the kernel so that the kernel can find the init process to go into user space
	make menuconfig
	```

	Then we would simply like to generate a Linux kernel image with the configuration above:
	```shell
	make
	```
	This will finally generate an ELF file called `vmlinux` in the root directory of the code base. We will then need to process it to make it a pure binary and put it into our customized boot loader.
	```shell
	cd arch/x86/vmxbooter/
	# This will generate a file called kernel.img 
	make
	```
	To test it in the Qemu, just do this in the `vmxbooter` directory :
	```shell
	make run
	```

### Build the Composite

- **Where is the hypervisor code**?

	There are three components to support vmx in Composite:

	1. `src/platform/x86_64/vmx`: this is the kernel support for vmx.
	2. `src/components/lib/vmrt`: this is the vm lib for user level manipulating vm operation in Composite.
	3. `src/components/implementation/simple_vmm`: this is a simple hypervisor implementation based on the vmrt.

- **Where is the VM (guest) image and how does Composite hypervisor load it**?

	The guest image consists of two parts: the guest bootloader and the guest Linux. Thus the hypervisor needs to load both of them and let the guest bootloader to find guest Linux and load it.

	Suppose we already compiled the vmlinux image, and it should be put here: `src/components/implementation/simple_vmm/vmm/guest/vmlinux.img`

	The guest bootloader is here: `src/components/implementation/simple_vmm/vmm/guest/guest_realmode.S`. It will then be compiled to this binary file: `src/components/implementation/simple_vmm/vmm/guest/guest.img`.

	Now we have both the `guest.img` (the guest bootloader) and the `vmlinux.img` (the stock Linux kernel image).

	The two guest images will then be included into the simple vmm component. 

	The hypervisor will then read these two images and load them into VM's virtual physical address page by page.

- **How to build the Composite hypervisor?**
	```shell
	./cos init x86_64
	./cos build
	./cos compose composition_scripts/simple_vmm.toml vm
	```
- **How to run the system?**
	```shell
	./cos run vm
	```

## Debugging

### Debugging the guest Linux in Composite

You can use the kernel's `printk` function to print information you want to know what is happening in the VM, for example:
```c
	printk(KERN_INFO "%s at %u in ()\n", __FILE__, __LINE__);
	pr_info("%s at %u in (%s)\n", __FILE__, __LINE__, __func__);
```

You can also use `vmcall` inside the linux kernel to force it out the VM:
```c
	asm volatile("vmcall");
```
This will cause VM exit and then you can do some hacking.

### Debugging the guest Linux in Qemu
Since it is in the Qemu, you can use either the print functions within the Linux kernel or GDB support by Qemu to hack the kernel.