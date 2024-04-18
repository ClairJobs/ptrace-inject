#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <wait.h>

#include "utils.h"
#include "ptrace.h"

/*
 * injectSharedLibrary()
 *
 * This is the code that will actually be injected into the target process.
 * This code is responsible for loading the shared library into the target
 * process' address space.  First, it calls malloc() to allocate a buffer to
 * hold the filename of the library to be loaded. Then, it calls
 * __libc_dlopen_mode(), libc's implementation of dlopen(), to load the desired
 * shared library. Finally, it calls free() to free the buffer containing the
 * library name. Each time it needs to give control back to the injector
 * process, it breaks back in by executing an "int $3" instruction. See the
 * comments below for more details on how this works.
 *
 */

void injectSharedLibrary(long mallocaddr, long freeaddr, long dlopenaddr)
{
	//   这里是我对目标执行此代码时数据将位于何处的假设
	//   rdi = address of malloc() in target process
	//   rsi = address of free() in target process
	//   rdx = address of __libc_dlopen_mode() in target process
	//   rcx = size of the path to the shared library we want to load

    // 保存free()和__libc_dlopen_mode()的地址在栈上，以便稍后使用
	asm(
        // rsi将包含free()的地址。它会在调用malloc()时被清除，
        // 所以先将它保存在栈上以备后用
        "push %rsi \n"
        // 对于rdx也是同样，它将包含_dl_open()的地址
        "push %rdx"
    );

    // 在目标进程中调用malloc()
	asm(
        // 保存r9的旧值，因为我们将使用它来调用malloc()
        "push %r9 \n"
        // 现在将malloc()的地址移动到r9
        "mov %rdi,%r9 \n"
        // 根据通过rcx传递的共享库路径的大小，选择要分配的内存量
        "mov %rcx,%rdi \n"
        // 现在调用r9; malloc()
        "callq *%r9 \n"
        // 从malloc()返回后，从栈上弹出r9的旧值
        "pop %r9 \n"
        // break，以便我们可以看到malloc()返回了什么
        "int $3"
    );

    // 调用__libc_dlopen_mode()来加载共享库
	asm(
		// get the address of __libc_dlopen_mode() off of the stack so we can call it
		"pop %rdx \n"
		// as before, save the previous value of r9 on the stack
		"push %r9 \n"
		// copy the address of __libc_dlopen_mode() into r9
		"mov %rdx,%r9 \n"
		// 1st argument to __libc_dlopen_mode(): filename = the address of the buffer returned by malloc()
		"mov %rax,%rdi \n"
		// 2nd argument to __libc_dlopen_mode(): flag = RTLD_LAZY
		"movabs $1,%rsi \n"
		// call __libc_dlopen_mode()
		"callq *%r9 \n"
		// restore old r9 value
		"pop %r9 \n"
		// break in so that we can see what __libc_dlopen_mode() returned
		"int $3"
	);

	// 调用free()来释放我们之前分配的缓冲区。
    // 注意：发现如果在r9中放入一个非零值，free()似乎会
    // 将其解释为要释放的地址，即使它只应该取一个参数。
    // 因此，我不得不使用不作为x64调用约定的一部分的寄存器来调用它。
    // 我选择了rbx。
	asm(
		// at this point, rax should still contain our malloc()d buffer from earlier.
		// we're going to free it, so move rax into rdi to make it the first argument to free().
		"mov %rax,%rdi \n"
		// pop rsi so that we can get the address to free(), which we pushed onto the stack a while ago.
		"pop %rsi \n"
		// save previous rbx value
		"push %rbx \n"
		// load the address of free() into rbx
		"mov %rsi,%rbx \n"
		// zero out rsi, because free() might think that it contains something that should be freed
		"xor %rsi,%rsi \n"
		// break in so that we can check out the arguments right before making the call
		"int $3 \n"
		// call free()
		"callq *%rbx \n"
		// restore previous rbx value
		"pop %rbx"
	);

	// 我们已经在这个函数的末尾覆盖了RET指令
    // 用一个INT 3，所以此时注入器将重新控制
    // 目标的执行。
}

/*
injectSharedLibrary_end()
这个函数的唯一目的是与injectSharedLibrary()相连，
以便我们可以使用它的地址来更精确地确定
injectSharedLibrary()的长度。
*/

void injectSharedLibrary_end()
{
}

int main(int argc, char** argv)
{
	if(argc < 4)
	{
		usage(argv[0]);
		return 1;
	}

	char* command = argv[1];
	char* commandArg = argv[2];
	char* libname = argv[3];
	char* libPath = realpath(libname, NULL);

	char* processName = NULL;
	pid_t target = 0;

	if(!libPath)
	{
		fprintf(stderr, "can't find file \"%s\"\n", libname);
		return 1;
	}

	if(!strcmp(command, "-n"))
	{
		processName = commandArg;
		target = findProcessByName(processName);
		if(target == -1)
		{
			fprintf(stderr, "doesn't look like a process named \"%s\" is running right now\n", processName);
			return 1;
		}

		printf("targeting process \"%s\" with pid %d\n", processName, target);
	}
	else if(!strcmp(command, "-p"))
	{
		target = atoi(commandArg);
		printf("targeting process with pid %d\n", target);
	}
	else
	{
		usage(argv[0]);
		return 1;
	}

	// 注入准备
	int libPathLength = strlen(libPath) + 1; //计算库路径字符串的长度，加1以包括终止字符 '\0'

	int mypid = getpid();					//获取当前进程的进程ID（PID）。
	long mylibcaddr = getlibcaddr(mypid);	//获取当前进程的 libc 库的基址

	// 在此进程中（即非目标进程）找到想要在目标中使用的系统调用的地址

	long mallocAddr = getFunctionAddress("malloc"); //获取当前进程中 malloc 函数的地址
	long freeAddr = getFunctionAddress("free");		//获取 free 函数的地址
	long dlopenAddr = getFunctionAddress("__libc_dlopen_mode"); //__libc_dlopen_mode这个函数用于动态加载共享库

	// 使用libc的基地址来计算想要使用的系统调用的偏移量
	long mallocOffset = mallocAddr - mylibcaddr; //计算相对libc基址的偏移
	long freeOffset = freeAddr - mylibcaddr;
	long dlopenOffset = dlopenAddr - mylibcaddr;

	
	// 获取目标进程的libc地址，并使用它来找到目标进程中使用的系统调用的地址
	long targetLibcAddr = getlibcaddr(target);
	long targetMallocAddr = targetLibcAddr + mallocOffset;
	long targetFreeAddr = targetLibcAddr + freeOffset;
	long targetDlopenAddr = targetLibcAddr + dlopenOffset;

	// 设置寄存器和附加到目标进程
	struct user_regs_struct oldregs, regs; 				//定义两个寄存器结构体，用于保存和修改目标进程的寄存器状态
	memset(&oldregs, 0, sizeof(struct user_regs_struct)); //初始化寄存器结构体，清零
	memset(&regs, 0, sizeof(struct user_regs_struct));		//初始化寄存器结构体，清零	

	ptrace_attach(target);									//使用 ptrace 系统调用附加到目标进程

	ptrace_getregs(target, &oldregs); 							//获取目标进程当前的寄存器状态，保存在 oldregs
	memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));	//复制当前寄存器状态到新的寄存器结构体 regs

	// find a good address to copy code to
	long addr = freespaceaddr(target) + sizeof(long); 		//寻找目标进程中可用于代码注入的地址

	// 现在我们有了一个复制代码的地址，设置目标的rip到这个地址。这里我们需要前进2个字节，因为rip会因当前指令的大小而增加，而注入函数开头的指令恰好是2个字节长
	regs.rip = addr + 2;			//设置 rip 寄存器（指令指针），指向注入代码的起始地址。因为某些指令长度为2字节，需要调整地址以匹配实际代码开始的位置

	// 通过将它们加载到正确的寄存器中，向我的函数injectSharedLibrary()传递参数。注意，这绝对只适用于x64，因为它依赖于x64的调用约定，其中参数通过寄存器rdi、rsi、rdx、rcx、r8和r9传递。有关更多细节，请参见injectSharedLibrary()中的注释。
	regs.rdi = targetMallocAddr;	//设置用于调用注入函数所需的寄存器值
	regs.rsi = targetFreeAddr;
	regs.rdx = targetDlopenAddr;
	regs.rcx = libPathLength;
	ptrace_setregs(target, &regs);	// 应用修改后的寄存器状态到目标进程


	// 准备注入代码
	// 计算 injectSharedLibrary() 的大小，以便知道需要分配多大的缓冲区。
	size_t injectSharedLibrary_size = (intptr_t)injectSharedLibrary_end - (intptr_t)injectSharedLibrary; //计算 injectSharedLibrary 函数的大小（字节）这个函数包含了要注入到目标进程的代码

	// 还需要找出 injectSharedLibrary() 末尾的 RET 指令位置，以便我们可以用 INT 3 覆盖它
	// 从而在目标进程中断返回。请注意，在 x64 上，
	// gcc 和 clang 都强制函数地址与字对齐，
	// 这意味着函数会用 NOPs 填充。因此，即使我们找到了函数的长度，
	// 它很可能被 NOPs 填充，所以我们需要实际搜索来找到 RET。
	intptr_t injectSharedLibrary_ret = (intptr_t)findRet(injectSharedLibrary_end) - (intptr_t)injectSharedLibrary; //查找 injectSharedLibrary 函数中返回指令（RET）的位置，为了在注入结束时能够设置断点

	// 备份我们想要修改的地址原来的数据。
	char* backup = malloc(injectSharedLibrary_size * sizeof(char)); //分配内存以备份目标进程中即将被覆盖的原始代码
	ptrace_read(target, addr, backup, injectSharedLibrary_size);    //使用 ptrace 读取目标进程在 addr 地址的内容，并保存到 backup，为恢复原始状态做准备

	// 设置一个缓冲区来存放我们将要注入到目标进程中的代码。
	char* newcode = malloc(injectSharedLibrary_size * sizeof(char)); //分配内存来存放即将注入的代码
	memset(newcode, 0, injectSharedLibrary_size * sizeof(char)); 	//初始化新代码的内存区域

	// 将 injectSharedLibrary() 的代码复制到一个缓冲区。
	memcpy(newcode, injectSharedLibrary, injectSharedLibrary_size - 1); //将注入函数的代码复制到新代码缓冲区
	// overwrite the RET instruction with an INT 3.
	newcode[injectSharedLibrary_ret] = INTEL_INT3_INSTRUCTION;		 //在返回指令的位置设置 INT 3 中断指令，以便在代码执行完成后能够控制目标进程

	// copy injectSharedLibrary()'s code to the target address inside the
	// target process' address space.
	ptrace_write(target, addr, newcode, injectSharedLibrary_size);	 //将修改后的新代码写入目标进程的内存

	// now that the new code is in place, let the target run our injected code.
	ptrace_cont(target);		//通过 ptrace 继续目标进程的执行，这将使目标进程开始执行注入的代码

	// at this point, the target should have run malloc(). check its return
	// value to see if it succeeded, and bail out cleanly if it didn't.
	struct user_regs_struct malloc_regs;  //定义另一个寄存器结构用来检查 malloc 调用的结果
	memset(&malloc_regs, 0, sizeof(struct user_regs_struct));
	ptrace_getregs(target, &malloc_regs); //获取注入代码执行后目标进程的寄存器状态
	unsigned long long targetBuf = malloc_regs.rax; // ???? 从 rax 寄存器中提取 malloc 的返回值，即分配的内存地址
	
	/*在 x86-64 架构中，rax 的使用是标准化的。这意味着任何返回类型为整数或指针的函数都将其返回值存储在 rax 寄存器中。
	这是系统调用和大多数 C 函数调用的通用约定，使得编译器和操作系统能够在不同的程序和库之间共享和理解函数调用的语义。
	这种约定还简化了错误处理和异常检查，因为函数的调用者只需要检查一个寄存器的值即可确定函数调用是否成功。
	如果函数发生错误，通常 rax 会包含一个错误代码或者特定的值（如 NULL），调用者可以据此采取适当的操作。
	这种模式在系统编程中尤其常见，因此你会看到很多操作系统级的代码都会频繁地从 rax 寄存器中读取值。*/

	if(targetBuf == 0) //检查 malloc 是否成功分配内存。如果失败，输出错误信息，并恢复目标进程状态并从其分离
	{
		fprintf(stderr, "malloc() failed to allocate memory\n");
		restoreStateAndDetach(target, addr, backup, injectSharedLibrary_size, oldregs);
		free(backup);
		free(newcode);
		return 1;
	}

	// if we get here, then malloc likely succeeded, so now we need to copy
	// the path to the shared library we want to inject into the buffer
	// that the target process just malloc'd. this is needed so that it can
	// be passed as an argument to __libc_dlopen_mode later on.

	// read the current value of rax, which contains malloc's return value,
	// and copy the name of our shared library to that address inside the
	// target process.
	// 复制库路径并继续执行
	ptrace_write(target, targetBuf, libPath, libPathLength);

	// continue the target's execution again in order to call  __libc_dlopen_mode.
	ptrace_cont(target); //将库路径写入目标进程刚分配的内存中

	// check out what the registers look like after calling dlopen. 
	// 检查库加载状态并清理
	struct user_regs_struct dlopen_regs; // 用于检查 __libc_dlopen_mode 调用结果的寄存器结构
	memset(&dlopen_regs, 0, sizeof(struct user_regs_struct)); // 初始化结构
	ptrace_getregs(target, &dlopen_regs); // 获取调用 __libc_dlopen_mode 后的寄存器状态
	unsigned long long libAddr = dlopen_regs.rax; //从 rax 中提取共享库的加载地址

	// if rax is 0 here, then __libc_dlopen_mode failed, and we should bail
	// out cleanly.
	if(libAddr == 0) //检查库是否成功加载。如果加载失败，输出错误信息，并恢复目标进程状态并从其分离
	{
		fprintf(stderr, "__libc_dlopen_mode() failed to load %s\n", libname);
		restoreStateAndDetach(target, addr, backup, injectSharedLibrary_size, oldregs);
		free(backup);
		free(newcode);
		return 1;
	}

	// now check /proc/pid/maps to see whether injection was successful.
	// 通过 /proc/pid/maps 检查注入是否成功
	if(checkloaded(target, libname))
	{
		printf("\"%s\" successfully injected\n", libname);
	}
	else
	{
		fprintf(stderr, "could not inject \"%s\"\n", libname);
	}

	// as a courtesy, free the buffer that we allocated inside the target
	// process. we don't really care whether this succeeds, so don't
	// bother checking the return value.
	ptrace_cont(target); // 在执行任何清理操作之前，让目标进程继续运行。这一步是在执行完所有注入相关的操作后进行的

	// at this point, if everything went according to plan, we've loaded
	// the shared library inside the target process, so we're done. restore
	// the old state and detach from the target.
	restoreStateAndDetach(target, addr, backup, injectSharedLibrary_size, oldregs); // 函数来恢复目标进程的原始状态并从该进程分离
	free(backup);
	free(newcode);

	return 0;
}
