#include <sys/param.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <sys/queue.h>
#include <getopt.h>
#include "mach_vm.h"
#include <stdlib.h>
#include <stdint.h>
#include <mach/mach_types.h>
#include <mach/mach_host.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <ctype.h>
#include <stdbool.h>
#include <Foundation/Foundation.h>
#include "plankton.h"
#include "kernel_base.h"
#include <termios.h>
#include <sys/event.h>
#include <unistd.h>
#include "jelbrekLib.h"

FILE *log_file = NULL;

void att(mach_port_t port);
void proc_name(int pid, char *buf, int size);
void give_info(void);
void get_number_of_threads(mach_port_t port);

size_t read_from_task(uint64_t addr, void *buf, size_t size, mach_port_t port)
{
    unsigned char buffer[size];
    if (!MACH_PORT_VALID(tfp0)) {
        return 0;
    }
    kern_return_t ret;
    vm_size_t remainder = size,
              bytes_read = 0;

    // The vm_* APIs are part of the mach_vm subsystem, which is a MIG thing
    // and therefore has a hard limit of 0x1000 bytes that it accepts. Due to
    // this, we have to do both reading and writing in chunks smaller than that.
    for(mach_vm_address_t end = (mach_vm_address_t)addr + size; addr < end; remainder -= size)
    {
        size = remainder > 0xfff ? 0xfff : remainder;
        ret = mach_vm_read_overwrite(port, addr, size, (mach_vm_address_t)&((char*)buf)[bytes_read], (mach_vm_size_t*)&size);
        if(ret != KERN_SUCCESS || size == 0)
        {
            fprintf(stderr, "vm_read error: %s", mach_error_string(ret));
            break;
        }
        bytes_read += size;
        addr += size;
    }
    printf("[+] vm_read_overwrite success!\n");
    int a = 0;
    for (int i = 0; i < size; i+=8){
        printf("0x%.8llx: %.02x%.02x%.02x%.02x %.02x%.02x%.02x%.02x\n",addr+i,buffer[a],buffer[a+1],buffer[a+2],buffer[a+3],buffer[a+4],buffer[a+5],buffer[a+6],buffer[a+7]);
        a+=8;
    }
    return bytes_read;
}

uint64_t rf(uint64_t addr, mach_port_t port, uint64_t size)
{
    read_from_task(addr, &size, sizeof(size), port);
    return read_from_task(addr, &size, sizeof(size), port)==sizeof(size)?size:0xdeadbeefdeadbeef;
}

void write_what_where(uint64_t addr, uint64_t data, mach_port_t port){

    kern_return_t kr = mach_vm_write(port,(mach_vm_address_t)addr,(vm_address_t)&data,sizeof(data));
    
    if (kr != KERN_SUCCESS){
        printf("[!] Write failed. %s\n",mach_error_string(kr));
    }else{
        printf("[+] Call to vm_write() succeeded.\n");
        printf("Wrote bytes.\n");
    }
}

void clear_register_vars(){
    thread_list = NULL;
    thread_count = 0;
    sc = ARM_THREAD_STATE64_COUNT;
}

void set_thread(mach_port_t port, int thread_number){
    // get threads in task
    task_threads(port, &thread_list, &thread_count);
    // set register state from x thread
    thread_set_state(thread_list[thread_number - 1],ARM_THREAD_STATE64,(thread_state_t)&arm_state64,sc);
}

void get_thread(mach_port_t port, int thread_number){
    // get threads in task
    task_threads(port, &thread_list, &thread_count);
    // get register state from x thread
    thread_get_state(thread_list[thread_number - 1],ARM_THREAD_STATE64,(thread_state_t)&arm_state64,&sc);
}

void set_register(mach_port_t port, int thread_number, int register_num, uint64_t value, const char *other_registers){
    get_thread(port, thread_number);
    if (register_num == 100){
        if(strcmp(other_registers,"fp")==0){
            arm_state64.__fp = value;
        } else if (strcmp(other_registers,"lr")==0){
            arm_state64.__lr = value;
        } else if (strcmp(other_registers,"sp")==0){
            arm_state64.__sp = value;
        } else if (strcmp(other_registers,"pc")==0){
            arm_state64.__pc = value;
        } else if (strcmp(other_registers,"cpsr")==0){
            arm_state64.__cpsr = (uint32_t)value;
        } else if (strcmp(other_registers,"pad")==0){
            arm_state64.__pad = (uint32_t)value;
        }
        set_thread(port, thread_number);
    } else {
        arm_state64.__x[register_num] = value;
        set_thread(port, thread_number);
    }
}

void check_register(mach_port_t port, int thread_number, uint64_t value, int register_num, const char *other_registers){
    if (register_num == 100){
        if(strcmp(other_registers,"fp")==0){
            if (value != arm_state64.__fp){
                printf("fp did not read back 0x%.8llx.\n", value);
            } else {
                printf("fp updated.\n");
            }
        } else if (strcmp(other_registers,"lr")==0){
            if (value != arm_state64.__lr){
                printf("lr did not read back 0x%.8llx.\n", value);
            } else {
                printf("lr updated.\n");
            }
        } else if (strcmp(other_registers,"sp")==0){
            if (value != arm_state64.__sp){
                printf("sp did not read back 0x%.8llx.\n", value);
            } else {
                printf("sp updated.\n");
            }
        } else if (strcmp(other_registers,"pc")==0){
            if (value != arm_state64.__pc){
                printf("pc did not read back 0x%.8llx.\n", value);
            } else {
                printf("pc updated.\n");
            }
        } else if (strcmp(other_registers,"cpsr")==0){
            if (value != arm_state64.__cpsr){
                printf("cpsr did not read back 0x%.08x.\n", (uint32_t)value);
            } else {
                printf("cpsr updated.\n");
            }
        } else if (strcmp(other_registers,"pad")==0){
            if (value != arm_state64.__pad){
                printf("pad did not read back 0x%.08x.\n", (uint32_t)value);
            } else {
                printf("pad updated.\n");
            }
        }
        clear_register_vars();
    } else {
        if (value != arm_state64.__x[register_num]){
            printf("x%d did not read back 0x%.8llx.\n", register_num, value);
        } else {
            printf("x%d updated.\n", register_num);
        }
    }
}

void set_and_check_reg(mach_port_t port, int thread_number, uint64_t value, int register_num, const char *other_registers){
    set_register(port, thread_number, register_num, value, other_registers);
    check_register(port, thread_number, value, register_num, other_registers);
}



void regset(char reg[], uint64_t value, mach_port_t port){
    int thread_number = 0;
    task_threads(port, &thread_list, &thread_count);
    printf("[+] Number of threads in process: %x\n",thread_count);
    clear_register_vars();
    
    printf("Enter the thread to attach to >> ");
    scanf("%d",&thread_number);
    printf("\x1b[0m");
    
    if (strcmp(reg,"X0")==0 || strcmp(reg,"x0")==0){
        set_and_check_reg(port, thread_number, value, 0, NULL);
    }else if (strcmp(reg,"X1")==0 || strcmp(reg,"x1")==0){
        set_and_check_reg(port, thread_number, value, 1, NULL);
    }else if (strcmp(reg,"X2")==0 || strcmp(reg,"x2")==0){
        set_and_check_reg(port, thread_number, value, 2, NULL);
    }else if (strcmp(reg,"X3")==0 || strcmp(reg,"x3")==0){
        set_and_check_reg(port, thread_number, value, 3, NULL);;
    }else if (strcmp(reg,"X4")==0 || strcmp(reg,"x4")==0){
        set_and_check_reg(port, thread_number, value, 4, NULL);
    }else if (strcmp(reg,"X5")==0 || strcmp(reg,"x5")==0){
        set_and_check_reg(port, thread_number, value, 5, NULL);
    }else if (strcmp(reg,"X6")==0 || strcmp(reg,"x6")==0){
        set_and_check_reg(port, thread_number, value, 6, NULL);
    }else if (strcmp(reg,"X7")==0 || strcmp(reg,"x7")==0){
        set_and_check_reg(port, thread_number, value, 7, NULL);
    }else if (strcmp(reg,"X8")==0 || strcmp(reg,"x8")==0){
        set_and_check_reg(port, thread_number, value, 8, NULL);
    }else if (strcmp(reg,"X9")==0 || strcmp(reg,"x9")==0){
        set_and_check_reg(port, thread_number, value, 9, NULL);
    }else if (strcmp(reg,"X10")==0 || strcmp(reg,"x10")==0){
        set_and_check_reg(port, thread_number, value, 10, NULL);
    }else if (strcmp(reg,"X11")==0 || strcmp(reg,"x11")==0){
        set_and_check_reg(port, thread_number, value, 11, NULL);
    }else if (strcmp(reg,"X12")==0 || strcmp(reg,"x12")==0){
        set_and_check_reg(port, thread_number, value, 12, NULL);
    }else if (strcmp(reg,"X13")==0 || strcmp(reg,"x13")==0){
        set_and_check_reg(port, thread_number, value, 13, NULL);
    }else if (strcmp(reg,"X14")==0 || strcmp(reg,"x14")==0){
        set_and_check_reg(port, thread_number, value, 14, NULL);
    }else if (strcmp(reg,"X15")==0 || strcmp(reg,"x15")==0){
        set_and_check_reg(port, thread_number, value, 15, NULL);
    }else if (strcmp(reg,"X16")==0 || strcmp(reg,"x16")==0){
        set_and_check_reg(port, thread_number, value, 16, NULL);
    }else if (strcmp(reg,"X17")==0 || strcmp(reg,"x17")==0){
        set_and_check_reg(port, thread_number, value, 17, NULL);
    }else if (strcmp(reg,"X18")==0 || strcmp(reg,"x18")==0){
        set_and_check_reg(port, thread_number, value, 18, NULL);
    }else if (strcmp(reg,"X19")==0 || strcmp(reg,"x19")==0){
        set_and_check_reg(port, thread_number, value, 19, NULL);
    }else if (strcmp(reg,"X20")==0 || strcmp(reg,"x20")==0){
        set_and_check_reg(port, thread_number, value, 20, NULL);
    }else if (strcmp(reg,"X21")==0 || strcmp(reg,"x21")==0){
        set_and_check_reg(port, thread_number, value, 21, NULL);
    }else if (strcmp(reg,"X22")==0 || strcmp(reg,"x22")==0){
        set_and_check_reg(port, thread_number, value, 22, NULL);
    }else if (strcmp(reg,"X23")==0 || strcmp(reg,"x23")==0){
        set_and_check_reg(port, thread_number, value, 23, NULL);
    }else if (strcmp(reg,"X24")==0 || strcmp(reg,"x24")==0){
        set_and_check_reg(port, thread_number, value, 24, NULL);
    }else if (strcmp(reg,"X25")==0 || strcmp(reg,"x25")==0){
        set_and_check_reg(port, thread_number, value, 25, NULL);
    }else if (strcmp(reg,"X26")==0 || strcmp(reg,"x26")==0){
        set_and_check_reg(port, thread_number, value, 26, NULL);
    }else if (strcmp(reg,"X27")==0 || strcmp(reg,"x27")==0){
        set_and_check_reg(port, thread_number, value, 27, NULL);
    }else if (strcmp(reg,"X28")==0 || strcmp(reg,"x28")==0){
        set_and_check_reg(port, thread_number, value, 28, NULL);
    }else if (strcmp(reg,"fp")==0 || strcmp(reg,"FP")==0){
        set_and_check_reg(port, thread_number, value, 100, "fp");
    }else if (strcmp(reg,"lr")==0 || strcmp(reg,"LR")==0){
        set_and_check_reg(port, thread_number, value, 100, "lr");
    }else if (strcmp(reg,"sp")==0 || strcmp(reg,"SP")==0){
        set_and_check_reg(port, thread_number, value, 100, "sp");
    }else if (strcmp(reg,"pc")==0 || strcmp(reg,"PC")==0){
        set_and_check_reg(port, thread_number, value, 100, "pc");
    }else if (strcmp(reg,"cpsr")==0 || strcmp(reg,"CPSR")==0){
        set_and_check_reg(port, thread_number, value, 100, "cpsr");
    }else if (strcmp(reg,"pad")==0 || strcmp(reg,"PAD")==0){
        set_and_check_reg(port, thread_number, value, 100, "pad");
    }else{
        printf("[!] Invalid register name specified.\n");
    }
}

uint64_t get_pid_of_proc(const char *process_name)
{
    int pid = 0;
    char buffer[256];
    int buffer_size = 256;
    uint64_t pid_of_proc = 0;

    // 99999 is the value of PID_MAX in bsd/sys/proc_internal.h
    for (pid = 0; pid <= 99999; pid++)
    {
        buffer[0] = 0;
        proc_name(pid, buffer, buffer_size);
        if (strlen(buffer) > 0)
        {
            if (!strcmp(process_name, buffer))
                pid_of_proc = pid;
        }
    }
    return pid_of_proc;
}

void listreg(mach_port_t port, int thread_number){
    printf("[*] Listing registers with port: 0x%d and thread: %d", port, thread_number);
    
    // get register state from thread
    get_thread(port, thread_number);
    
    printf("\nRegisters\n");
    int i;
    int count = 29;
    for (i = 0; i < count; i++){
        printf("x%d   0x%.8llx\n",i ,arm_state64.__x[i]);
    }
    printf("\nfp    0x%.8llx\n", arm_state64.__fp);
    printf("lr    0x%.8llx\n", arm_state64.__lr);
    printf("sp    0x%.8llx\n", arm_state64.__sp);
    printf("pc    0x%.8llx\n", arm_state64.__pc);
    printf("cpsr  0x%.08x\n", arm_state64.__cpsr);
    printf("pad   0x%.08x\n", arm_state64.__pad);
}

size_t kernel_read(uint64_t addr, void *buf, size_t size)
{
    if (!MACH_PORT_VALID(tfp0)) {
        return 0;
    }
    kern_return_t ret;
    vm_size_t remainder = size,
              bytes_read = 0;

    // The vm_* APIs are part of the mach_vm subsystem, which is a MIG thing
    // and therefore has a hard limit of 0x1000 bytes that it accepts. Due to
    // this, we have to do both reading and writing in chunks smaller than that.
    for(mach_vm_address_t end = (mach_vm_address_t)addr + size; addr < end; remainder -= size)
    {
        size = remainder > 0xfff ? 0xfff : remainder;
        ret = mach_vm_read_overwrite(tfp0, addr, size, (mach_vm_address_t)&((char*)buf)[bytes_read], (mach_vm_size_t*)&size);
        if(ret != KERN_SUCCESS || size == 0)
        {
            fprintf(stderr, "mach_vm_read_overwrite error: %s", mach_error_string(ret));
            break;
        }
        bytes_read += size;
        addr += size;
    }
    printf("[+] mach_vm_read_overwrite success!\n");
    return bytes_read;
}

uint64_t rk64(uint64_t addr)
{
    uint64_t val = 0;
    kernel_read(addr, &val, sizeof(val));
    return kernel_read(addr, &val, sizeof(val))==sizeof(val)?val:0xdeadbeefdeadbeef;
}

size_t kernel_write(uint64_t addr, void *buf, size_t size)
{
    if (!MACH_PORT_VALID(tfp0)) {
        return 0;
    }
    kern_return_t ret;
    vm_size_t remainder = size,
              bytes_written = 0;

    for(mach_vm_address_t end = (mach_vm_address_t)addr + size; addr < end; remainder -= size)
    {
        size = remainder > 0xfff ? 0xfff : remainder;
        ret = mach_vm_write(tfp0, addr, (vm_offset_t)&((char*)buf)[bytes_written], (uint)size);
        if(ret != KERN_SUCCESS)
        {
            fprintf(stderr, "mach_vm_write error: %s", mach_error_string(ret));
            break;
        }
        bytes_written += size;
        addr += size;
    }
    printf("[+] mach_vm_write success!\n");
    return bytes_written;
}

bool wk64(uint64_t addr, uint64_t val)
{
    return kernel_write(addr, &val, sizeof(val)) == sizeof(val);
}

void gethexvals(const void* data, size_t size, uint64_t addr) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    int theAddto = 0;
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("| 0x%016llx ", addr + theAddto);
                theAddto = theAddto + 16;
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("| 0x%016llx ", addr + theAddto);
                theAddto = theAddto + 16;
                printf("|  %s \n", ascii);
            }
        }
    }
}

kern_return_t readFromkernel(task_t tfp0, uint64_t addr, void *data, size_t size){
    kern_return_t err = 0;
    char buf[size];
    
    mach_vm_size_t rSize = 0;
    err = mach_vm_read_overwrite(tfp0, addr, sizeof(buf), (uint64_t)buf, &rSize);
    printf("[+] mach_vm_read_overwrite success!\n");
    
    printf("info:\n");
    gethexvals(buf, sizeof(buf), addr);
    return err;
}

int inittfp0(){
    kern_return_t err;
    // tfp0, kexecute
    err = task_for_pid(mach_task_self(), 0, &tfp0);
    if (err != KERN_SUCCESS) {
        err = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &tfp0);
        if (err != KERN_SUCCESS) {
            fprintf(stderr, "host_get_special_port 4: %s", mach_error_string(err));
            tfp0 = KERN_INVALID_TASK;
            return -1;
        }
    }
    return 0;
}

int getTfp0() {
    return tfp0;
}

void initEngine(){
    inittfp0();
    kbase = get_kbase(&kslide, tfp0); //causes panic when reading live kernel address
    init_with_kbase(tfp0, kbase, NULL);
}

void give_info(){
    printf("[+] tfp0 = 0x%u\n", tfp0);
    printf("[+] kbase = 0x%016llx\n", kbase);
    printf("[+] kslide = 0x%016llx\n", kslide);
}

void get_number_of_threads(mach_port_t port) {
    thread_act_port_array_t thread_list;
    mach_msg_type_number_t thread_count;
    // get threads in task
    task_threads(port, &thread_list, &thread_count);

    printf("[+] Number of threads in process: %x\n",thread_count);
}

void suspend(mach_port_t port){
    task_suspend(port);
    printf("[*] Task suspended.\n");
}

void resume(mach_port_t port){
    task_resume(port);
    printf("[*] Task resumed.\n");
}

mach_port_t getPort(int pid){
    mach_port_t port;
    kern_return_t kr;

    if(pid == 0){
        port = tfp0;
    } else if ((kr = task_for_pid(mach_task_self(), pid, &port)) != KERN_SUCCESS){
        printf("[!] Error!\n");
               
        printf("[!] Call to task_for_pid() with PID %d failed.\n",pid);
    }
    return port;
}

int getPidOfProc(char nameofproc[128]){
    int pid;
    printf("\x1b[0m");
    
    if (!isdigit(nameofproc[0])){
        pid = (int)get_pid_of_proc(nameofproc);
    } else {
        pid = atoi(nameofproc);
    }
    return pid;
}

void quit() {
    term_jelbrek();
    printf("[*] Cleaned up\n");
    exit(0);
}
