#ifndef plankton_h
#define plankton_h

#include <stdio.h>

uint64_t offset_options = 0;
uint64_t offset_cr_flags = 0;
uint64_t offset_zonemap=0;
uint64_t kernel_task_kaddr=0;
uint64_t kernel_task_offset_all_image_info_addr=0;
mach_port_t tfp0=0;
uint64_t kbase, kslide;
thread_act_port_array_t thread_list;
mach_msg_type_number_t thread_count;
// get threads in task
arm_thread_state64_t arm_state64;
mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;

#endif
