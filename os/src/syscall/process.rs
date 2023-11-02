//! Process management syscalls
use crate::{
    config::MAX_SYSCALL_NUM,
    mm::{translated_physical_address, VirtAddr, VirtPageNum},
    task::{
        change_program_brk, current_user_token, exit_current_and_run_next, mmap, set_task_info,
        suspend_current_and_run_next, TaskStatus, munmap,
    },
    timer::get_time_us,
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    pub status: TaskStatus,
    /// The numbers of syscall called by task
    pub syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    pub time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    
    let us_time = get_time_us();
    let tmp = 1000000;
    let kernel_time = translated_physical_address(current_user_token(), ts);
    unsafe {
        *kernel_time = TimeVal {
            sec: us_time / tmp, usec: us_time % tmp, };
    }
    0
}
/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(_ti: *mut TaskInfo) -> isize {
    let kernel_ti = translated_physical_address(current_user_token(), _ti);
    set_task_info(kernel_ti);
    0
}
// YOUR JOB: Implement mmap.
/// 申请长度为_len字节的物理内存，并映射到_start开始的虚拟内存，内存属性为port
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    let start_vaddr: VirtAddr = _start.into();
    // start 没有按页大小对齐 port & !0x7 != 0 (port 其余位必须为0) port & 0x7 = 0 (这样的内存无意义) 
    if (start_vaddr.aligned() == false) ||_port & !0x7 != 0 || _port & 0x7 == 0 {
        return -1;
    }
    let end_vaddr: VirtAddr = (_start + _len).into();
    mmap(start_vaddr.into(), end_vaddr.ceil() as VirtPageNum, _port)
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    let start_vir_addr: VirtAddr = _start.into();
    if start_vir_addr.aligned() == false{
        return -1;
    }
    let end_vir_addr: VirtAddr = (_start + _len).into();
    munmap(start_vir_addr.into(), end_vir_addr.ceil() as VirtPageNum)
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
