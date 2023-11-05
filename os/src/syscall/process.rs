//! Process management syscalls
use alloc::sync::Arc;

use crate::{
    config::MAX_SYSCALL_NUM,
    loader::get_app_data_by_name,
    mm::{translated_physical_address, translated_refmut, translated_str, VirtAddr, VirtPageNum},
    task::{
        add_task, current_task, current_user_token, exit_current_and_run_next, pro_mmap, pro_munmap,
        suspend_current_and_run_next, TaskControlBlock, TaskStatus,
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
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(exit_code: i32) -> ! {
    trace!("kernel:pid[{}] sys_exit", current_task().unwrap().pid.0);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel:pid[{}] sys_yield", current_task().unwrap().pid.0);
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    trace!("kernel: sys_getpid pid:{}", current_task().unwrap().pid.0);
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        task.exec(data);
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    trace!(
        "kernel::pid[{}] sys_waitpid [{}]",
        current_task().unwrap().pid.0,
        pid
    );
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
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
    trace!(
        "kernel:pid[{}] sys_task_info NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );
    -1 
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
   
    let start_vaddr: VirtAddr = _start.into();
    // start 没有按页大小对齐 port & !0x7 != 0 (port 其余位必须为0) port & 0x7 = 0 (这样的内存无意义) 
    if (start_vaddr.aligned() == false) ||_port & !0x7 != 0 || _port & 0x7 == 0 {
        return -1;
    }
    let end_vaddr: VirtAddr = (_start + _len).into();
    pro_mmap(start_vaddr.into(), end_vaddr.ceil() as VirtPageNum, _port)

}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {

    let start_vir_addr: VirtAddr = _start.into();
    if start_vir_addr.aligned() == false{
        return -1;
    }
    let end_vir_addr: VirtAddr = (_start + _len).into();
    pro_munmap(start_vir_addr.into(), end_vir_addr.ceil() as VirtPageNum)
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().pid.0);
    if let Some(old_brk) = current_task().unwrap().change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

/// YOUR JOB: Implement spawn.
/// HINT: fork + exec =/= spawn
/// 根据exec()中的参数创建新的地址空间memory_set。
/// 创建新的TaskControlBlock，模仿fork()进行初始化赋值工作，
/// 把复制地址空间的操作修改为把地址空间赋值为memory_set
pub fn sys_spawn(_path: *const u8) -> isize {
    let token = current_user_token();
    let path = translated_str(token, _path);

    if let Some(data) = get_app_data_by_name(path.as_str()) {
        //当前进程
        let current_task = current_task().unwrap();
        let mut current_inner = current_task.inner_exclusive_access();
        //新进程
        let new_task: Arc<TaskControlBlock> = Arc::new(TaskControlBlock::new(data));
        let mut new_inner = new_task.inner_exclusive_access();
        //将当前进程设为新进程的子进程
        new_inner.parent = Some(Arc::downgrade(&current_task));
        current_inner.children.push(new_task.clone());

        drop(new_inner);
        drop(current_inner);
        
        let new_pid = new_task.pid.0;
        add_task(new_task);
        new_pid as isize

    } else {

        -1
    }
}

// YOUR JOB: Set task priority.
pub fn sys_set_priority(_prio: isize) -> isize {
    if _prio <= 1 {
        return -1;
    }

    let current_task = current_task().unwrap();
    let mut current_task_inner = current_task.inner_exclusive_access();
    current_task_inner.priority = _prio as u8;
    drop(current_task_inner);
    
     _prio 
}
