pub struct Limits {
    #[cfg(windows)]
    _job: std::os::windows::io::OwnedHandle,
}

#[cfg(target_os = "linux")]
pub fn apply() -> std::io::Result<Limits> {
    let limit = libc::rlimit {
        rlim_cur: 2 * 1024 * 1024 * 1024,
        rlim_max: 2 * 1024 * 1024 * 1024,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_AS, &limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Limits {})
}

#[cfg(windows)]
pub fn apply() -> std::io::Result<Limits> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::System::{JobObjects::*, Threading::GetCurrentProcess};
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let job = unsafe { OwnedHandle::from_raw_handle(job) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.ProcessMemoryLimit = 2 * 1024 * 1024 * 1024;
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const _,
            std::mem::size_of_val(&limits) as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { AssignProcessToJobObject(job.as_raw_handle(), GetCurrentProcess()) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Limits { _job: job })
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn apply() -> std::io::Result<Limits> {
    Ok(Limits {})
}
