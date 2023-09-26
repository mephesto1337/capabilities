#![deny(missing_docs)]

//! The basic usage is the following:
//! ```rust
//! fn run() {
//!     let cap = Capabilities::current();
//!     cap.enable(Capability::DacReadSearch).unwrap();
//!     cap.commit().unwrap();
//!     std::fs::read_to_string("/etc/shadow").unwrap();
//! }
//! ```

use std::{
    ffi::CStr,
    fmt::{self, Display},
    io,
    mem::MaybeUninit,
    ptr,
};

mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

/// Represents a set of capabilities
pub struct Capabilities(bindings::cap_t);

impl Drop for Capabilities {
    fn drop(&mut self) {
        unsafe {
            bindings::cap_free(self.0.cast());
        }
    }
}

/// Error type for this crate
#[derive(Debug)]
pub struct CapError {
    /// A bit of context of which call trigger the error
    context: String,

    /// The associated IO error from errno
    error: io::Error,
}

impl Display for CapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Encounter error {e} while {c:?}",
            e = self.error,
            c = self.context
        )
    }
}

impl std::error::Error for CapError {}

impl From<CapError> for io::Error {
    fn from(value: CapError) -> Self {
        value.error
    }
}

macro_rules! check_libcap_call {
    (int $e:expr) => {{
        let ret = $e;
        if ret == -1 {
            Err(CapError {
                context: stringify!($e).into(),
                error: std::io::Error::last_os_error(),
            })
        } else {
            Ok(())
        }
    }};
}

/// Capabilities in Linux
#[derive(Debug, Clone, Copy)]
pub enum Capability {
    /// Make arbitrary changes to file UIDs and GIDs (see chown(2)).
    Chown,

    /// Bypass file read, write, and execute permission checks.  (DAC is an abbreviation of
    /// "discretionary access control".)
    DacOverride,

    /// * Bypass file read permission checks and directory read and execute permission checks;
    /// * invoke open_by_handle_at(2);
    /// * use  the linkat(2) AT_EMPTY_PATH flag to create a link to a file referred to by a file descriptor.
    DacReadSearch,

    /// * Bypass permission checks on operations that normally require the filesystem UID of the
    ///   process to  match the UID of the file (e.g., chmod(2), utime(2)), excluding those
    ///   operations covered by CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH;
    /// * set inode flags (see ioctl_iflags(2)) on arbitrary files;
    /// * set Access Control Lists (ACLs) on arbitrary files;
    /// * ignore directory sticky bit on file deletion;
    /// * modify user extended attributes on sticky directory owned by any user;
    /// * specify O_NOATIME for arbitrary files in open(2) and fcntl(2).
    Fowner,

    /// * Don't clear set-user-ID and set-group-ID mode bits when a file is modified;
    /// * set the set-group-ID bit for a file whose GID does not match the filesystem or any of the
    ///   supplementary GIDs of the calling process.
    Fsetid,

    /// Bypass permission checks for sending signals (see kill(2)).  This includes use of the
    /// ioctl(2) KDSIGACCEPT operation.
    Kill,

    /// * Make arbitrary manipulations of process GIDs and supplementary GID list;
    /// * forge GID when passing socket credentials via UNIX domain sockets;
    /// * write a group ID mapping in a user namespace (see user_namespaces(7)).
    Setgid,

    /// * Make  arbitrary  manipulations  of  process  UIDs  (setuid(2), setreuid(2), setresuid(2),
    ///   setfsuid(2));
    /// * forge UID when passing socket credentials via UNIX domain sockets;
    /// * write a user ID mapping in a user namespace (see user_namespaces(7)).
    Setuid,

    /// If file capabilities are supported (i.e., since Linux 2.6.24): add any capability from the
    /// calling thread's  bounding  set  to  its  inheritable  set;  drop  capabilities from the
    /// bounding set (via prctl(2) PR_CAPBSET_DROP); make changes to the securebits flags.
    ///
    /// If file capabilities are not supported (i.e., before Linux 2.6.24): grant or remove any
    /// capability in the caller's permitted capability set to or from any other process.  (This
    /// property of CAP_SET‐ PCAP is not available when the kernel is configured to support file
    /// capabilities, since  CAP_SETP‐ CAP has entirely different semantics for such kernels.)
    Setpcap,

    /// Set the FS_APPEND_FL and FS_IMMUTABLE_FL inode flags (see ioctl_iflags(2)).
    LinuxImmutable,

    /// Bind a socket to Internet domain privileged ports (port numbers less than 1024).
    NetBindService,

    /// (Unused)  Make socket broadcasts, and listen to multicasts.
    NetBroadcast,

    /// Perform various network-related operations:
    /// *  interface configuration;
    /// *  administration of IP firewall, masquerading, and accounting;
    /// *  modify routing tables;
    /// *  bind to any address for transparent proxying;
    /// *  set type-of-service (TOS);
    /// *  clear driver statistics;
    /// *  set promiscuous mode;
    /// *  enabling multicasting;
    /// *  use  setsockopt(2)  to  set the following socket options: SO_DEBUG, SO_MARK, SO_PRIORITY (for a
    ///    priority outside the range 0 to 6), SO_RCVBUFFORCE, and SO_SNDBUFFORCE.
    NetAdmin,

    /// * Use RAW and PACKET sockets;
    /// * bind to any address for transparent proxying.
    NetRaw,

    /// * Lock memory (mlock(2), mlockall(2), mmap(2), shmctl(2));
    /// * Allocate memory using huge pages (memfd_create(2), mmap(2), shmctl(2)).
    IpcLock,

    /// Bypass permission checks for operations on System V IPC objects.
    IpcOwner,

    /// * Load and unload kernel modules (see init_module(2) and delete_module(2));
    /// * before Linux 2.6.25: drop capabilities from the system-wide capability bounding set.
    SysModule,

    /// * Perform I/O port operations (iopl(2) and ioperm(2));
    /// * access /proc/kcore;
    /// * employ the FIBMAP ioctl(2) operation;
    /// * open devices for accessing x86 model-specific registers (MSRs, see msr(4));
    /// * update /proc/sys/vm/mmap_min_addr;
    /// * create memory mappings at addresses below the value specified by
    ///   /proc/sys/vm/mmap_min_addr;
    /// * map files in /proc/bus/pci;
    /// * open /dev/mem and /dev/kmem;
    /// * perform various SCSI device commands;
    /// * perform certain operations on hpsa(4) and cciss(4) devices;
    /// * perform a range of device-specific operations on other devices.
    SysRawio,

    /// * Use chroot(2);
    /// * change mount namespaces using setns(2).
    SysChroot,

    /// * Trace arbitrary processes using ptrace(2);
    /// * apply get_robust_list(2) to arbitrary processes;
    /// * transfer  data  to  or  from  the  memory  of arbitrary processes using
    ///    process_vm_readv(2) and process_vm_writev(2);
    /// * inspect processes using kcmp(2).
    SysPtrace,

    /// Use acct(2).
    SysPacct,

    /// Note: this capability is overloaded; see Notes to kernel developers below.

    /// *  Perform  a  range  of  system  administration  operations  including:  quotactl(2),
    ///    mount(2), umount(2), pivot_root(2), swapon(2), swapoff(2), sethostname(2), and
    ///    setdomainname(2);
    /// *  perform  privileged syslog(2) operations (since Linux 2.6.37, CAP_SYSLOG should be used
    ///    to permit such operations);
    /// *  perform VM86_REQUEST_IRQ vm86(2) command;
    /// *  access the same checkpoint/restore functionality that  is  governed  by
    ///    CAP_CHECKPOINT_RESTORE (but the latter, weaker capability is preferred for accessing that
    ///    functionality).
    /// *  perform  the  same BPF operations as are governed by CAP_BPF (but the latter, weaker
    ///    capability is preferred for accessing that functionality).
    /// *  employ the same performance monitoring mechanisms as are governed by CAP_PERFMON (but
    ///     the  latter, weaker capability is preferred for accessing that functionality).
    /// *  perform IPC_SET and IPC_RMID operations on arbitrary System V IPC objects;
    /// *  override RLIMIT_NPROC resource limit;
    /// *  perform operations on trusted and security extended attributes (see xattr(7));
    /// *  use lookup_dcookie(2);
    /// *  use  ioprio_set(2)  to  assign  IOPRIO_CLASS_RT and (before Linux 2.6.25)
    ///    IOPRIO_CLASS_IDLE I/O scheduling classes;
    /// *  forge PID when passing socket credentials via UNIX domain sockets;
    /// *  exceed /proc/sys/fs/file-max, the system-wide limit on the number  of  open  files,  in
    ///    system calls that open files (e.g., accept(2), execve(2), open(2), pipe(2));
    /// *  employ  CLONE_* flags that create new namespaces with clone(2) and unshare(2) (but,
    ///    since Linux 3.8, creating user namespaces does not require any capability);
    /// *  access privileged perf event information;
    /// *  call setns(2) (requires CAP_SYS_ADMIN in the target namespace);
    /// *  call fanotify_init(2);
    /// *  perform privileged KEYCTL_CHOWN and KEYCTL_SETPERM keyctl(2) operations;
    /// *  perform madvise(2) MADV_HWPOISON operation;
    /// *  employ the TIOCSTI ioctl(2) to insert characters into the input queue of a terminal
    ///     other  than the caller's controlling terminal;
    /// *  employ the obsolete nfsservctl(2) system call;
    /// *  employ the obsolete bdflush(2) system call;
    /// *  perform various privileged block-device ioctl(2) operations;
    /// *  perform various privileged filesystem ioctl(2) operations;
    /// *  perform privileged ioctl(2) operations on the /dev/random device (see random(4));
    /// *  install a seccomp(2) filter without first having to set the no_new_privs thread attribute;
    /// *  modify allow/deny rules for device control groups;
    /// *  employ the ptrace(2) PTRACE_SECCOMP_GET_FILTER operation to dump tracee's seccomp filters;
    /// *  employ  the  ptrace(2)  PTRACE_SETOPTIONS operation to suspend the tracee's seccomp protections (i.e., the PTRACE_O_SUSPEND_SECCOMP flag);
    /// *  perform administrative operations on many device drivers;
    /// *  modify autogroup nice values by writing to /proc/pid/autogroup (see sched(7)).
    SysAdmin,

    /// Use reboot(2) and kexec_load(2).
    SysBoot,

    /// * Lower the process nice value (nice(2), setpriority(2)) and change the nice value for
    ///   arbitrary processes;
    /// * set  real-time scheduling policies for calling process, and set scheduling policies and
    ///   priorities for arbitrary processes (sched_setscheduler(2), sched_setparam(2),
    ///   sched_setattr(2));
    /// * set CPU affinity for arbitrary processes (sched_setaffinity(2));
    /// * set I/O scheduling class and priority for arbitrary processes (ioprio_set(2));
    /// * apply migrate_pages(2) to arbitrary processes and allow processes to be migrated  to
    ///   arbitrary nodes;
    /// * apply move_pages(2) to arbitrary processes;
    /// * use the MPOL_MF_MOVE_ALL flag with mbind(2) and move_pages(2).
    SysNice,

    /// * Use reserved space on ext2 filesystems;
    /// * make ioctl(2) calls controlling ext3 journaling;
    /// * override disk quota limits;
    /// * increase resource limits (see setrlimit(2));
    /// * override RLIMIT_NPROC resource limit;
    /// * override maximum number of consoles on console allocation;
    /// * override maximum number of keymaps;
    /// * allow more than 64hz interrupts from the real-time clock;
    /// * raise msg_qbytes limit for a System V message queue above the limit in
    ///   /proc/sys/kernel/msgmnb (see msgop(2) and msgctl(2));
    /// * allow  the RLIMIT_NOFILE resource limit on the number of "in-flight" file descriptors to
    ///   be by‐passed when passing file descriptors to another process via a UNIX domain socket
    ///   (see unix(7));
    /// * override the /proc/sys/fs/pipe-size-max limit when setting the capacity of  a  pipe
    ///   using  the F_SETPIPE_SZ fcntl(2) command;
    /// * use   F_SETPIPE_SZ   to  increase  the  capacity  of  a  pipe  above  the  limit
    ///   specified  by /proc/sys/fs/pipe-max-size;
    /// * override /proc/sys/fs/mqueue/queues_max,/proc/sys/fs/mqueue/msg_max, and
    ///   /proc/sys/fs/mqueue/msgsize_max limits when creating POSIX message queues (see
    ///   mq_overview(7));
    /// * employ the prctl(2) PR_SET_MM operation;
    /// * set  /proc/pid/oom_score_adj  to  a  value  lower  than  the  value  last set by a
    ///   process with CAP_SYS_RESOURCE.
    SysResource,

    /// Set system clock (settimeofday(2), stime(2), adjtimex(2)); set real-time (hardware) clock.
    SysTime,

    /// Use vhangup(2); employ various privileged ioctl(2) operations on virtual terminals.
    SysTtyConfig,

    /// Create special files using mknod(2).
    Mknod,

    /// Establish leases on arbitrary files (see fcntl(2)).
    Lease,

    /// Write records to kernel auditing log.
    AuditWrite,

    /// Enable and disable kernel auditing; change auditing filter rules; retrieve auditing  status
    /// and filtering rules.
    AuditControl,

    /// Set arbitrary capabilities on a file.
    ///
    /// Since Linux 5.12, this capability is also needed to map user ID 0 in a  new  user
    /// namespace;  see user_namespaces(7) for details.
    Setfcap,

    /// Override Mandatory Access Control (MAC).  Implemented for the Smack LSM.
    MacOverride,

    /// Allow MAC configuration or state changes.  Implemented for the Smack Linux Security Module (LSM).
    MacAdmin,

    /// * Perform privileged syslog(2) operations.  See syslog(2) for information on which
    ///   operations require privilege.
    /// * View kernel addresses exposed via /proc and  other  interfaces  when
    ///   /proc/sys/kernel/kptr_re‐ strict has the value 1.  (See the discussion of the
    ///   kptr_restrict in proc(5).)
    Syslog,

    /// Trigger  something that will wake up the system (set CLOCK_REALTIME_ALARM and
    /// CLOCK_BOOTTIME_ALARM timers).
    WakeAlarm,

    /// Employ features that can block system suspend (epoll(7) EPOLLWAKEUP, /proc/sys/wake_lock).
    BlockSuspend,

    /// Allow reading the audit log via a multicast netlink socket.
    AuditRead,

    /// Employ various performance-monitoring mechanisms, including:
    ///
    /// *  call perf_event_open(2);
    /// *  employ various BPF operations that have performance implications.
    ///
    /// This capability was added in Linux 5.8 to separate out performance monitoring  functionality  from
    /// the  overloaded  CAP_SYS_ADMIN  capability.   See  also  the  kernel source file Documentation/ad‐
    /// min-guide/perf-security.rst.
    Perfmon,

    /// Employ privileged BPF operations
    Bpf,

    /// *  Update /proc/sys/kernel/ns_last_pid (see pid_namespaces(7));
    /// *  employ the set_tid feature of clone3(2);
    /// *  read the contents of the symbolic links in /proc/pid/map_files for other processes.
    ///
    /// This capability was added in Linux 5.9 to separate out checkpoint/restore functionality
    /// from  the overloaded CAP_SYS_ADMIN capability.
    ///
    CheckpointRestore,
}

impl Capability {
    fn as_cap_value_t(&self) -> bindings::cap_value_t {
        let val = match self {
            Self::Chown => bindings::CAP_CHOWN,
            Self::DacOverride => bindings::CAP_DAC_OVERRIDE,
            Self::DacReadSearch => bindings::CAP_DAC_READ_SEARCH,
            Self::Fowner => bindings::CAP_FOWNER,
            Self::Fsetid => bindings::CAP_FSETID,
            Self::Kill => bindings::CAP_KILL,
            Self::Setgid => bindings::CAP_SETGID,
            Self::Setuid => bindings::CAP_SETUID,
            Self::Setpcap => bindings::CAP_SETPCAP,
            Self::LinuxImmutable => bindings::CAP_LINUX_IMMUTABLE,
            Self::NetBindService => bindings::CAP_NET_BIND_SERVICE,
            Self::NetBroadcast => bindings::CAP_NET_BROADCAST,
            Self::NetAdmin => bindings::CAP_NET_ADMIN,
            Self::NetRaw => bindings::CAP_NET_RAW,
            Self::IpcLock => bindings::CAP_IPC_LOCK,
            Self::IpcOwner => bindings::CAP_IPC_OWNER,
            Self::SysModule => bindings::CAP_SYS_MODULE,
            Self::SysRawio => bindings::CAP_SYS_RAWIO,
            Self::SysChroot => bindings::CAP_SYS_CHROOT,
            Self::SysPtrace => bindings::CAP_SYS_PTRACE,
            Self::SysPacct => bindings::CAP_SYS_PACCT,
            Self::SysAdmin => bindings::CAP_SYS_ADMIN,
            Self::SysBoot => bindings::CAP_SYS_BOOT,
            Self::SysNice => bindings::CAP_SYS_NICE,
            Self::SysResource => bindings::CAP_SYS_RESOURCE,
            Self::SysTime => bindings::CAP_SYS_TIME,
            Self::SysTtyConfig => bindings::CAP_SYS_TTY_CONFIG,
            Self::Mknod => bindings::CAP_MKNOD,
            Self::Lease => bindings::CAP_LEASE,
            Self::AuditWrite => bindings::CAP_AUDIT_WRITE,
            Self::AuditControl => bindings::CAP_AUDIT_CONTROL,
            Self::Setfcap => bindings::CAP_SETFCAP,
            Self::MacOverride => bindings::CAP_MAC_OVERRIDE,
            Self::MacAdmin => bindings::CAP_MAC_ADMIN,
            Self::Syslog => bindings::CAP_SYSLOG,
            Self::WakeAlarm => bindings::CAP_WAKE_ALARM,
            Self::BlockSuspend => bindings::CAP_BLOCK_SUSPEND,
            Self::AuditRead => bindings::CAP_AUDIT_READ,
            Self::Perfmon => bindings::CAP_PERFMON,
            Self::Bpf => bindings::CAP_BPF,
            Self::CheckpointRestore => bindings::CAP_CHECKPOINT_RESTORE,
        };
        val as _
    }
}

impl Capabilities {
    /// Returns current capabilities owns by the calling thread
    pub fn current() -> Self {
        let cap = unsafe { bindings::cap_get_proc() };
        Self(cap)
    }

    /// Check whether a capability is enabled (effective flag is set)
    pub fn has(&self, cap: Capability) -> Result<bool, CapError> {
        let value = cap.as_cap_value_t();
        let mut is_set = MaybeUninit::<bindings::cap_flag_value_t>::uninit();
        check_libcap_call!(int unsafe {
            bindings::cap_get_flag(
                self.0,
                value,
                bindings::cap_flag_t_CAP_EFFECTIVE,
                is_set.as_mut_ptr()
            )
        })?;

        let is_set = unsafe { is_set.assume_init() };
        Ok(is_set == bindings::cap_flag_value_t_CAP_SET)
    }

    /// Enable (set effective flag) a single capacity
    pub fn enable(&mut self, cap: Capability) -> Result<(), CapError> {
        let value = cap.as_cap_value_t();
        check_libcap_call!(int unsafe {
            bindings::cap_set_flag(
                self.0,
                bindings::cap_flag_t_CAP_EFFECTIVE,
                1,
                ptr::addr_of!(value).cast(),
                bindings::cap_flag_value_t_CAP_SET,
            )
        })
    }

    /// Enable (set effective flag) several capabilities
    pub fn enable_many(
        &mut self,
        caps: impl IntoIterator<Item = Capability>,
    ) -> Result<(), CapError> {
        let caps: Vec<_> = caps.into_iter().map(|c| c.as_cap_value_t()).collect();
        check_libcap_call!(int unsafe {
            bindings::cap_set_flag(
                self.0,
                bindings::cap_flag_t_CAP_EFFECTIVE,
                caps.len().try_into().expect("Too many capabilities for i32?!"),
                caps.as_ptr(),
                bindings::cap_flag_value_t_CAP_SET,
            )
        })
    }

    /// Commits capabilities set to current thread
    pub fn commit(&self) -> Result<(), CapError> {
        check_libcap_call!(int unsafe { bindings::cap_set_proc(self.0) })
    }
}

impl fmt::Display for Capabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c_text = unsafe { bindings::cap_to_text(self.0, ptr::null_mut()) };
        let text = unsafe { CStr::from_ptr(c_text) }
            .to_str()
            .expect("libcap should return valid UTF-U strings");
        let ret = f.write_str(text);
        unsafe {
            bindings::cap_free(c_text.cast());
        }
        ret
    }
}

impl PartialEq for Capabilities {
    fn eq(&self, other: &Self) -> bool {
        let res = unsafe { bindings::cap_compare(self.0, other.0) };
        res == 0
    }
}
