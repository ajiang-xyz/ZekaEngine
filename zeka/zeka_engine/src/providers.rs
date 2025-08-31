use rug::{Integer, integer::Order};
use std::{sync::mpsc::Sender, thread, time::Duration};
use zeka_crypto::{consts, numbers::cantor_pairing_mod};

#[cfg(target_os = "linux")]
use libc::*;

#[cfg(target_os = "linux")]
use std::{
    collections::HashMap, ffi::CString, fs::read_link, io::Error, mem::size_of, os::fd::AsRawFd,
    slice::from_raw_parts,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ZekaEventMetadata {
    pub origin: ZekaEventOrigin,
    pub event_type: ZekaEventType,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ZekaEventOrigin {
    Registry,
    Fanotify,
    Etw,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ZekaEventType {
    Write,
    Delete,
    Attribute,
}

#[cfg(target_os = "linux")]
pub struct FanotifyEventFlags(u64);

#[cfg(target_os = "linux")]
impl FanotifyEventFlags {
    fn contains_any(&self, flags: u64) -> bool {
        self.0 & flags != 0
    }
}

#[repr(C)]
#[derive(Debug)]
#[cfg(target_os = "linux")]
#[allow(non_camel_case_types)]
struct file_handle {
    handle_bytes: u32,
    handle_type: i32,
    // followed in memory by: u8 f_handle[handle_bytes]
}

#[inline]
#[cfg(target_os = "linux")]
#[allow(non_snake_case)]
fn FAN_EVENT_OK(meta: &fanotify_event_metadata, remaining: usize) -> bool {
    let m = size_of::<fanotify_event_metadata>();
    remaining >= m && (meta.event_len as usize) >= m && (meta.event_len as usize) <= remaining
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn fanotify_mask_to_string(mask: u64) -> String {
    const FLAGS: &[(u64, &str)] = &[
        (FAN_ACCESS, "FAN_ACCESS"),
        (FAN_MODIFY, "FAN_MODIFY"),
        (FAN_ATTRIB, "FAN_ATTRIB"),
        (FAN_CLOSE_WRITE, "FAN_CLOSE_WRITE"),
        (FAN_CLOSE_NOWRITE, "FAN_CLOSE_NOWRITE"),
        (FAN_OPEN, "FAN_OPEN"),
        (FAN_OPEN_EXEC, "FAN_OPEN_EXEC"),
        (FAN_Q_OVERFLOW, "FAN_Q_OVERFLOW"),
        (FAN_OPEN_PERM, "FAN_OPEN_PERM"),
        (FAN_ACCESS_PERM, "FAN_ACCESS_PERM"),
        (FAN_ONDIR, "FAN_ONDIR"),
        (FAN_EVENT_ON_CHILD, "FAN_EVENT_ON_CHILD"),
        (FAN_CREATE, "FAN_CREATE"),
        (FAN_DELETE, "FAN_DELETE"),
        (FAN_DELETE_SELF, "FAN_DELETE_SELF"),
        (FAN_MOVE_SELF, "FAN_MOVE_SELF"),
        (FAN_MOVED_FROM, "FAN_MOVED_FROM"),
        (FAN_MOVED_TO, "FAN_MOVED_TO"),
        (FAN_RENAME, "FAN_RENAME"),
    ];

    let mut names = Vec::new();
    for &(bit, name) in FLAGS {
        if mask & bit != 0 {
            names.push(name);
        }
    }

    if names.is_empty() {
        format!("<unknown event> (0x{mask:x})")
    } else {
        names.join(" | ")
    }
}

#[cfg(target_os = "linux")]
fn align8(len: usize) -> usize {
    (len + 7) & !7
}

#[cfg(target_os = "linux")]
pub fn fanotify_provider(tx: Sender<(String, ZekaEventMetadata)>) {
    let path = "/";
    let fan_fd = unsafe {
        fanotify_init(
            FAN_UNLIMITED_QUEUE
                | FAN_UNLIMITED_MARKS
                | FAN_REPORT_FID
                | FAN_REPORT_DFID_NAME_TARGET,
            O_RDWR as u32,
        )
    };
    if fan_fd < -1 {
        panic!(
            "Unable to initialize fanotify: {:?}",
            Error::last_os_error()
        );
    }

    let mount_fd = std::fs::File::open(path).unwrap_or_else(|_| panic!("Unable to open `{path}`"));
    let rc = unsafe {
        fanotify_mark(
            fan_fd,
            FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
            FAN_CLOSE_WRITE
                | FAN_MOVED_TO
                | FAN_CREATE
                | FAN_RENAME
                | FAN_DELETE
                // | FAN_MODIFY
                // | FAN_ATTRIB
                | FAN_EVENT_ON_CHILD
                | FAN_ONDIR,
            mount_fd.as_raw_fd(),
            CString::new(path).unwrap().as_ptr(),
        )
    };
    if rc < -1 {
        panic!("Unable to mark path: {:?}", Error::last_os_error());
    }

    #[allow(unused_variables)]
    let mut i = 1;
    let mut buf = [0u8; 64 * 1024];
    let mut seen_paths: HashMap<Integer, String> = HashMap::new();
    loop {
        let mut base = buf.as_mut_ptr();
        let buflen = unsafe { read(fan_fd, base as *mut _, buf.len()) };
        if buflen < 0 {
            panic!(
                "Error reading from fanotify: {:?}. Are you running as sudo?",
                Error::last_os_error()
            );
        }
        let mut buflen = buflen as usize;

        loop {
            let meta = unsafe { &*(base as *const fanotify_event_metadata) };
            let event_flags = FanotifyEventFlags(meta.mask);

            if !FAN_EVENT_OK(meta, buflen as usize) {
                break;
            }

            let fid = unsafe {
                &*(base.add(size_of::<fanotify_event_metadata>()) as *const fanotify_event_info_fid)
            };

            let fsid = Integer::from_digits(&fid.fsid.val.map(|v| v as u32), Order::Msf);

            // https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html#:~:text=struct%20file_handle%20%7B
            let file_handle = unsafe {
                &*(base.add(
                    size_of::<fanotify_event_metadata>()
                        + size_of::<fanotify_event_info_header>()
                        + size_of::<__c_anonymous__kernel_fsid_t>(),
                ) as *const file_handle)
            };

            let f_handle = unsafe {
                from_raw_parts(
                    base.add(
                        size_of::<fanotify_event_metadata>()
                            + size_of::<fanotify_event_info_header>()
                            + size_of::<__c_anonymous__kernel_fsid_t>()
                            + size_of::<u32>()
                            + size_of::<i32>(),
                    ),
                    file_handle.handle_bytes as usize,
                )
            };
            let f_handle = Integer::from_digits(f_handle, Order::Msf);
            let uid = cantor_pairing_mod(&f_handle, &fsid, &consts::VULN_FIELD_MOD);

            let event_fd = unsafe {
                syscall(
                    SYS_open_by_handle_at,
                    mount_fd.as_raw_fd(),
                    file_handle as *const _ as *const libc::c_void,
                    O_RDONLY,
                )
            };

            let bytes = unsafe {
                std::slice::from_raw_parts(
                    base.add(
                        size_of::<fanotify_event_metadata>()
                            + size_of::<fanotify_event_info_header>()
                            + size_of::<__c_anonymous__kernel_fsid_t>()
                            + size_of::<u32>()
                            + size_of::<i32>()
                            + file_handle.handle_bytes as usize,
                    ),
                    fid.hdr.len as usize,
                )
            };
            let nul_pos = bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(bytes.len() as usize);

            let file_path = match (
                read_link(format!("/proc/self/fd/{event_fd}")),
                String::from_utf8(bytes[..nul_pos].to_vec()),
            ) {
                (Ok(path), Ok(filename)) => {
                    let path = format!("{}/{}", path.display(), filename);
                    seen_paths.insert(uid.clone(), path.clone());
                    path
                }
                (Ok(path), _) => {
                    format!("{}/<invalid>", path.display())
                }
                (_, _) => {
                    if let Some(existing_path) = seen_paths.remove(&uid) {
                        existing_path.clone()
                    } else {
                        "<invalid>".to_string()
                    }
                }
            };

            if event_fd >= 0 {
                unsafe {
                    close(event_fd as i32);
                }
            }

            // println!("event_id: {i}");
            // println!("base_addr: {base:?}");
            // println!("buflen: {buflen}");
            // println!("event_flags: {}", fanotify_mask_to_string(event_flags.0));
            // println!("file_path: {file_path}");
            // println!("meta: {meta:#?}");
            // println!("fid: {fid:#?}");
            // println!("file_handle: {file_handle:#?}");
            // println!("f_handle: {f_handle:?}");
            // println!("fsid: {fsid}");
            // println!("uid: {uid}");
            // println!();

            match if event_flags.contains_any(FAN_CLOSE_WRITE | FAN_MOVED_TO | FAN_CREATE) {
                tx.send((
                    file_path,
                    ZekaEventMetadata {
                        origin: ZekaEventOrigin::Fanotify,
                        event_type: ZekaEventType::Write,
                    },
                ))
            } else if event_flags.contains_any(FAN_RENAME | FAN_DELETE) {
                tx.send((
                    file_path,
                    ZekaEventMetadata {
                        origin: ZekaEventOrigin::Fanotify,
                        event_type: ZekaEventType::Delete,
                    },
                ))
            // } else if event_flags.contains_any(FAN_ATTRIB) {
            //     tx.send(ZekaEvent {
            //         origin: ZekaEventOrigin::Fanotify,
            //         event_type: ZekaEventType::Attribute,
            //         path: file_path,
            //     })
            } else {
                Ok(())
            } {
                Ok(()) => {}
                Err(e) => eprintln!("\rFailed sending event: {e}"),
            }

            // FAN_EVENT_NEXT
            let step = meta.event_len as usize;
            buflen -= step;
            base = unsafe { base.add(step) };
            base = align8(base as usize) as *mut u8;
            i += 1;
        }
    }
}

pub fn etw_provider(tx: Sender<(String, ZekaEventMetadata)>) {
    loop {
        match tx.send((
            "<etw not implemented yet>".to_string(),
            ZekaEventMetadata {
                origin: ZekaEventOrigin::Etw,
                event_type: ZekaEventType::Write,
            },
        )) {
            Ok(()) => {}
            Err(e) => eprintln!("\rFailed sending event: {e}"),
        };

        thread::sleep(Duration::from_millis(100));
    }
}

pub fn registry_provider(tx: Sender<(String, ZekaEventMetadata)>) {
    loop {
        match tx.send((
            "<registry not implemented yet>".to_string(),
            ZekaEventMetadata {
                origin: ZekaEventOrigin::Registry,
                event_type: ZekaEventType::Write,
            },
        )) {
            Ok(()) => {}
            Err(e) => eprintln!("\rFailed sending event: {e}"),
        };

        thread::sleep(Duration::from_millis(100));
    }
}
