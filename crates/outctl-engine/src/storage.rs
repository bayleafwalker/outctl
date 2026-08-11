use sha2::{Digest, Sha256};
use std::ffi::{CString, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const CHUNK_BYTES: usize = 64 * 1024;
static CAPTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) fn capture_id() -> String {
    let epoch_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let sequence = CAPTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{epoch_nanos:016x}{:08x}{sequence:08x}", std::process::id())
}

#[derive(Debug)]
pub(crate) struct PrivateDir {
    file: File,
    display_path: PathBuf,
}

impl PrivateDir {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        walk_directory(path, false)
    }

    pub(crate) fn ensure(path: &Path) -> io::Result<Self> {
        let directory = walk_directory(path, true)?;
        directory.set_private_permissions()?;
        Ok(directory)
    }

    pub(crate) fn display_path(&self) -> &Path {
        &self.display_path
    }

    pub(crate) fn try_open_dir(&self, name: &str) -> io::Result<Option<Self>> {
        validate_name(name)?;
        match openat_directory(self.file.as_raw_fd(), name) {
            Ok(file) => Ok(Some(Self {
                file,
                display_path: self.display_path.join(name),
            })),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn open_dir(&self, name: &str) -> io::Result<Self> {
        self.try_open_dir(name)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("directory is unavailable: {name}"),
            )
        })
    }

    pub(crate) fn ensure_dir(&self, name: &str) -> io::Result<Self> {
        validate_name(name)?;
        match self.try_open_dir(name) {
            Ok(Some(directory)) => {
                directory.set_private_permissions()?;
                Ok(directory)
            }
            Ok(None) => {
                mkdirat(self.file.as_raw_fd(), name)?;
                let directory = self.open_dir(name)?;
                directory.set_private_permissions()?;
                Ok(directory)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn create_dir(&self, name: &str) -> io::Result<Self> {
        validate_name(name)?;
        mkdirat(self.file.as_raw_fd(), name)?;
        let directory = self.open_dir(name)?;
        directory.set_private_permissions()?;
        Ok(directory)
    }

    pub(crate) fn create_file(&self, name: &str) -> io::Result<File> {
        self.create_file_with_flags(name, libc::O_WRONLY)
    }

    pub(crate) fn create_read_write_file(&self, name: &str) -> io::Result<File> {
        self.create_file_with_flags(name, libc::O_RDWR)
    }

    fn create_file_with_flags(&self, name: &str, access: i32) -> io::Result<File> {
        validate_name(name)?;
        let file = openat_file(
            self.file.as_raw_fd(),
            name,
            access | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        require_regular(&file)?;
        set_file_mode(&file, 0o600)?;
        Ok(file)
    }

    pub(crate) fn remove_file(&self, name: &str) -> io::Result<()> {
        let name = c_name(name)?;
        let result = unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) };
        if result == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(crate) fn remove_dir(&self, name: &str) -> io::Result<()> {
        let name = c_name(name)?;
        let result =
            unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
        if result == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(crate) fn open_file(&self, name: &str) -> io::Result<File> {
        validate_name(name)?;
        let file = openat_file(self.file.as_raw_fd(), name, libc::O_RDONLY, 0)?;
        require_regular(&file)?;
        Ok(file)
    }

    pub(crate) fn try_open_file(&self, name: &str) -> io::Result<Option<File>> {
        match self.open_file(name) {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn write_new(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let mut file = self.create_file(name)?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    pub(crate) fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }

    pub(crate) fn same_directory(&self, other: &Self) -> io::Result<bool> {
        let left = self.file.metadata()?;
        let right = other.file.metadata()?;
        use std::os::unix::fs::MetadataExt;
        Ok(left.dev() == right.dev() && left.ino() == right.ino())
    }

    pub(crate) fn names(&self) -> io::Result<Vec<OsString>> {
        let proc_path = PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()));
        fs::read_dir(proc_path)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect()
    }

    pub(crate) fn create_private_temp_dir(
        parent_path: &Path,
        prefix: &str,
    ) -> io::Result<(Self, String, Self)> {
        let parent = Self::open(parent_path)?;
        let mut random = File::open("/dev/urandom")?;
        for _ in 0..32 {
            let mut bytes = [0_u8; 16];
            random.read_exact(&mut bytes)?;
            let suffix = bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let name = format!("{prefix}-{suffix}");
            match parent.create_dir(&name) {
                Ok(directory) => return Ok((parent, name, directory)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a private temporary directory",
        ))
    }

    fn set_private_permissions(&self) -> io::Result<()> {
        set_file_mode(&self.file, 0o700)
    }
}

pub(crate) fn rename_entry(
    source: &PrivateDir,
    source_name: &str,
    destination: &PrivateDir,
    destination_name: &str,
) -> io::Result<()> {
    let source_name = c_name(source_name)?;
    let destination_name = c_name(destination_name)?;
    let result = unsafe {
        libc::renameat(
            source.file.as_raw_fd(),
            source_name.as_ptr(),
            destination.file.as_raw_fd(),
            destination_name.as_ptr(),
        )
    };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn file_len(file: &File) -> io::Result<u64> {
    require_regular(file)?;
    Ok(file.metadata()?.len())
}

pub(crate) fn read_range(file: &File, start: u64, end: u64) -> io::Result<Vec<u8>> {
    let length = usize::try_from(end.saturating_sub(start))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "range is too large"))?;
    let mut data = vec![0_u8; length];
    file.read_exact_at(&mut data, start)?;
    Ok(data)
}

pub(crate) fn sha256_file(file: &File) -> io::Result<String> {
    let mut file = file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; CHUNK_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn walk_directory(path: &Path, create: bool) -> io::Result<PrivateDir> {
    let absolute = path.is_absolute();
    let mut current = open_directory_path(if absolute {
        Path::new("/")
    } else {
        Path::new(".")
    })?;
    let mut display_path = if absolute {
        PathBuf::from("/")
    } else {
        PathBuf::from(".")
    };
    for component in path.components() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::RootDir | Component::CurDir) {
                continue;
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("unsafe directory path: {}", path.display()),
            ));
        };
        let name = name.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "directory path must be UTF-8")
        })?;
        validate_name(name)?;
        let next = match openat_directory(current.as_raw_fd(), name) {
            Ok(file) => file,
            Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                mkdirat(current.as_raw_fd(), name)?;
                openat_directory(current.as_raw_fd(), name)?
            }
            Err(error) => return Err(error),
        };
        current = next;
        display_path.push(name);
    }
    let display_path = if path.as_os_str().is_empty() {
        display_path
    } else {
        path.to_path_buf()
    };
    Ok(PrivateDir {
        file: current,
        display_path,
    })
}

fn open_directory_path(path: &Path) -> io::Result<File> {
    let encoded = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let descriptor = unsafe {
        libc::open(
            encoded.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    descriptor_file(descriptor)
}

fn openat_directory(parent: i32, name: &str) -> io::Result<File> {
    let name = c_name(name)?;
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    descriptor_file(descriptor)
}

fn openat_file(parent: i32, name: &str, flags: i32, mode: libc::mode_t) -> io::Result<File> {
    let name = c_name(name)?;
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    descriptor_file(descriptor)
}

fn mkdirat(parent: i32, name: &str) -> io::Result<()> {
    let name = c_name(name)?;
    let result = unsafe { libc::mkdirat(parent, name.as_ptr(), 0o700) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn descriptor_file(descriptor: i32) -> io::Result<File> {
    if descriptor == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn require_regular(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if metadata.file_type().is_file() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "artifact is not a regular file",
        ))
    }
}

fn set_file_mode(file: &File, mode: libc::mode_t) -> io::Result<()> {
    if unsafe { libc::fchmod(file.as_raw_fd(), mode) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn c_name(name: &str) -> io::Result<CString> {
    validate_name(name)?;
    CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))
}

fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty() || matches!(name, "." | "..") || name.as_bytes().contains(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe directory entry name",
        ));
    }
    if name.as_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory entry contains NUL",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{rename_entry, PrivateDir};
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("outctl-storage-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn pinned_directory_does_not_follow_replacement_path() {
        let root = temporary_root();
        let attacker = root.with_extension("attacker");
        let moved = root.with_extension("moved");
        fs::create_dir(&attacker).unwrap();
        let directory = PrivateDir::ensure(&root).unwrap();
        fs::rename(&root, &moved).unwrap();
        symlink(&attacker, &root).unwrap();

        directory.write_new("evidence", b"original").unwrap();
        assert_eq!(fs::read(moved.join("evidence")).unwrap(), b"original");
        assert!(!attacker.join("evidence").exists());

        fs::remove_file(&root).unwrap();
        fs::remove_dir_all(&moved).unwrap();
        fs::remove_dir_all(&attacker).unwrap();
    }

    #[test]
    fn no_follow_file_open_rejects_symlink() {
        let root = temporary_root();
        let outside = root.with_extension("outside");
        fs::write(&outside, b"secret").unwrap();
        let directory = PrivateDir::ensure(&root).unwrap();
        symlink(&outside, root.join("artifact")).unwrap();
        assert!(directory.open_file("artifact").is_err());
        fs::remove_dir_all(&root).unwrap();
        fs::remove_file(&outside).unwrap();
    }

    #[test]
    fn finalization_rename_stays_between_pinned_parent_directories() {
        let root = temporary_root();
        let moved = root.with_extension("moved");
        let attacker = root.with_extension("attacker");
        fs::create_dir(&attacker).unwrap();
        let root_directory = PrivateDir::ensure(&root).unwrap();
        let partial_root = root_directory.ensure_dir("partial").unwrap();
        let captures_root = root_directory.ensure_dir("captures").unwrap();
        let partial = partial_root.create_dir("capture.partial").unwrap();
        partial.write_new("evidence", b"original").unwrap();

        fs::rename(&root, &moved).unwrap();
        symlink(&attacker, &root).unwrap();
        rename_entry(&partial_root, "capture.partial", &captures_root, "capture").unwrap();

        assert_eq!(
            fs::read(moved.join("captures/capture/evidence")).unwrap(),
            b"original"
        );
        assert!(!attacker.join("captures/capture").exists());
        fs::remove_file(&root).unwrap();
        fs::remove_dir_all(&moved).unwrap();
        fs::remove_dir_all(&attacker).unwrap();
    }
}
