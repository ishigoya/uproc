use core::slice::Iter;
use std::path::{Component};
use std::time::{SystemTime};
use std::convert::{From, Into};
use std::ffi::{OsString, OsStr};
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq)]
pub enum FileKind {
    File,
    NamedPipe,
    Directory,
    Symlink,
}


impl From<FileKind> for fuser::FileType {
    fn from(kind: FileKind) -> Self {
        match kind {
            FileKind::File => fuser::FileType::RegularFile,
            FileKind::NamedPipe => fuser::FileType::NamedPipe,
            FileKind::Directory => fuser::FileType::Directory,
            FileKind::Symlink => fuser::FileType::Symlink,
        }
    }
}

impl FileKind {
    pub fn from_u32(kind: u32) -> Result<Self, ()> {

        match kind & libc::S_IFMT {
            libc::S_IFREG => Ok(FileKind::File),
            libc::S_IFIFO => Ok(FileKind::NamedPipe),
            libc::S_IFDIR => Ok(FileKind::Directory),
            libc::S_IFLNK => Ok(FileKind::Symlink),
            _ => Err(()),
        }
    }

    pub fn get_initial_file_attrs(self, inode: usize, mode: u32, uid: u32, gid: u32) -> fuser::FileAttr {
        fuser::FileAttr {
            ino: inode as u64,
            size: 0,
            blocks: 0,
            atime: SystemTime::now(),
            mtime: SystemTime::now(),
            ctime: SystemTime::now(),
            crtime: SystemTime::now(),
            kind: self.into(),
            perm: (mode & !(libc::S_ISUID | libc::S_ISGID)) as u16,
            nlink: self.get_nlink(),
            uid, // 
            gid, // 
            rdev: 0,
            blksize: 0,
            flags: 0,
        }
    }

    fn get_nlink(self) -> u32 {
        match self {
            FileKind::File =>      1,
            FileKind::NamedPipe => 1,
            FileKind::Directory => 2,
            FileKind::Symlink =>   1,
        }
    }

    fn get_perm(self) -> u16 {
        match self {
            FileKind::File =>      0o600,
            FileKind::NamedPipe => 0o600,
            FileKind::Directory => 0o700,
            FileKind::Symlink =>   0o600,
        }
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct UPPath(Vec<OsString>);

impl UPPath {
    pub fn new(c: Vec<OsString>) -> UPPath {
        UPPath(c)
    }

    pub fn add(&mut self, mut path: UPPath) {
        self.0.append(&mut path.0);
    }

    pub fn last(&self) -> &OsStr {
        OsStr::new(self.0.last().unwrap())
    }

    pub fn last_as_uppath(&self) -> Self {
        UPPath::from(self.0.last().unwrap().to_owned())
    }

    pub fn iter(&self) -> Iter<OsString> {
        self.0.iter()
    }
}

impl From<PathBuf> for UPPath {
    fn from(path: PathBuf) -> Self {
        let new_path: Vec<OsString> = path.components()
                            .filter(|x| !matches!(x, Component::RootDir) )
                            .map(|x| x.as_os_str()
                                 .to_os_string()
                                 )
                            .collect();
        UPPath(new_path)
    }

}

impl From<&Path> for UPPath {
    fn from(path: &Path) -> Self {
        let new_path: Vec<OsString> = path.components()
                            .filter(|x| !matches!(x, Component::RootDir) )
                            .map(|x| x.as_os_str()
                                 .to_os_string()
                                 )
                            .collect();
        UPPath(new_path)
    }

}

impl From<String> for UPPath {
    fn from(path: String) -> Self {
        UPPath::from(PathBuf::from(path))
    }
}

impl From<OsString> for UPPath {
    fn from(path: OsString) -> Self {
        UPPath(vec![path])
    }
}

impl From<&OsStr> for UPPath {
    fn from(path: &OsStr) -> Self {
        UPPath::from(path.to_os_string())
    }
}

impl Into<PathBuf> for UPPath {
    fn into(self) -> PathBuf {
        let mut v = self.0.into_iter();
        let mut r = match v.next() {
            Some(x) => PathBuf::from(x),
            None => return PathBuf::new(),
        };

        for n in v.next() {
            r.push(&PathBuf::from(n))
        };
        r
    }

}

impl FromIterator<OsString> for UPPath {
    fn from_iter<I: IntoIterator<Item=OsString>>(iter: I) -> Self {
        let mut c = UPPath::new(vec![]);

        for i in iter {
            c.add(UPPath::from(i));
        }
        c
    }
}
