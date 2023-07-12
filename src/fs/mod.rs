use libc::{EPERM, ENOSYS, c_int};
use log::{debug, warn};
use std::ffi::{OsStr};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, SystemTime};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Sender, Receiver};
use std::iter::zip;
use std::cell::Cell;
use std::io;
use std::fs::OpenOptions;

use fuser::{TimeOrNow, Filesystem, FileAttr, KernelConfig, FUSE_ROOT_ID, 
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyAttr, Request, ReplyData, ReplyDirectory, ReplyCreate, ReplyLock, ReplyIoctl, ReplyLseek,
};
use fuser::consts::{FOPEN_DIRECT_IO, FUSE_HANDLE_KILLPRIV};

mod file;
mod zipper;

use file::{FileKind, UPPath};
use zipper::{Node, NodeZipper};

const FMODE_EXEC: i32 = 0x20;


pub struct Msg {
    pub path: PathBuf,
    pub content: Option<String>,
}

struct InodeVals {
    gen: u64,
    path: Option<UPPath>,
}

#[derive(Copy, Clone, Debug)]
pub enum FileHandle {
    Read,
    Write,
    ReadAndWrite,
    NoRW,
}

impl FileHandle {
    fn new(read: bool, write: bool) -> FileHandle {
        match (read, write) {
            (true, false)  => FileHandle::Read,
            (true, true)   => FileHandle::ReadAndWrite,
            (false, true)  => FileHandle::Write,
            (false, false) => FileHandle::NoRW,
        }
    }

    fn can_read(self) -> bool {
        match self {
            FileHandle::Read => true,
            FileHandle::ReadAndWrite => true,
            FileHandle::Write => false,
            FileHandle::NoRW => false,
        }
    }

    fn can_write(self) -> bool {
        match self {
            FileHandle::Read => false,
            FileHandle::ReadAndWrite => true,
            FileHandle::Write => true,
            FileHandle::NoRW => false,
        }
    }
}


pub struct UProcFS {
    ino_store: Vec<InodeVals>,
    root_node: Cell<Option<Node>>,
    file_handles: Vec<Option<FileHandle>>,
    uid: u32,
    gid: u32,
    sender: Sender<Msg>,
    receiver: Receiver<String>,
}

impl UProcFS
{
    pub fn new(sender: Sender<Msg>, receiver: Receiver<String>) -> UProcFS {
        let metadata = std::fs::metadata("/proc/self");
        let uid = metadata.map(|m| m.uid()).unwrap();
        let metadata = std::fs::metadata("/proc/self");
        let gid = metadata.map(|m| m.gid()).unwrap();
        let root = FileKind::Directory;
        let _root_attrs = root.get_initial_file_attrs(FUSE_ROOT_ID.try_into().unwrap(), 0o700, uid, gid);
        UProcFS {
            // Adding a dud entry as FUSE_ROOT_ID = 1
            ino_store: vec![InodeVals {
                                    gen: 0,
                                    path: None,
                                }],
            // root node created in init()
            root_node: Cell::new(None),
              file_handles: Vec::new(),
                uid,
                gid,
                sender,
                receiver,
        }
    }

    pub fn touch_file(&self, path: &Path) -> io::Result<()> {
        match OpenOptions::new().create(true).write(true).open(path) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn get_path(&self, inode: usize) -> Result<UPPath, ()> {
        self.ino_store[inode].path.clone().ok_or(())
    }

    fn close_nodezipper(&self, zipper: NodeZipper) {
        self.root_node.set(Some(zipper.finish()));
        debug!("The zipper has finished");
    }

    fn get_nodezipper(&self, path: &UPPath) -> (Result<(), ()>, NodeZipper) {
        debug!("The nodezipper is going to {:?}", path);
        let node = self.root_node.replace(None).expect("the zipper should be closed after use");
        debug!("The zipper is on the root node");
        let mut zipper = node.zipper();
        for path_el in path.iter() {
            match zipper.child(path_el) {
                Ok(z) => zipper = z,
                Err(z) => return (Err(()), z),
            }
        };
        (Ok(()), zipper)
    }

    fn _getattr(&self, path: &UPPath) -> Result<FileAttr, ()> {
        let (res, zipper) = self.get_nodezipper(path);

        // if the result is an Error, the zipper is in the wrong place
        let attr = zipper.node.data.clone();
        self.close_nodezipper(zipper);
        match res {
            Ok(_) => Ok(attr.get()),
            Err(_) => Err(()),
        }
    }

    fn _getchildren(&self, path: &UPPath) -> Vec<UPPath> {
        let (_, zipper) = self.get_nodezipper(path);
        let children: Vec<UPPath> = zipper.get_children().iter().map(|x| UPPath::from((*x).clone())).collect();
        self.close_nodezipper(zipper);
        children
    }

    fn check_access(
        &self,
        attr: &FileAttr,
        mut access_mask: i32,
    ) -> bool {
        // F_OK tests for existence of file
        if access_mask == libc::F_OK {
            return true;
        }
        let file_mode = i32::from(attr.perm);
    
        // root is allowed to read & write anything
        if self.uid == 0 {
            // root only allowed to exec if one of the X bits is set
            access_mask &= libc::X_OK;
            access_mask -= access_mask & (file_mode >> 6);
            access_mask -= access_mask & (file_mode >> 3);
            access_mask -= access_mask & file_mode;
            return access_mask == 0;
        }
    
        if self.uid == attr.uid {
            access_mask -= access_mask & (file_mode >> 6);
        } else if self.gid == attr.gid {
            access_mask -= access_mask & (file_mode >> 3);
        } else {
            access_mask -= access_mask & file_mode;
        }
    
        access_mask == 0
    }

    fn update_attrs(&self, path: &UPPath, attr: &FileAttr) {
        let (_, zipper) = self.get_nodezipper(path);
        zipper.node.data.replace(*attr);
        self.close_nodezipper(zipper);
    }

    fn get_directory_content(&self, path: &UPPath) -> Vec<(UPPath, FileAttr)> {
        let mut attrs = Vec::<FileAttr>::new();
        let names = self._getchildren(path);
        for name in names.iter() {
            let mut full_path = path.clone();
            full_path.add(name.clone());
            attrs.push(self._getattr(&full_path).unwrap());
        }
        zip(names, attrs).collect()
    }

    fn lookup_name_and_attr(&self, parent_inode: Option<u64>, name: Option<&OsStr>) -> Result<(UPPath, FileAttr), ()> {
        if parent_inode.is_none() && name.is_none() {return Err(());};

        let mut path = match parent_inode {
            Some(inode) => match self.get_path(inode as usize) {
                                    Ok(p) => p,
                                    Err(_) => return Err(()),
                            },
            None => UPPath::from(name.unwrap()),
        };

        match name {
            Some(n) => path.add(UPPath::from(n)),
            None => (),
        };

        // implicit lookup against name
        let attr = match self._getattr(&path) {
            Ok(a) => a,
            Err(_) => return Err(()),
        };

        Ok((path, attr))
    }
    
    fn new_file(&mut self, path: &UPPath, inode: usize, gen: u64, attr: &FileAttr) {
        self.add_node(path, attr);
        self.ino_store.insert(inode, InodeVals{
            gen,
            path: Some(path.clone()),
        });
    }

    // allocate inode and return generation
    fn allocate_inode(&self) -> (usize, u64) {
        for (i, inode_data) in self.ino_store.iter().skip(1).enumerate() {
            if inode_data.path.is_none() {
                return (i, inode_data.gen+1);
            }
        }
        (self.ino_store.len(), 0)
    }

    fn add_node(&mut self, path: &UPPath, attr: &FileAttr) {
        let (_, zipper) = self.get_nodezipper(path);
        let returned_zipper = zipper.add_child(path.last(), Node::new(*attr));
        self.close_nodezipper(returned_zipper);
    }

    fn add_root_dot(&mut self, attr: &FileAttr) {
        let node = self.root_node.replace(None).expect("the zipper should be closed after use");
        let zipper = node.zipper();
        let returned_zipper = zipper.add_child(OsStr::new("."), Node::new(*attr));
        self.close_nodezipper(returned_zipper);
    }

    fn finish_dir_creation(&mut self, path: &UPPath, attrs: &FileAttr, parent_attrs: &FileAttr) {
        let mut dot = path.clone();
        dot.add(UPPath::from(".".to_string()));
        let mut dotdot = path.clone();
        dotdot.add(UPPath::from("..".to_string()));

        self.add_node(&dot, attrs);
        // TODO: do I need to iterate nlook for the parent?
        self.add_node(&dotdot, parent_attrs);
    }

    fn find_next_file_handle(&self) -> usize {
        for (fh, fh_type) in self.file_handles.iter().enumerate() {
            if fh_type.is_none() {
                return fh;
            }
        }
        self.file_handles.len()
    }

    fn allocate_next_file_handle(&mut self, read: bool, write: bool) -> u64 {
        let fh = self.find_next_file_handle();
        self.file_handles.insert(fh, Some(FileHandle::new(read, write)));
        fh as u64
    }
}

impl Filesystem for UProcFS
{
    /// Initialize filesystem.
    /// Called before any other filesystem method.
    /// The kernel module connection can be configured using the KernelConfig object
    fn init(&mut self, _req: &Request<'_>, config: &mut KernelConfig) -> Result<(), c_int> {
        config.add_capabilities(FUSE_HANDLE_KILLPRIV).unwrap();
        // if the inode store only has the dud value, no root
        if self.ino_store.len() == 1 {
            let root = FileKind::Directory;
            let root_attrs = root.get_initial_file_attrs(FUSE_ROOT_ID.try_into().unwrap(), 0o700, self.uid, self.gid);
            self.root_node.set(Some(Node::new(root_attrs)));
            self.ino_store.push(InodeVals {
                gen: 0,
                path: Some(UPPath::from("/".to_string())),

            });
            self.add_root_dot(&root_attrs);
        }
        debug!("init complete");

        Ok(())
    }

    /// Clean up filesystem.
    /// Called on filesystem exit.
    /// TODO
    fn destroy(&mut self) {}

    /// Look up a directory entry by name and get its attributes.
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        // 
        debug!("name lookup for {:?}", name);
        match self.lookup_name_and_attr(Some(parent), None) {
            Ok((_name, attr)) => {
                if !self.check_access(
                    &attr,
                    libc::X_OK,
                ) {
                    reply.error(libc::EACCES);
                    return;
                }
            },
            Err(_) => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let (_path, attrs) = match self.lookup_name_and_attr(Some(parent), Some(name)) {
            Ok(x) => x,
            Err(_) => {
                debug!("doesn't exist");
                reply.error(libc::ENOENT);
                return;
            }
        };
        // TODO: uncomment me and sort out this mess
//        let true_path = match name.len() {
//            x if x > MAX_NAME_LENGTH as usize => {
//                reply.error(libc::ENAMETOOLONG);
//                return;
//            },
//            x if x == 0 => self.get_path(parent as usize),
//            _ => Ok(name_comps.clone()),
//        };

        debug!("name lookup successful for {:?}, sending attrs", name);
        reply.entry(&Duration::new(0, 0), &attrs, self.ino_store[attrs.ino as usize].gen);
    }

    /// Get file attributes.
    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {

        match self.lookup_name_and_attr(Some(ino), None) {
            Ok((_, attr)) => {
                debug!("attrs: {:?}", attr);
                reply.attr(&Duration::new(0, 0), &attr);
            },
            Err(_) => {
                reply.error(libc::ENOENT);
            },
        };
    }

    /// Read symbolic link.
    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        debug!("[Not Implemented] readlink(ino: {:#x?})", ino);
        reply.error(ENOSYS);
        // if directory, read directory
        // if link, read link
        // if other, handle it
    }

    /// Create file node.
    /// Create a regular file, character device, block device, fifo or socket node.
    fn mknod(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        let file_type = match FileKind::from_u32(mode) {
            Ok(x) => x,
            Err(_) => {
                warn!("mknod() implementation is incomplete. Only supports regular files, symlinks, and directories. Got {:o}", mode);
                reply.error(libc::ENOSYS);
                return;
            },
        };

        match self.lookup_name_and_attr(Some(parent), Some(name)) {
            Ok(_) => {
                reply.error(libc::EEXIST);
                return;
            }
            _ => (),
        };

        let (parent_path, mut parent_attrs) = match self.lookup_name_and_attr(Some(parent), None) {
            Ok(x) => x,
            Err(_) => {
                reply.error(ENOSYS);
                return;
            },
        };

        let mut path = parent_path.clone();
        path.add(UPPath::from(name));

        if !self.check_access(
            &parent_attrs,
            libc::W_OK,
        ) {
            reply.error(libc::EACCES);
            return;
        }

        parent_attrs.mtime = SystemTime::now();
        self.update_attrs(&parent_path, &parent_attrs);

        let (inode, gen) = self.allocate_inode();
        let attrs = file_type.get_initial_file_attrs(inode, mode, self.uid, self.gid);
        debug!("attrs: {:?}", attrs);
        self.new_file(&path, inode, gen, &attrs);
        // TODO this is just for testing
//        self.ino_store[inode].bufhand = Some(BufHandler {read_handler: Some(Box::new(WhoAmI {})), write_handler: Some(Box::new(WhoAmI {}))});
        match file_type {
            FileKind::Directory => {
                self.finish_dir_creation(&path, &attrs, &parent_attrs);
                },
                _ => (),
        };

        // TODO: implement flags
        reply.entry(&Duration::new(0, 0), &attrs, gen);
    }

    /// Create a directory.
    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        debug!("mkdir() called with {:?} {:?} {:o}", parent, name, mode);
        let (parent_path, mut parent_attrs) = match self.lookup_name_and_attr(Some(parent), None) {
            Ok(x) => x,
            Err(_) => {
                // TODO check
                reply.error(1);
                return;
            },
        };
        let mut new_path = parent_path.clone();
        new_path.add(UPPath::from(name));
        if self._getchildren(&parent_path).contains(&new_path.last_as_uppath()) {
            reply.error(libc::EEXIST);
            return;
        }

        if !self.check_access(
            &parent_attrs,
            libc::W_OK,
        ) {
            reply.error(libc::EACCES);
            return;
        }
        parent_attrs.mtime = SystemTime::now();

        // TODO: do I need this check?
        if !(parent_attrs.kind == fuser::FileType::Directory) {
            reply.error(libc::EACCES);
            return;
        }

        self.update_attrs(&parent_path, &parent_attrs);


        let (inode, generation) = self.allocate_inode();
        let attrs = FileKind::Directory.get_initial_file_attrs(inode, mode, self.uid, self.gid);
        self.new_file(&new_path, inode, generation, &attrs);
        self.finish_dir_creation(&new_path, &attrs, &parent_attrs);

        reply.entry(&Duration::new(0, 0), &attrs, generation);
    }

    /// Remove a file.
    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        debug!(
            "[Not Implemented] unlink(parent: {:#x?}, name: {:?})",
            parent, name,
        );
        reply.error(ENOSYS);
    }

    /// Create a symbolic link.
    fn symlink(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        link: &Path,
        reply: ReplyEntry,
    ) {
        debug!(
            "[Not Implemented] symlink(parent: {:#x?}, name: {:?}, link: {:?})",
            parent, name, link,
        );
        reply.error(EPERM);
    }

    /// Create a hard link.
    fn link(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        newparent: u64,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        debug!(
            "[Not Implemented] link(ino: {:#x?}, newparent: {:#x?}, newname: {:?})",
            ino, newparent, newname
        );
        reply.error(EPERM);
    }

    /// Open a file.
    /// Open flags (with the exception of O_CREAT, O_EXCL, O_NOCTTY and O_TRUNC) are
    /// available in flags. Filesystem may store an arbitrary file handle (pointer, index,
    /// etc) in fh, and use this in other all other file operations (read, write, flush,
    /// release, fsync). Filesystem may also implement stateless file I/O and not store
    /// anything in fh. There are also some flags (direct_io, keep_cache) which the
    /// filesystem may set, to change the way the file is opened. See fuse_file_info
    /// structure in <fuse_common.h> for more details.
    fn open(&mut self, _req: &Request<'_>, inode: u64, flags: i32, reply: ReplyOpen) {
            debug!("open() called for {:?}", inode);
        let (access_mask, read, write) = match flags & libc::O_ACCMODE {
            libc::O_RDONLY => {
                // Behavior is undefined, but most filesystems return EACCES
                if flags & libc::O_TRUNC != 0 {
                    reply.error(libc::EACCES);
                    return;
                }
                if flags & FMODE_EXEC != 0 {
                    // Open is from internal exec syscall
                    (libc::X_OK, true, false)
                } else {
                    (libc::R_OK, true, false)
                }
            }
            libc::O_WRONLY => (libc::W_OK, false, true),
            libc::O_RDWR => (libc::R_OK | libc::W_OK, true, true),
            // Exactly one access mode flag must be specified
            _ => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        match self.lookup_name_and_attr(Some(inode), None) {
            Ok((_, attr)) => {
                if self.check_access(
                    &attr,
                    access_mask,
                ) {
                    let open_flags = FOPEN_DIRECT_IO;
//                    let open_flags = 0;
                    debug!("we did it, let's open 'er. This one can read ({:?}) and write ({:?})", read, write);
                    reply.opened(self.allocate_next_file_handle(read, write), open_flags);
                } else {
                    reply.error(libc::EACCES);
                }
            }
            // TODO: fix error code
            Err(_error_code) => reply.error(1),
        }
    }

    /// Read data.
    /// Read should send exactly the number of bytes requested except on EOF or error,
    /// otherwise the rest of the data will be substituted with zeroes. An exception to
    /// this is when the file has been opened in 'direct_io' mode, in which case the
    /// return value of the read system call will reflect the return value of this
    /// operation. fh will contain the value set by the open method, or will be undefined
    /// if the open method didn't set any value.
    ///
    /// flags: these are the file flags, such as O_SYNC. Only supported with ABI >= 7.9
    /// lock_owner: only supported with ABI >= 7.9
    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        _size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        assert!(offset >= 0);
        if !self.file_handles[fh as usize].unwrap().can_read() {
            reply.error(libc::EACCES);
            return;
        }

        let (path, _) = self.lookup_name_and_attr(Some(ino), None).unwrap();

        self.sender.send(Msg { path: path.into(), content: None }).unwrap();
        let mut output = self.receiver.recv().unwrap();
    
//        let mut output: Vec<u8> = match &self.ino_store[ino as usize].read_handler {
//            Some(r) => (*r.call()).to_vec(),
//            None => panic!(),
//        };
        if output.len() <= offset as usize {
            // TODO: check error
            debug!("here now");
            debug!("output len {:?}", output.len());
            reply.data(br"");
        } else {
            output.push('\n'); // newline character
            debug!("this time here");
            reply.data(output.as_bytes());
        }
    }

    /// Write data.
    /// Write should return exactly the number of bytes requested except on error. An
    /// exception to this is when the file has been opened in 'direct_io' mode, in
    /// which case the return value of the write system call will reflect the return
    /// value of this operation. fh will contain the value set by the open method, or
    /// will be undefined if the open method didn't set any value.
    ///
    /// write_flags: will contain FUSE_WRITE_CACHE, if this write is from the page cache. If set,
    /// the pid, uid, gid, and fh may not match the value that would have been sent if write cachin
    /// is disabled
    /// flags: these are the file flags, such as O_SYNC. Only supported with ABI >= 7.9
    /// lock_owner: only supported with ABI >= 7.9
    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        assert!(offset >= 0);
        debug!("file handle {:?}", self.file_handles[fh as usize]);
        if !self.file_handles[fh as usize].unwrap().can_write() {
            reply.error(libc::EACCES);
            return;
        }

//        match &self.ino_store[ino as usize].write_handler {
//            Some(w) => w.call(String::from_utf8_lossy(data).to_string()),
//            None => panic!(),
//        };
        let (path, _) = self.lookup_name_and_attr(Some(ino), None).unwrap();

        self.sender.send(Msg { path: path.into(), content: Some(String::from_utf8_lossy(data).to_string()) }).unwrap();
        reply.written(data.len() as u32);
        //} else {
        //    debug!("this time here");
        //    reply.data(&output);
        //}
    }

    /// Flush method.
    /// This is called on each close() of the opened file. Since file descriptors can
    /// be duplicated (dup, dup2, fork), for one open call there may be many flush
    /// calls. Filesystems shouldn't assume that flush will always be called after some
    /// writes, or that if will be called at all. fh will contain the value set by the
    /// open method, or will be undefined if the open method didn't set any value.
    /// NOTE: the name of the method is misleading, since (unlike fsync) the filesystem
    /// is not forced to flush pending writes. One reason to flush data, is if the
    /// filesystem wants to return write errors. If the filesystem supports file locking
    /// operations (setlk, getlk) it should remove all locks belonging to 'lock_owner'.
    fn flush(&mut self, _req: &Request<'_>, ino: u64, fh: u64, lock_owner: u64, reply: ReplyEmpty) {
    //    self.file_handles[fh as usize] = None;
    //    reply.ok();
        debug!(
            "[Not Implemented] flush(ino: {:#x?}, fh: {}, lock_owner: {:?})",
            ino, fh, lock_owner
        );
        reply.error(ENOSYS);
    }

    /// Release an open file.
    /// Release is called when there are no more references to an open file: all file
    /// descriptors are closed and all memory mappings are unmapped. For every open
    /// call there will be exactly one release call. The filesystem may reply with an
    /// error, but error values are not returned to close() or munmap() which triggered
    /// the release. fh will contain the value set by the open method, or will be undefined
    /// if the open method didn't set any value. flags will contain the same flags as for
    /// open.
    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        // change entry in file_handles
        reply.ok();
    }

    /// Read directory.
    /// Send a buffer filled using buffer.fill(), with size not exceeding the
    /// requested size. Send an empty buffer on end of stream. fh will contain the
    /// value set by the opendir method, or will be undefined if the opendir method
    /// didn't set any value.
    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        debug!("readdir() called with {:?}", ino);
        assert!(offset >= 0);
        let path = self.get_path(ino as usize).unwrap();

        for (index, entry) in self.get_directory_content(&path).iter().skip(offset as usize).enumerate() {
            let (name, attrs) = entry;
            debug!("entry info: name {:?}, attrs {:?}", name, attrs);
            let (inode, file_type) = (attrs.ino, attrs.kind);

            let buffer_full: bool = reply.add(
                inode,
                offset + index as i64 + 1,
                file_type,
                // TODO: check if this is correct
                name.last(),
            );

            if buffer_full {
                break;
            }
        }

        reply.ok();
    }

    /// Create and open a file.
    /// If the file does not exist, first create it with the specified mode, and then
    /// open it. Open flags (with the exception of O_NOCTTY) are available in flags.
    /// Filesystem may store an arbitrary file handle (pointer, index, etc) in fh,
    /// and use this in other all other file operations (read, write, flush, release,
    /// fsync). There are also some flags (direct_io, keep_cache) which the
    /// filesystem may set, to change the way the file is opened. See fuse_file_info
    /// structure in <fuse_common.h> for more details. If this method is not
    /// implemented or under Linux kernel versions earlier than 2.6.15, the mknod()
    /// and open() methods will be called instead.
    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        debug!(
            "[Not Implemented] create(parent: {:#x?}, name: {:?}, mode: {}, umask: {:#x?}, \
            flags: {:#x?})",
            parent, name, mode, umask, flags
        );
        reply.error(ENOSYS);
    }

    /// Set file attributes.
    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _mode: Option<u32>,
        uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        ctime: Option<SystemTime>,
        _fh: Option<u64>,
        crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let (path, attr) = match self.lookup_name_and_attr(Some(ino), None) {
            Ok(x) => x,
            Err(_) => {
                debug!("failed to get attrs");
                reply.error(ENOSYS);
                return;
            }
        };
        let new_attr = FileAttr {
                ino,
                size:   size.unwrap_or(      attr.size   ),
                blocks: attr.blocks ,
                atime:  match atime {
                    Some(time) => match time {
                        TimeOrNow::SpecificTime(t) => t,
                        TimeOrNow::Now => SystemTime::now(),
                    },
                    None => SystemTime::now(),
                },
                mtime:  match mtime {
                    Some(time) => match time {
                        TimeOrNow::SpecificTime(t) => t,
                        TimeOrNow::Now => SystemTime::now(),
                    },
                    None => SystemTime::now(),
                },
                ctime:  ctime.unwrap_or(attr.ctime  ),
                crtime: crtime.unwrap_or(attr.crtime ),
                kind:   attr.kind   ,
                perm:   attr.perm   ,
                nlink:  attr.nlink  ,
                uid:    uid.unwrap_or(       attr.uid    ),
                gid:    uid.unwrap_or(       attr.gid    ),
                rdev:          attr.rdev   ,
                blksize:attr.blksize,
                flags:  flags.unwrap_or(       attr.flags  ),
        };

        debug!("attrs {:?}", new_attr);

        self.update_attrs(&path, &new_attr);
        reply.attr(&Duration::new(0, 0), &new_attr);

    }

    /// Open a directory.
    /// Filesystem may store an arbitrary file handle (pointer, index, etc) in fh, and
    /// use this in other all other directory stream operations (readdir, releasedir,
    /// fsyncdir). Filesystem may also implement stateless directory I/O and not store
    /// anything in fh, though that makes it impossible to implement standard conforming
    /// directory stream operations in case the contents of the directory can change
    /// between opendir and releasedir.
    fn opendir(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let (access_mask, read, write) = match flags & libc::O_ACCMODE {
            libc::O_RDONLY => {
                // Behavior is undefined, but most filesystems return EACCES
                if flags & libc::O_TRUNC != 0 {
                    reply.error(libc::EACCES);
                    return;
                }
                (libc::R_OK, true, false)
            }
            libc::O_WRONLY => (libc::W_OK, false, true),
            libc::O_RDWR => (libc::R_OK | libc::W_OK, true, true),
            // Exactly one access mode flag must be specified
            _ => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        match self.lookup_name_and_attr(Some(ino), None) {
            Ok((_name, attr)) => {
                if self.check_access(&attr, access_mask) {
                    let open_flags = FOPEN_DIRECT_IO;
                    reply.opened(self.allocate_next_file_handle(read, write), open_flags);
                } else {
                    reply.error(libc::EACCES);
                }
            },
            Err(_error_code) => reply.error(1),
        }
    }


////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
///                 The following functions are not implemented                          ///
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
///
///
///                                  //           //
///                                ///          ///
///                               ////         ////
///                               |////       /////
///                               |))//;     /)))//;
///                              /)))))/;   /)))))/;
///                          .---`,))))/;  /)))))))/;
///                      __--\/6-  \`))/; |)))))))/;
///                     (----/    \\\``;  |))))))/;
///                        ~/-\  \\\\\``   \))))))/;
///                            \\\\\\\\`    |)))))/;
///                            |\\\\\\\\___/))))))/;__-------.
///                            //////|  %%_/))))))/;           \___,
///                           |||||||\   \%%%%VLK;:              \_. \
///                           |\\\\\\\\\                        |  | |
///                            \\\\\\\                          |  | |
///                             |\\\\               __|        /   / /
///                             | \\__\     \___----  |       |   / /
///                             |    / |     >     \   \      \  / /
///                             |   /  |    /       \   \      >/ /  ,,
///                             |   |  |   |         |   |    // /  //,
///                             |   |  |   |         |   |   /| |   |\\,
///                          _--'   _--'   |     _---_---'  |  \ \__/\|/
///                         (-(-===(-(-(===/    (-(-=(-(-(==/   \____/m
///
///
    /// Synchronize file contents.
    /// If the datasync parameter is non-zero, then only the user data should be flushed,
    /// not the meta data.
    fn fsync(&mut self, _req: &Request<'_>, ino: u64, fh: u64, datasync: bool, reply: ReplyEmpty) {
        debug!(
            "[Not Implemented] fsync(ino: {:#x?}, fh: {}, datasync: {})",
            ino, fh, datasync
        );
        reply.error(ENOSYS);
    }

    /// Release an open directory.
    /// For every opendir call there will be exactly one releasedir call. fh will
    /// contain the value set by the opendir method, or will be undefined if the
    /// opendir method didn't set any value.
    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        self.file_handles[fh as usize] = None;
        reply.ok();
    }

    /// Synchronize directory contents.
    /// If the datasync parameter is set, then only the directory contents should
    /// be flushed, not the meta data. fh will contain the value set by the opendir
    /// method, or will be undefined if the opendir method didn't set any value.
    fn fsyncdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        debug!(
            "[Not Implemented] fsyncdir(ino: {:#x?}, fh: {}, datasync: {})",
            ino, fh, datasync
        );
        reply.error(ENOSYS);
    }


    /// Check file access permissions.
    /// This will be called for the access() system call. If the 'default_permissions'
    /// mount option is given, this method is not called. This method is not called
    /// under Linux kernel versions 2.4.x
    fn access(&mut self, _req: &Request<'_>, ino: u64, mask: i32, reply: ReplyEmpty) {

        match self.lookup_name_and_attr(Some(ino), None) {
            Ok((_, attr)) => {
                if self.check_access(&attr, mask) {
                    debug!("access ok for access call");
                    reply.ok();
                } else {
                    reply.error(libc::EACCES);
                }
            }
//            Err(error_code) => reply.error(error_code),
//            TODO: get proper error response
            Err(()) => reply.error(1),
        }
    }


    /// Get file system statistics.
    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        reply.statfs(0, 0, 0, 0, 0, 512, 255, 0);
    }

    /// Test for a POSIX file lock.
    fn getlk(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        lock_owner: u64,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        reply: ReplyLock,
    ) {
        debug!(
            "[Not Implemented] getlk(ino: {:#x?}, fh: {}, lock_owner: {}, start: {}, \
            end: {}, typ: {}, pid: {})",
            ino, fh, lock_owner, start, end, typ, pid
        );
        reply.error(ENOSYS);
    }

    /// Acquire, modify or release a POSIX file lock.
    /// For POSIX threads (NPTL) there's a 1-1 relation between pid and owner, but
    /// otherwise this is not always the case.  For checking lock ownership,
    /// 'fi->owner' must be used. The l_pid field in 'struct flock' should only be
    /// used to fill in this field in getlk(). Note: if the locking methods are not
    /// implemented, the kernel will still allow file locking to work locally.
    /// Hence these are only interesting for network filesystems and similar.
    fn setlk(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        lock_owner: u64,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        sleep: bool,
        reply: ReplyEmpty,
    ) {
        debug!(
            "[Not Implemented] setlk(ino: {:#x?}, fh: {}, lock_owner: {}, start: {}, \
            end: {}, typ: {}, pid: {}, sleep: {})",
            ino, fh, lock_owner, start, end, typ, pid, sleep
        );
        reply.error(ENOSYS);
    }

    /// control device
    fn ioctl(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        flags: u32,
        cmd: u32,
        in_data: &[u8],
        out_size: u32,
        reply: ReplyIoctl,
    ) {
        debug!(
            "[Not Implemented] ioctl(ino: {:#x?}, fh: {}, flags: {}, cmd: {}, \
            in_data.len(): {}, out_size: {})",
            ino,
            fh,
            flags,
            cmd,
            in_data.len(),
            out_size,
        );
        reply.error(ENOSYS);
    }

    /// Preallocate or deallocate space to a file
    fn fallocate(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        length: i64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        debug!(
            "[Not Implemented] fallocate(ino: {:#x?}, fh: {}, offset: {}, \
            length: {}, mode: {})",
            ino, fh, offset, length, mode
        );
        reply.error(ENOSYS);
    }

    /// Reposition read/write file offset
    fn lseek(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        whence: i32,
        reply: ReplyLseek,
    ) {
        debug!(
            "[Not Implemented] lseek(ino: {:#x?}, fh: {}, offset: {}, whence: {})",
            ino, fh, offset, whence
        );
        reply.error(ENOSYS);
    }

    /// Copy the specified range from the source inode to the destination inode
    fn copy_file_range(
        &mut self,
        _req: &Request<'_>,
        ino_in: u64,
        fh_in: u64,
        offset_in: i64,
        ino_out: u64,
        fh_out: u64,
        offset_out: i64,
        len: u64,
        flags: u32,
        reply: ReplyWrite,
    ) {
        debug!(
            "[Not Implemented] copy_file_range(ino_in: {:#x?}, fh_in: {}, \
            offset_in: {}, ino_out: {:#x?}, fh_out: {}, offset_out: {}, \
            len: {}, flags: {})",
            ino_in, fh_in, offset_in, ino_out, fh_out, offset_out, len, flags
        );
        reply.error(ENOSYS);
    }

     fn rename(
         &mut self,
         _req: &Request,
         parent: u64,
         name: &OsStr,
         new_parent: u64,
         new_name: &OsStr,
         flags: u32,
         reply: ReplyEmpty,
     ) {
        debug!(
            "[Not Implemented] rename(parent: {:#x?}, name: {:?}, newparent: {:#x?}, \
            newname: {:?}, flags: {})",
            parent, name, new_parent, new_name, flags,
        );
        reply.error(ENOSYS);
     }


    /// Forget about an inode.
    /// The nlookup parameter indicates the number of lookups previously performed on
    /// this inode. If the filesystem implements inode lifetimes, it is recommended that
    /// inodes acquire a single reference on each lookup, and lose nlookup references on
    /// each forget. The filesystem may ignore forget calls, if the inodes don't need to
    /// have a limited lifetime. On unmount it is not guaranteed, that all referenced
    /// inodes will receive a forget message.
    fn forget(&mut self, _req: &Request<'_>, _ino: u64, _nlookup: u64) {}

    /// Like forget, but take multiple forget requests at once for performance. The default
    /// implementation will fallback to forget.
    #[cfg(feature = "abi-7-16")]
    fn batch_forget(&mut self, req: &Request<'_>, nodes: &[fuse_forget_one]) {
        for node in nodes {
            self.forget(req, node.nodeid, node.nlookup);
        }
    }

}
