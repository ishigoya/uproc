use std::collections::HashMap;
use fuser::FileAttr;
use std::cell::Cell;
use std::ffi::{OsStr, OsString};

// https://stackoverflow.com/a/36168919
#[derive(Debug)]
pub struct Node {
    pub data: Cell<FileAttr>,
    children: HashMap<OsString, Node>,
}

impl Node {
    pub fn new(data: FileAttr) -> Node {
        Node { data: Cell::new(data), children: HashMap::new() }
    }

    fn add_child(&mut self, name: &OsStr, child: Node) -> Result<(), ()> {
        match self.children.contains_key(name) {
            false => {
                    self.children.insert(name.to_os_string(), child);
                    Ok(())
            },
            true => Err(())
        }
    }
}


#[derive(Debug)]
struct ParentInfo {
    node: Box<NodeZipper>,
    child_key_in_parent: OsString,
}


#[derive(Debug)]
pub struct NodeZipper {
    pub node: Node,
    parent: Option<ParentInfo>,
}


impl NodeZipper {
    pub fn child(mut self, name: &OsStr) -> Result<NodeZipper, NodeZipper> {
        // Remove the specified child from the node's children.
        // A NodeZipper shouldn't let its users inspect its parent,
        // since we mutate the parents
        // to move the focused nodes out of their list of children.
        // We use swap_remove() for efficiency.
        match self.node.children.remove_entry(name) {
            Some((key, child)) => {
                Ok(NodeZipper {
                    node: child,
                    parent: Some(ParentInfo { node: Box::new(self), 
                                              child_key_in_parent: key })
                })
            },
            None => Err(self), // close me or bad things will happen!
        }
    }

    pub fn get_children(&self) -> Vec<OsString> {
        self.node.children.keys().cloned().collect()
    }

    pub fn parent(self) -> NodeZipper {
        // Destructure this NodeZipper
        let NodeZipper { node, parent } = self;

        let ParentInfo {
            node: mut parent_node,
            child_key_in_parent: name,
        } = parent.unwrap();

        let _ = parent_node.node.add_child(&name, node);

        // Return a new NodeZipper focused on the parent.
        NodeZipper {
            node: parent_node.node,
            parent: parent_node.parent,
        }
    }

    pub fn finish(mut self) -> Node {
        while self.parent.is_some() {
            self = self.parent();
        }

        self.node
    }

    pub fn add_child(mut self, name: &OsStr, node: Node) -> NodeZipper {
        self.node.add_child(name, node).unwrap();
        self
    }
}

impl Node {
    pub fn zipper(self) -> NodeZipper {
        NodeZipper { node: self, parent: None }
    }
}
