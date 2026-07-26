//! A CIP object instance: a numbered container of attributes belonging to a
//! [`CipClass`]. Instance IDs are unique within a class; instance 0 is the
//! class-level container (revision, max-instance, class attributes).

use std::collections::BTreeMap;

use crate::cip::attribute::CipAttribute;

/// A CIP object instance.
#[derive(Debug, Default)]
pub struct CipInstance {
    pub id: u32,
    // BTreeMap so `Get_Attributes_All` iterates in ascending attribute-id
    // order without needing to sort explicitly — matches C# and C++ where
    // attributes come back to the wire in id order.
    attributes: BTreeMap<u16, CipAttribute>,
}

impl CipInstance {
    /// Create an empty instance with the given id.
    pub fn new(id: u32) -> Self {
        Self { id, attributes: BTreeMap::new() }
    }

    /// Register an attribute on this instance. If the id already existed it
    /// is replaced.
    pub fn add_attribute(&mut self, attr: CipAttribute) {
        self.attributes.insert(attr.id, attr);
    }

    /// Look up an attribute by id.
    pub fn get_attribute(&self, id: u16) -> Option<&CipAttribute> {
        self.attributes.get(&id)
    }

    /// Mutably look up an attribute by id — used by service handlers that
    /// want to write back a computed value.
    pub fn get_attribute_mut(&mut self, id: u16) -> Option<&mut CipAttribute> {
        self.attributes.get_mut(&id)
    }

    /// Iterate every attribute in ascending id order.
    pub fn attributes(&self) -> impl Iterator<Item = &CipAttribute> {
        self.attributes.values()
    }
}
