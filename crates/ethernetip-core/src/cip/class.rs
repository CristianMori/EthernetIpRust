//! A CIP class — the object-type header that owns a set of numbered
//! instances and the services that operate on them. Class-level services
//! (registered via [`CipClass::add_class_service`]) target the class itself
//! (instance 0); instance-level services target any created instance.
//!
//! On construction the class gets a class-level instance (id 0) with the two
//! standard class attributes (revision as attr 1, current-max-instance as
//! attr 2) and the two standard class-level services
//! (`Get_Attribute_Single`, `Get_Attributes_All`).

use std::collections::HashMap;

use crate::cip::attribute::{AttributeAccess, CipAttribute};
use crate::cip::data_type::CipDataType;
use crate::cip::instance::CipInstance;
use crate::cip::service::CipServiceDefinition;
use crate::cip::standard_services;

/// A CIP class definition.
#[derive(Debug)]
pub struct CipClass {
    pub class_code: u16,
    pub name: &'static str,
    pub revision: u16,

    /// Instance 0 — holds class-level attributes (revision, max instance,
    /// vendor-specific class attributes). Kept separate from `instances` so a
    /// path with instance_id = 0 or an omitted instance segment routes here.
    class_instance: CipInstance,
    /// All non-zero instances of this class.
    instances: HashMap<u32, CipInstance>,
    /// Highest instance id ever created — mirrored into class attribute 2.
    max_instance_id: u32,

    /// Services that handle requests targeted at any instance of this class.
    instance_services: HashMap<u8, CipServiceDefinition>,
    /// Services that handle requests targeted at instance 0 (the class itself).
    class_services: HashMap<u8, CipServiceDefinition>,
}

impl CipClass {
    /// Create a class with the standard class-level attributes and services
    /// already wired up.
    pub fn new(class_code: u16, name: &'static str, revision: u16) -> Self {
        let mut class_instance = CipInstance::new(0);
        class_instance.add_attribute(CipAttribute::from_u16(
            1,
            CipDataType::Uint,
            AttributeAccess::READ,
            revision,
        ));
        class_instance.add_attribute(CipAttribute::from_u16(
            2,
            CipDataType::Uint,
            AttributeAccess::READ,
            0,
        ));

        let mut cls = Self {
            class_code,
            name,
            revision,
            class_instance,
            instances: HashMap::new(),
            max_instance_id: 0,
            instance_services: HashMap::new(),
            class_services: HashMap::new(),
        };
        cls.add_class_service(CipServiceDefinition::new(
            standard_services::GET_ATTRIBUTE_SINGLE,
            "Get_Attribute_Single",
            standard_services::handle_get_attribute_single,
        ));
        cls.add_class_service(CipServiceDefinition::new(
            standard_services::GET_ATTRIBUTES_ALL,
            "Get_Attributes_All",
            standard_services::handle_get_attributes_all,
        ));
        cls
    }

    /// Create and register a new instance. Updates class attribute 2
    /// (current max instance) so `Get_Attribute_Single` on instance 0 stays
    /// consistent.
    pub fn create_instance(&mut self, instance_id: u32) -> &mut CipInstance {
        self.instances.insert(instance_id, CipInstance::new(instance_id));
        self.update_max_instance(instance_id);
        self.instances.get_mut(&instance_id).unwrap()
    }

    /// Register an already-built instance (used when a handler needs to own
    /// the instance's data outside the class).
    pub fn add_instance(&mut self, instance: CipInstance) {
        let id = instance.id;
        self.instances.insert(id, instance);
        self.update_max_instance(id);
    }

    /// Remove an instance by id. Returns the removed instance, or `None`
    /// if it wasn't present. The class-level max-instance attribute (attr
    /// 2 on instance 0) is *not* rolled back — CIP allows instance ids to
    /// stay high-water-marked, and rescanning to find the new max would
    /// add lock-time to a call that's already on the connection-teardown
    /// path.
    pub fn remove_instance(&mut self, id: u32) -> Option<CipInstance> {
        self.instances.remove(&id)
    }

    fn update_max_instance(&mut self, id: u32) {
        if id <= self.max_instance_id {
            return;
        }
        self.max_instance_id = id;
        if let Some(attr) = self.class_instance.get_attribute_mut(2) {
            attr.set_data(&(id as u16).to_le_bytes());
        }
    }

    /// Look up an instance by id. `id == 0` returns the class-level instance.
    pub fn get_instance(&self, id: u32) -> Option<&CipInstance> {
        if id == 0 {
            Some(&self.class_instance)
        } else {
            self.instances.get(&id)
        }
    }

    /// Mutably look up an instance by id. Used by the dispatcher to hand a
    /// writable reference to service handlers.
    pub fn get_instance_mut(&mut self, id: u32) -> Option<&mut CipInstance> {
        if id == 0 {
            Some(&mut self.class_instance)
        } else {
            self.instances.get_mut(&id)
        }
    }

    /// Register a service available on every non-zero instance.
    pub fn add_instance_service(&mut self, svc: CipServiceDefinition) {
        self.instance_services.insert(svc.service_code, svc);
    }

    /// Register a service available on the class itself (instance 0).
    pub fn add_class_service(&mut self, svc: CipServiceDefinition) {
        self.class_services.insert(svc.service_code, svc);
    }

    /// Look up a service, class-level or instance-level based on whether the
    /// request path targets instance 0.
    pub fn get_service(&self, service_code: u8, is_class_level: bool) -> Option<&CipServiceDefinition> {
        if is_class_level {
            self.class_services.get(&service_code)
        } else {
            self.instance_services.get(&service_code)
        }
    }

    /// Convenience: wire the three standard instance-level services
    /// (`Get_Attribute_Single`, `Set_Attribute_Single`, `Get_Attributes_All`)
    /// onto this class.
    pub fn add_standard_instance_services(&mut self) {
        self.add_instance_service(CipServiceDefinition::new(
            standard_services::GET_ATTRIBUTE_SINGLE,
            "Get_Attribute_Single",
            standard_services::handle_get_attribute_single,
        ));
        self.add_instance_service(CipServiceDefinition::new(
            standard_services::SET_ATTRIBUTE_SINGLE,
            "Set_Attribute_Single",
            standard_services::handle_set_attribute_single,
        ));
        self.add_instance_service(CipServiceDefinition::new(
            standard_services::GET_ATTRIBUTES_ALL,
            "Get_Attributes_All",
            standard_services::handle_get_attributes_all,
        ));
    }
}
