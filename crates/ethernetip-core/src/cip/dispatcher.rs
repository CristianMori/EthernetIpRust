//! Top-level CIP object router. Owns a set of [`CipClass`] instances keyed by
//! class code and resolves each incoming Message Router request through
//! `class → instance → service → handler`. Wrapped in a `Mutex` so
//! multiple sessions can share one dispatcher without external
//! synchronization.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::cip::class::CipClass;
use crate::cip::path::CipPath;
use crate::cip::service::{CipServiceRequest, CipServiceResponse};
use crate::cip::status;

/// A CIP object dispatcher — holds the class registry and answers requests
/// by walking the object tree.
#[derive(Debug, Default)]
pub struct CipDispatcher {
    classes: Mutex<HashMap<u16, CipClass>>,
}

impl CipDispatcher {
    /// Create an empty dispatcher. Register classes with
    /// [`CipDispatcher::register_class`] before use.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a class. If a class with the same class code was already
    /// registered it's replaced — matches the C# implementation.
    pub fn register_class(&self, class: CipClass) {
        self.classes
            .lock()
            .expect("CipDispatcher classes mutex poisoned")
            .insert(class.class_code, class);
    }

    /// Route a Message Router request to the matching class + instance +
    /// service. Returns:
    ///
    /// * `PATH_DESTINATION_UNKNOWN` (0x05) when the path has no class
    ///   segment or the class code isn't registered.
    /// * `OBJECT_DOES_NOT_EXIST` (0x16) when the class exists but the
    ///   instance id isn't registered.
    /// * `SERVICE_NOT_SUPPORTED` (0x08) when the class + instance resolves
    ///   but the service code has no handler.
    pub fn dispatch(&self, service_code: u8, path: CipPath, data: Vec<u8>) -> CipServiceResponse {
        let Some(class_id) = path.class_id else {
            return CipServiceResponse::error(service_code, status::PATH_DESTINATION_UNKNOWN);
        };
        let class_id16 = class_id as u16;
        let instance_id = path.instance_id.unwrap_or(0);
        let is_class_level = instance_id == 0;

        let mut guard = self
            .classes
            .lock()
            .expect("CipDispatcher classes mutex poisoned");
        let Some(class) = guard.get_mut(&class_id16) else {
            return CipServiceResponse::error(service_code, status::PATH_DESTINATION_UNKNOWN);
        };

        let handler = match class.get_service(service_code, is_class_level) {
            Some(svc) => svc.handler.clone(),
            None => return CipServiceResponse::error(service_code, status::SERVICE_NOT_SUPPORTED),
        };

        let Some(instance) = class.get_instance_mut(instance_id) else {
            return CipServiceResponse::error(service_code, status::OBJECT_DOES_NOT_EXIST);
        };

        let request = CipServiceRequest {
            service_code,
            path,
            data,
        };
        handler(instance, &request)
    }

    /// True when the given class code is registered — useful in the safety
    /// adapter to decide whether to route or fall through to the old inline
    /// handler.
    pub fn has_class(&self, class_code: u16) -> bool {
        self.classes
            .lock()
            .expect("CipDispatcher classes mutex poisoned")
            .contains_key(&class_code)
    }

    /// Give a scoped mutable reference to an instance inside a registered
    /// class. Returns `None` when the class isn't registered or the
    /// instance id isn't present. Handy when a caller has already handed a
    /// class over to the dispatcher and now wants to push state into one
    /// of its attributes — e.g. a Safety Supervisor whose `start()` needs
    /// to update the State (attr 1) and Mode (attr 2) attributes.
    pub fn with_instance_mut<F, R>(&self, class_code: u16, instance_id: u32, f: F) -> Option<R>
    where
        F: FnOnce(&mut crate::cip::instance::CipInstance) -> R,
    {
        let mut guard = self
            .classes
            .lock()
            .expect("CipDispatcher classes mutex poisoned");
        let class = guard.get_mut(&class_code)?;
        let instance = class.get_instance_mut(instance_id)?;
        Some(f(instance))
    }
}
