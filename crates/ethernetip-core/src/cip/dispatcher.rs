//! Top-level CIP object router. Owns a set of [`CipClass`] instances keyed by
//! class code and resolves each incoming Message Router request through
//! `class → instance → service → handler`. Wrapped in a `Mutex` so
//! multiple sessions can share one dispatcher without external
//! synchronization.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use crate::cip::class::CipClass;
use crate::cip::instance::CipInstance;
use crate::cip::path::CipPath;
use crate::cip::service::{CipServiceHandler, CipServiceRequest, CipServiceResponse};
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

    /// Acquire the classes guard, recovering transparently from mutex
    /// poisoning.
    ///
    /// `std::sync::Mutex` poisons itself if a thread panics while holding
    /// the guard; every subsequent `.lock()` then returns `Err`. The
    /// dispatcher has no invariants that a panicked handler could have
    /// left half-updated — the only mutation under this guard is inserting
    /// / looking up classes by id, and the per-handler mutation now runs
    /// against an instance that has been taken out of the map (see
    /// [`CipClass::take_instance_for_dispatch`]). Taking the inner guard
    /// on poisoning keeps the whole CIP handler fleet responsive instead
    /// of translating one panic into a permanent dispatcher-wide outage.
    fn classes_lock(&self) -> MutexGuard<'_, HashMap<u16, CipClass>> {
        self.classes.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Register a class. If a class with the same class code was already
    /// registered it's replaced — matches the C# implementation.
    pub fn register_class(&self, class: CipClass) {
        self.classes_lock().insert(class.class_code, class);
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
        self.dispatch_with_context(service_code, path, data, None)
    }

    /// Same as [`dispatch`] but passes a per-request context to the
    /// handler. Handlers that need per-session state (Forward_Open needs
    /// an assembly registry + a task spawner, for example) downcast the
    /// context via [`crate::cip::CipServiceRequest::context`] to whatever
    /// type the caller registered.
    pub fn dispatch_with_context(
        &self,
        service_code: u8,
        path: CipPath,
        data: Vec<u8>,
        context: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>,
    ) -> CipServiceResponse {
        let Some(class_id) = path.class_id else {
            return CipServiceResponse::error(service_code, status::PATH_DESTINATION_UNKNOWN);
        };
        let class_id16 = class_id as u16;
        let instance_id = path.instance_id.unwrap_or(0);
        let is_class_level = instance_id == 0;

        // Phase 1: under the classes lock, resolve service → handler and
        // pull the target instance out of the class. Dropping the guard
        // after this scope is critical — the handler must not run while
        // the dispatcher mutex is held, both so another thread can keep
        // dispatching through this same dispatcher during the call and so
        // that a handler which recursively dispatches (e.g. a service
        // that re-enters CipDispatcher for a different class) does not
        // deadlock itself.
        let (handler, mut instance): (CipServiceHandler, CipInstance) = {
            let mut guard = self.classes_lock();
            let Some(class) = guard.get_mut(&class_id16) else {
                return CipServiceResponse::error(service_code, status::PATH_DESTINATION_UNKNOWN);
            };
            let handler = match class.get_service(service_code, is_class_level) {
                Some(svc) => svc.handler.clone(),
                None => {
                    return CipServiceResponse::error(service_code, status::SERVICE_NOT_SUPPORTED)
                }
            };
            let Some(instance) = class.take_instance_for_dispatch(instance_id) else {
                return CipServiceResponse::error(service_code, status::OBJECT_DOES_NOT_EXIST);
            };
            (handler, instance)
        };

        let request = CipServiceRequest {
            service_code,
            path,
            data,
            context,
        };

        // RAII guard so a panic inside the handler still restores the
        // instance back to the class. Without it, a panic would both
        // poison the mutex (recoverable via `classes_lock`) AND leave the
        // instance missing — the next dispatch to the same id would wrongly
        // return `OBJECT_DOES_NOT_EXIST`.
        struct Restore<'a> {
            dispatcher: &'a CipDispatcher,
            class_id: u16,
            instance_id: u32,
            instance: Option<CipInstance>,
        }
        impl<'a> Drop for Restore<'a> {
            fn drop(&mut self) {
                if let Some(instance) = self.instance.take() {
                    let mut guard = self.dispatcher.classes_lock();
                    if let Some(class) = guard.get_mut(&self.class_id) {
                        class.restore_instance_for_dispatch(self.instance_id, instance);
                    }
                }
            }
        }
        let mut restore = Restore {
            dispatcher: self,
            class_id: class_id16,
            instance_id,
            instance: None,
        };

        let response = handler(&mut instance, &request);
        restore.instance = Some(instance);
        drop(restore);
        response
    }

    /// True when the given class code is registered — useful in the safety
    /// adapter to decide whether to route or fall through to the old inline
    /// handler.
    pub fn has_class(&self, class_code: u16) -> bool {
        self.classes_lock().contains_key(&class_code)
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
        let mut guard = self.classes_lock();
        let class = guard.get_mut(&class_code)?;
        let instance = class.get_instance_mut(instance_id)?;
        Some(f(instance))
    }

    /// Give a scoped mutable reference to a whole registered class.
    /// Callers use this to add new instances after the class has been
    /// handed to the dispatcher — the Safety Validator, for example,
    /// allocates a fresh instance every time a safety connection opens.
    pub fn with_class_mut<F, R>(&self, class_code: u16, f: F) -> Option<R>
    where
        F: FnOnce(&mut crate::cip::class::CipClass) -> R,
    {
        let mut guard = self.classes_lock();
        let class = guard.get_mut(&class_code)?;
        Some(f(class))
    }
}
