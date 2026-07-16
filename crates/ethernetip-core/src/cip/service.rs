//! CIP service dispatch types — the request/response pair passed between the
//! dispatcher and the per-instance handlers, plus the handler function type
//! and the definition record registered on a class.

use std::any::Any;
use std::sync::Arc;

use crate::cip::instance::CipInstance;
use crate::cip::path::CipPath;
use crate::cip::service_codes;

/// A CIP service request routed to a specific class + instance.
#[derive(Clone)]
pub struct CipServiceRequest {
    /// Original service code (without the reply bit).
    pub service_code: u8,
    /// Parsed request path — carries the class/instance/attribute the
    /// dispatcher used to reach this handler, plus any member id.
    pub path: CipPath,
    /// Service-specific body (what followed the path in the MR request).
    pub data: Vec<u8>,
    /// Optional per-request context. Handlers that need per-session state
    /// (peer socket address, an assembly registry, a transport socket)
    /// downcast this to whatever type the caller registered. Populated by
    /// [`crate::cip::CipDispatcher::dispatch_with_context`]; `None` when
    /// the request came through the plain `dispatch` entry point.
    pub context: Option<Arc<dyn Any + Send + Sync>>,
}

impl CipServiceRequest {
    /// Downcast the context to a concrete type. Returns `None` when the
    /// request has no context or when the concrete type doesn't match.
    pub fn context<T: Any + Send + Sync>(&self) -> Option<&T> {
        self.context.as_ref().and_then(|arc| arc.downcast_ref::<T>())
    }
}

impl std::fmt::Debug for CipServiceRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CipServiceRequest")
            .field("service_code", &self.service_code)
            .field("path", &self.path)
            .field("data_len", &self.data.len())
            .field("has_context", &self.context.is_some())
            .finish()
    }
}

/// A CIP service response — reply service code with the reply bit set, a
/// general status (plus optional extended-status words), and the
/// service-specific body.
#[derive(Debug, Clone)]
pub struct CipServiceResponse {
    /// Reply service code (original | 0x80).
    pub service_code: u8,
    /// General status byte (`status::SUCCESS` on success).
    pub general_status: u8,
    /// Additional status words (0 or more `u16` LE values, written after the
    /// header in the MR response).
    pub extended_status: Vec<u16>,
    /// Service-specific reply body.
    pub data: Vec<u8>,
}

impl CipServiceResponse {
    /// Success response with the reply bit set and no body.
    pub fn success(service_code: u8) -> Self {
        Self::success_with(service_code, Vec::new())
    }

    /// Success response with the reply bit set and a body.
    pub fn success_with(service_code: u8, data: Vec<u8>) -> Self {
        Self {
            service_code: service_code | service_codes::REPLY_FLAG,
            general_status: 0,
            extended_status: Vec::new(),
            data,
        }
    }

    /// Error response with the reply bit set and no extended status.
    pub fn error(service_code: u8, general_status: u8) -> Self {
        Self {
            service_code: service_code | service_codes::REPLY_FLAG,
            general_status,
            extended_status: Vec::new(),
            data: Vec::new(),
        }
    }

    /// Error response with the reply bit set and one extended-status word.
    pub fn error_ext(service_code: u8, general_status: u8, ext: u16) -> Self {
        Self {
            service_code: service_code | service_codes::REPLY_FLAG,
            general_status,
            extended_status: vec![ext],
            data: Vec::new(),
        }
    }

    /// Encode into MR response wire format:
    /// `reply_service, reserved(0), general_status, ext_size (words), ext_words..., data`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.extended_status.len() * 2 + self.data.len());
        out.push(self.service_code);
        out.push(0); // reserved
        out.push(self.general_status);
        out.push(self.extended_status.len() as u8);
        for w in &self.extended_status {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out.extend_from_slice(&self.data);
        out
    }
}

/// Handler function type. Wrapped in an `Arc` inside `CipServiceDefinition`
/// so a service can be shared across threads (or between class and instance
/// level). Takes `&mut CipInstance` so handlers can update attributes in
/// place — the Safety_Reset service, for example, clears CFUNID / owner-list
/// attributes directly on the instance it was routed to.
pub type CipServiceHandler =
    Arc<dyn Fn(&mut CipInstance, &CipServiceRequest) -> CipServiceResponse + Send + Sync>;

/// Binds a service code + human-readable name to a handler.
#[derive(Clone)]
pub struct CipServiceDefinition {
    pub service_code: u8,
    pub name: &'static str,
    pub handler: CipServiceHandler,
}

impl CipServiceDefinition {
    pub fn new<F>(service_code: u8, name: &'static str, handler: F) -> Self
    where
        F: Fn(&mut CipInstance, &CipServiceRequest) -> CipServiceResponse + Send + Sync + 'static,
    {
        Self {
            service_code,
            name,
            handler: Arc::new(handler),
        }
    }
}

impl std::fmt::Debug for CipServiceDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CipServiceDefinition")
            .field("service_code", &self.service_code)
            .field("name", &self.name)
            .finish()
    }
}
