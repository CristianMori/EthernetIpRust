//! CIP Safety Validator Object (class 0x3A). One CIP instance per active
//! safety connection: attribute 1 is the validator state (Idle / Executing
//! / Faulted), attribute 2 is the validator type (client / server / combined,
//! zero here — we don't model the distinction yet).
//!
//! Ports from `EthernetIPSharp.Safety.SafetyValidatorObject`. Deliberately
//! thin — the safety-adapter still owns the per-connection PID / CID /
//! rollover state and the CRC verification path; this object exists so
//! commissioning tools can enumerate a connection's validator instance
//! via `Get_Attribute_Single` on class 0x3A. Runtime counters
//! (`packets_produced`, `crc_errors`, ...) live on
//! [`SafetyValidatorInstance`] but aren't wired into the data-path yet.

use std::sync::{Arc, Mutex};

use ethernetip_core::cip::{
    class_codes, AttributeAccess, CipAttribute, CipClass, CipDataType, CipDispatcher,
};

/// State of a Safety Validator instance (Vol 5 §5-3.6.1).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyValidatorState {
    Idle = 0,
    Executing = 1,
    Faulted = 2,
}

/// Per-connection runtime counters. Not exposed as CIP attributes yet —
/// the safety adapter owns the same numbers on its own connection row
/// and duplicating them here would drift. Kept as a placeholder for a
/// future wiring pass that routes the safety data path through the
/// validator instance so a scanner can read live counts via
/// `Get_Attribute_Single`.
#[derive(Debug, Default, Clone)]
pub struct SafetyValidatorInstanceState {
    pub state: SafetyValidatorState,
    pub pid_seed_s1: u8,
    pub pid_seed_s3: u16,
    pub pid_seed_s5: u32,
    pub rollover_count: u16,
    pub timestamp: u16,
    pub ping_count: u8,
    pub packets_produced: u32,
    pub packets_consumed: u32,
    pub crc_errors: u32,
}

impl Default for SafetyValidatorState {
    fn default() -> Self {
        SafetyValidatorState::Idle
    }
}

impl SafetyValidatorInstanceState {
    /// Advance the 128 µs timestamp, bumping [`Self::rollover_count`] on
    /// wrap. Matches the producer-side rollover convention used everywhere
    /// else in this crate.
    pub fn advance_timestamp(&mut self, increment: u16) {
        let prev = self.timestamp;
        self.timestamp = self.timestamp.wrapping_add(increment);
        if self.timestamp < prev {
            self.rollover_count = self.rollover_count.wrapping_add(1);
        }
    }
}

/// CIP Safety Validator Object (class 0x3A) — one per device, allocates
/// numbered per-connection instances on demand.
///
/// Construct once at device init, register on a [`CipDispatcher`] via
/// [`into_cip_class`], then either:
///
///  * call [`create_instance_local`] before registration for statically
///    known instances, or
///  * call [`create_instance_via_dispatcher`] after registration when a
///    safety connection opens (typical run-time path).
///
/// Each instance has attributes 1 (State) and 2 (Type). The optional
/// runtime state tracker is held separately on the validator object so
/// callers can update rollover / counters without going through the CIP
/// attribute layer.
#[derive(Debug)]
pub struct SafetyValidatorObject {
    cip_class: Option<CipClass>,
    /// Monotonic instance-id allocator. Starts at 0 so the first allocated
    /// instance is 1 (matches C#).
    next_instance_id: Arc<Mutex<u32>>,
    /// Runtime state for every allocated instance, keyed by instance id.
    /// Not visible via CIP today; kept here so a follow-up integration
    /// pass can wire it into the adapter's data path.
    runtime: Arc<Mutex<std::collections::HashMap<u32, SafetyValidatorInstanceState>>>,
}

impl SafetyValidatorObject {
    /// Build the class with no instances. Instances are added by
    /// [`Self::create_instance_local`] / [`Self::create_instance_via_dispatcher`].
    pub fn new() -> Self {
        let mut cls = CipClass::new(class_codes::SAFETY_VALIDATOR, "Safety Validator", 1);
        cls.add_standard_instance_services();
        Self {
            cip_class: Some(cls),
            next_instance_id: Arc::new(Mutex::new(0)),
            runtime: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Take the built [`CipClass`] so it can be registered on a
    /// dispatcher. Panics if called twice.
    pub fn into_cip_class(&mut self) -> CipClass {
        self.cip_class
            .take()
            .expect("SafetyValidatorObject::into_cip_class called twice")
    }

    /// Allocate a new instance directly on the still-owned CipClass. Only
    /// valid before [`Self::into_cip_class`] has consumed the class.
    /// Returns the assigned instance id.
    pub fn create_instance_local(&mut self, init: SafetyValidatorInstanceState) -> Option<u32> {
        // Allocate the id before the &mut CipClass borrow so both borrows
        // don't overlap.
        let id = self.alloc_instance_id();
        let cls = self.cip_class.as_mut()?;
        let inst = cls.create_instance(id);
        inst.add_attribute(CipAttribute::from_u8(
            1,
            CipDataType::Usint,
            AttributeAccess::READ,
            init.state as u8,
        ));
        inst.add_attribute(CipAttribute::from_u8(
            2,
            CipDataType::Usint,
            AttributeAccess::READ,
            0,
        ));
        self.runtime.lock().unwrap().insert(id, init);
        Some(id)
    }

    /// Allocate a new instance through a dispatcher that already holds
    /// this validator's class. Returns the assigned instance id, or `None`
    /// when the dispatcher doesn't have class 0x3A registered.
    pub fn create_instance_via_dispatcher(
        &self,
        dispatcher: &CipDispatcher,
        init: SafetyValidatorInstanceState,
    ) -> Option<u32> {
        let id = self.alloc_instance_id();
        let ok = dispatcher.with_class_mut(class_codes::SAFETY_VALIDATOR, |cls| {
            let inst = cls.create_instance(id);
            inst.add_attribute(CipAttribute::from_u8(
                1,
                CipDataType::Usint,
                AttributeAccess::READ,
                init.state as u8,
            ));
            inst.add_attribute(CipAttribute::from_u8(
                2,
                CipDataType::Usint,
                AttributeAccess::READ,
                0,
            ));
        });
        if ok.is_none() {
            return None;
        }
        self.runtime.lock().unwrap().insert(id, init);
        Some(id)
    }

    /// Read the current runtime state for an instance. Returns a clone
    /// because the caller usually just wants a snapshot for logging.
    pub fn runtime_state(&self, instance_id: u32) -> Option<SafetyValidatorInstanceState> {
        self.runtime.lock().unwrap().get(&instance_id).cloned()
    }

    /// Mutate the runtime state for an instance under the internal lock.
    /// Silently drops when the instance id isn't registered.
    pub fn with_runtime_state<F>(&self, instance_id: u32, f: F)
    where
        F: FnOnce(&mut SafetyValidatorInstanceState),
    {
        if let Some(state) = self.runtime.lock().unwrap().get_mut(&instance_id) {
            f(state);
        }
    }

    fn alloc_instance_id(&self) -> u32 {
        let mut g = self.next_instance_id.lock().unwrap();
        *g += 1;
        *g
    }
}

impl Default for SafetyValidatorObject {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethernetip_core::cip::{status, CipPath};

    #[test]
    fn state_default_is_idle() {
        assert_eq!(SafetyValidatorState::default(), SafetyValidatorState::Idle);
    }

    #[test]
    fn advance_timestamp_bumps_rollover_on_wrap() {
        let mut s = SafetyValidatorInstanceState::default();
        s.timestamp = 0xFF00;
        s.advance_timestamp(0x200); // wraps from 0xFF00 → 0x0100
        assert_eq!(s.timestamp, 0x0100);
        assert_eq!(s.rollover_count, 1);
        s.advance_timestamp(0x0080);
        assert_eq!(s.timestamp, 0x0180);
        assert_eq!(s.rollover_count, 1);
    }

    #[test]
    fn create_instance_local_before_register() {
        let mut val = SafetyValidatorObject::new();
        let id = val.create_instance_local(SafetyValidatorInstanceState {
            state: SafetyValidatorState::Executing,
            ..Default::default()
        });
        assert_eq!(id, Some(1));

        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(val.into_cip_class());

        // Get_Attribute_Single(class=0x3A, instance=1, attr=1) → Executing.
        let path = CipPath::parse(&[0x20, 0x3A, 0x24, 0x01, 0x30, 0x01]).unwrap();
        let r = dispatcher.dispatch(0x0E, path, Vec::new());
        assert_eq!(r.general_status, status::SUCCESS);
        assert_eq!(r.data, vec![SafetyValidatorState::Executing as u8]);
    }

    #[test]
    fn create_instance_via_dispatcher_after_register() {
        let mut val = SafetyValidatorObject::new();
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(val.into_cip_class());

        // First instance goes to id 1.
        let id = val.create_instance_via_dispatcher(
            &dispatcher,
            SafetyValidatorInstanceState::default(),
        );
        assert_eq!(id, Some(1));

        // Get_Attribute_Single(class=0x3A, instance=1, attr=2) → 0 (type).
        let path = CipPath::parse(&[0x20, 0x3A, 0x24, 0x01, 0x30, 0x02]).unwrap();
        let r = dispatcher.dispatch(0x0E, path, Vec::new());
        assert_eq!(r.general_status, status::SUCCESS);
        assert_eq!(r.data, vec![0]);
    }

    #[test]
    fn instance_ids_allocated_monotonically() {
        let mut val = SafetyValidatorObject::new();
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(val.into_cip_class());
        for expected in 1..=5 {
            let id = val
                .create_instance_via_dispatcher(&dispatcher, SafetyValidatorInstanceState::default());
            assert_eq!(id, Some(expected));
        }
    }

    #[test]
    fn with_runtime_state_updates_counters() {
        let mut val = SafetyValidatorObject::new();
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(val.into_cip_class());
        let id = val
            .create_instance_via_dispatcher(&dispatcher, SafetyValidatorInstanceState::default())
            .unwrap();
        val.with_runtime_state(id, |s| {
            s.packets_consumed = 42;
            s.crc_errors = 3;
        });
        let snap = val.runtime_state(id).unwrap();
        assert_eq!(snap.packets_consumed, 42);
        assert_eq!(snap.crc_errors, 3);
    }
}
