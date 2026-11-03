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

use std::sync::{Arc, Mutex, MutexGuard};

use ethernetip_core::cip::{
    class_codes, AttributeAccess, CipAttribute, CipClass, CipDataType, CipDispatcher,
};

/// Acquire a `std::sync::Mutex` guard, recovering transparently from
/// mutex poisoning.
///
/// `std::sync::Mutex` poisons itself if a thread panics while holding
/// the guard; every subsequent `.lock()` then returns `Err`. The
/// validator's internal maps have no half-committed invariants a
/// panicked write could leave behind (every insert / remove is a single
/// map operation), so recovering the inner guard keeps class 0x3A
/// usable instead of letting one panic translate into a permanent
/// validator-wide outage.
fn lock_recover<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

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
/// Upper bound on the Safety Validator instance id the allocator will
/// ever hand out. The on-wire path narrows the instance id back down to
/// a `u16` (`target_connection_serial` in the SafetyAppReply and the
/// `sv_inst` field on the active-connection record), so letting a u32
/// id ever exceed 0xFFFF would silently alias a different instance's
/// id on remove — `remove_instance_via_dispatcher(sv_inst)` would
/// target the wrong id and leak the real instance. Rust-port policy is
/// "fail loud at the wire boundary" — refuse the allocation here so
/// the FO path can reject the Forward_Open with a CIP resource error
/// instead of accepting it and later misrouting the close.
pub const MAX_SAFETY_VALIDATOR_ID: u32 = u16::MAX as u32;

#[derive(Debug)]
pub struct SafetyValidatorObject {
    cip_class: Option<CipClass>,
    /// Monotonic instance-id allocator. Starts at 0 so the first allocated
    /// instance is 1 (matches C#). Capped at [`MAX_SAFETY_VALIDATOR_ID`]
    /// so an id can always round-trip through the wire's u16 fields.
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
        // don't overlap. `alloc_instance_id` returns `None` once the
        // counter has used up the u16 half of the id space (see
        // [`MAX_SAFETY_VALIDATOR_ID`]), which is the only correct answer
        // once a later `sv_inst as u16` would alias a different id.
        let id = self.alloc_instance_id()?;
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
        lock_recover(&self.runtime).insert(id, init);
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
        // See `create_instance_local` — the allocator refuses to go past
        // [`MAX_SAFETY_VALIDATOR_ID`], which forces the FO handler to
        // reject the Forward_Open with a CIP resource error instead of
        // silently aliasing an existing id through the wire's u16
        // `target_connection_serial`.
        let id = self.alloc_instance_id()?;
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
        lock_recover(&self.runtime).insert(id, init);
        Some(id)
    }

    /// Read the current runtime state for an instance. Returns a clone
    /// because the caller usually just wants a snapshot for logging.
    pub fn runtime_state(&self, instance_id: u32) -> Option<SafetyValidatorInstanceState> {
        lock_recover(&self.runtime).get(&instance_id).cloned()
    }

    /// Remove a validator instance through a dispatcher that already
    /// holds this validator's class. Called by the safety adapter's
    /// Forward_Close handler so instances don't leak across
    /// connect / disconnect cycles. Returns `true` when the id existed
    /// in either the CIP class or the runtime map.
    pub fn remove_instance_via_dispatcher(
        &self,
        dispatcher: &CipDispatcher,
        instance_id: u32,
    ) -> bool {
        let removed_cip = dispatcher
            .with_class_mut(class_codes::SAFETY_VALIDATOR, |cls| {
                cls.remove_instance(instance_id).is_some()
            })
            .unwrap_or(false);
        let removed_runtime = lock_recover(&self.runtime).remove(&instance_id).is_some();
        removed_cip || removed_runtime
    }

    /// Mutate the runtime state for an instance under the internal lock.
    /// Silently drops when the instance id isn't registered.
    pub fn with_runtime_state<F>(&self, instance_id: u32, f: F)
    where
        F: FnOnce(&mut SafetyValidatorInstanceState),
    {
        if let Some(state) = lock_recover(&self.runtime).get_mut(&instance_id) {
            f(state);
        }
    }

    fn alloc_instance_id(&self) -> Option<u32> {
        let mut g = lock_recover(&self.next_instance_id);
        // Refuse the allocation when the next id would exceed what the
        // on-wire `target_connection_serial: u16` can carry — see
        // [`MAX_SAFETY_VALIDATOR_ID`]. The counter is left at its cap
        // so every subsequent call also fails, which is the correct
        // bounded-total behaviour for a safety device that can't
        // forget old instances until a FC removes them.
        if *g >= MAX_SAFETY_VALIDATOR_ID {
            return None;
        }
        *g += 1;
        Some(*g)
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
    fn alloc_instance_id_refuses_past_u16_max() {
        // The on-wire path narrows the instance id to a u16 twice
        // (SafetyAppReply.target_connection_serial, ActiveConnection.sv_inst),
        // so letting a u32 id climb past u16::MAX would silently alias a
        // different instance's id on remove. The allocator must therefore
        // return None once it reaches MAX_SAFETY_VALIDATOR_ID, and every
        // subsequent call must also return None — the counter is parked
        // at its cap, not reset.
        let val = SafetyValidatorObject::new();
        {
            let mut g = lock_recover(&val.next_instance_id);
            *g = MAX_SAFETY_VALIDATOR_ID - 1;
        }
        // Last legal id.
        assert_eq!(val.alloc_instance_id(), Some(MAX_SAFETY_VALIDATOR_ID));
        // Past the cap: every subsequent allocation refused.
        assert_eq!(val.alloc_instance_id(), None);
        assert_eq!(val.alloc_instance_id(), None);
        // Counter is still parked at the cap.
        assert_eq!(*lock_recover(&val.next_instance_id), MAX_SAFETY_VALIDATOR_ID);
    }

    #[test]
    fn create_instance_via_dispatcher_rejects_past_u16_max() {
        // End-to-end on the public API: a validator whose counter has
        // already reached the cap refuses to hand out a new instance,
        // and the CIP class picks up no row (so the FO handler can turn
        // the None into a CIP resource error).
        let mut val = SafetyValidatorObject::new();
        let dispatcher = Arc::new(CipDispatcher::new());
        {
            let mut g = lock_recover(&val.next_instance_id);
            *g = MAX_SAFETY_VALIDATOR_ID;
        }
        dispatcher.register_class(val.into_cip_class());
        let id = val.create_instance_via_dispatcher(
            &dispatcher,
            SafetyValidatorInstanceState::default(),
        );
        assert_eq!(id, None);
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
    fn remove_instance_drops_from_class_and_runtime() {
        let mut val = SafetyValidatorObject::new();
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(val.into_cip_class());
        let id = val
            .create_instance_via_dispatcher(&dispatcher, SafetyValidatorInstanceState::default())
            .unwrap();

        // Before remove: attribute lookup succeeds.
        let mut p = vec![0x20, 0x3A, 0x24, id as u8, 0x30, 0x01];
        // Assumes id fits in a byte for the test; it does (== 1).
        assert_eq!(id, 1);
        let r = dispatcher.dispatch(0x0E, CipPath::parse(&p).unwrap(), Vec::new());
        assert_eq!(r.general_status, status::SUCCESS);

        // Remove.
        assert!(val.remove_instance_via_dispatcher(&dispatcher, id));

        // After remove: attribute lookup gets OBJECT_DOES_NOT_EXIST.
        p = vec![0x20, 0x3A, 0x24, id as u8, 0x30, 0x01];
        let r = dispatcher.dispatch(0x0E, CipPath::parse(&p).unwrap(), Vec::new());
        assert_eq!(r.general_status, status::OBJECT_DOES_NOT_EXIST);
        // Runtime map is gone too.
        assert!(val.runtime_state(id).is_none());

        // Removing again returns false — nothing to remove.
        assert!(!val.remove_instance_via_dispatcher(&dispatcher, id));
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
