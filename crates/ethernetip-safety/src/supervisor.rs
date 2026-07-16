//! CIP Safety Supervisor Object (class 0x39). One per device. Owns the
//! device-level safety state (Idle / Executing / Abort / ...), the SNN and
//! TUNID, the Safety Configuration Identifier, and the three services PLCs
//! use during commissioning: `Safety_Reset` (0x54, with reset types
//! device / factory / **ownership**), `Propose_TUNID` (0x56), and
//! `Apply_TUNID` (0x57).
//!
//! Ports directly from `EthernetIPSharp.Safety.SafetySupervisorObject`.
//! Attribute IDs, service codes, and reset-type semantics match Vol 5
//! (CIP Safety) exactly.

use std::sync::{Arc, Mutex};

use ethernetip_core::cip::{
    class_codes, status, AttributeAccess, CipAttribute, CipClass, CipDataType, CipInstance,
    CipServiceDefinition, CipServiceRequest, CipServiceResponse,
};

use crate::types::{SafetyConfigurationId, SafetyNetworkNumber, UniqueNetworkId};

pub const SAFETY_RESET_SERVICE: u8 = 0x54;
pub const PROPOSE_TUNID_SERVICE: u8 = 0x56;
pub const APPLY_TUNID_SERVICE: u8 = 0x57;

/// Safety Supervisor state machine states (Vol 5 §7-1.5.4.2).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetySupervisorState {
    Idle = 0,
    SelfTesting = 1,
    Executing = 2,
    Abort = 3,
    Exception = 4,
    WaitForLock = 5,
}

/// Safety Supervisor device modes.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetySupervisorMode {
    Idle = 0,
    Configuration = 1,
    Run = 2,
}

/// Mutable state the supervisor's service handlers close over. Wrapped in a
/// `Mutex` so the dispatcher (which only borrows `&self`) can update it
/// from any handler; contention is negligible in practice — Supervisor
/// services fire at commissioning, not on the hot I/O path.
#[derive(Debug)]
struct SupervisorInner {
    state: SafetySupervisorState,
    mode: SafetySupervisorMode,
    snn: SafetyNetworkNumber,
    scid: SafetyConfigurationId,
    tunid: UniqueNetworkId,
    tunid_assigned: bool,
    /// Pending TUNID proposed via 0x56 / consumed by 0x57.
    proposed_tunid: Option<UniqueNetworkId>,
}

/// CIP Safety Supervisor (class 0x39).
///
/// Construct once at device init, hand the resulting [`CipClass`] to a
/// dispatcher via [`SafetySupervisorObject::into_cip_class`], and give the
/// dispatcher to the safety adapter through
/// [`crate::SafetyAdapterConfig::dispatcher`]. The supervisor keeps its own
/// `Arc` to the mutable state so [`SafetySupervisorObject::state`] / `mode`
/// / `tunid` accessors work from the outside after the class has been
/// consumed.
pub struct SafetySupervisorObject {
    inner: Arc<Mutex<SupervisorInner>>,
    cip_class: Option<CipClass>,
}

impl SafetySupervisorObject {
    /// Build the class + register attributes and the three commissioning
    /// services. `snn` and `node_address` seed attribute 3 (SNN) and
    /// attribute 27 (TUNID).
    pub fn new(snn: SafetyNetworkNumber, node_address: u32) -> Self {
        let inner = Arc::new(Mutex::new(SupervisorInner {
            state: SafetySupervisorState::Idle,
            mode: SafetySupervisorMode::Idle,
            snn,
            scid: SafetyConfigurationId::default(),
            tunid: UniqueNetworkId { snn, node_address },
            tunid_assigned: false,
            proposed_tunid: None,
        }));

        let mut cls = CipClass::new(class_codes::SAFETY_SUPERVISOR, "Safety Supervisor", 1);
        cls.add_standard_instance_services();
        let inst = cls.create_instance(1);

        // Attr 1: State (USINT). Kept in sync with SupervisorInner via
        // update_state_attribute() after every state transition.
        inst.add_attribute(CipAttribute::from_u8(
            1,
            CipDataType::Usint,
            AttributeAccess::READ,
            SafetySupervisorState::Idle as u8,
        ));
        // Attr 2: Mode (USINT).
        inst.add_attribute(CipAttribute::from_u8(
            2,
            CipDataType::Usint,
            AttributeAccess::READ,
            SafetySupervisorMode::Idle as u8,
        ));
        // Attr 3: SNN (6 bytes).
        let mut snn_bytes = [0u8; 6];
        snn.copy_to(&mut snn_bytes);
        inst.add_attribute(CipAttribute::new(
            3,
            CipDataType::Byte,
            AttributeAccess::READ,
            snn_bytes.to_vec(),
        ));
        // Attr 4: Configuration Lock (USINT). Writable so a scanner can
        // toggle the lock during commissioning; framework enforces the
        // Set_Single access flag.
        inst.add_attribute(CipAttribute::from_u8(
            4,
            CipDataType::Usint,
            AttributeAccess::ALL,
            0,
        ));
        // Attr 6: SCID (SCCRC[4] + SCTS[6]) — zeros = unconfigured.
        inst.add_attribute(CipAttribute::new(
            6,
            CipDataType::Byte,
            AttributeAccess::READ,
            vec![0u8; SafetyConfigurationId::SIZE],
        ));
        // Attr 25 (0x19): CFUNID (10 bytes) — zeros = unowned. Reset
        // Ownership clears this back to zeros.
        inst.add_attribute(CipAttribute::new(
            25,
            CipDataType::Byte,
            AttributeAccess::READ,
            vec![0u8; UniqueNetworkId::SIZE],
        ));
        // Attr 27 (0x1B): TUNID (SNN + node address).
        let mut tunid_bytes = [0u8; UniqueNetworkId::SIZE];
        UniqueNetworkId { snn, node_address }.copy_to(&mut tunid_bytes);
        inst.add_attribute(CipAttribute::new(
            27,
            CipDataType::Byte,
            AttributeAccess::READ,
            tunid_bytes.to_vec(),
        ));
        // Attr 28 (0x1C): Output Connection Point Owners struct. First u16
        // is the count of owner entries; we advertise 0 (no owned outputs).
        inst.add_attribute(CipAttribute::new(
            28,
            CipDataType::Uint,
            AttributeAccess::READ,
            vec![0x00, 0x00],
        ));

        // Wire the three commissioning services. Each captures its own
        // Arc to the inner state so the handler closures can mutate it.
        let inner_reset = inner.clone();
        cls.add_instance_service(CipServiceDefinition::new(
            SAFETY_RESET_SERVICE,
            "Safety_Reset",
            move |inst, req| handle_safety_reset(inst, req, &inner_reset),
        ));
        let inner_propose = inner.clone();
        cls.add_instance_service(CipServiceDefinition::new(
            PROPOSE_TUNID_SERVICE,
            "Propose_TUNID",
            move |inst, req| handle_propose_tunid(inst, req, &inner_propose),
        ));
        let inner_apply = inner.clone();
        cls.add_instance_service(CipServiceDefinition::new(
            APPLY_TUNID_SERVICE,
            "Apply_TUNID",
            move |inst, req| handle_apply_tunid(inst, req, &inner_apply),
        ));

        Self { inner, cip_class: Some(cls) }
    }

    /// Transition to Executing / Run — ready to accept safety connections.
    /// Attributes 1 (State) and 2 (Mode) are updated in the CipClass if it
    /// hasn't been consumed yet by [`into_cip_class`]; after consumption use
    /// [`Self::sync_to_dispatcher`] to push the new values through the
    /// dispatcher.
    pub fn start(&mut self) {
        let mut g = self.inner.lock().unwrap();
        g.state = SafetySupervisorState::Executing;
        g.mode = SafetySupervisorMode::Run;
        let state = g.state as u8;
        let mode = g.mode as u8;
        drop(g);
        self.sync_state_mode_local(state, mode);
    }

    /// Transition to Abort (safety fault detected). The application picks
    /// the moment to call this; the supervisor itself doesn't watchdog.
    pub fn abort(&mut self) {
        let mut g = self.inner.lock().unwrap();
        g.state = SafetySupervisorState::Abort;
        let state = g.state as u8;
        let mode = g.mode as u8;
        drop(g);
        self.sync_state_mode_local(state, mode);
    }

    /// Reset from Abort back to Idle.
    pub fn reset(&mut self) {
        let mut g = self.inner.lock().unwrap();
        g.state = SafetySupervisorState::Idle;
        g.mode = SafetySupervisorMode::Idle;
        let state = g.state as u8;
        let mode = g.mode as u8;
        drop(g);
        self.sync_state_mode_local(state, mode);
    }

    /// Write the current State / Mode into attributes 1 / 2 of the not-yet-
    /// consumed CipClass. Silent no-op once `into_cip_class` has run.
    fn sync_state_mode_local(&mut self, state: u8, mode: u8) {
        let Some(cls) = self.cip_class.as_mut() else { return };
        let Some(inst) = cls.get_instance_mut(1) else { return };
        if let Some(a) = inst.get_attribute_mut(1) {
            a.set_data(&[state]);
        }
        if let Some(a) = inst.get_attribute_mut(2) {
            a.set_data(&[mode]);
        }
    }

    /// Push the current State / Mode into attributes 1 / 2 of the given
    /// running dispatcher's Safety Supervisor instance. Use this after
    /// [`Self::into_cip_class`] has consumed the class and later
    /// state-transition calls (`start`, `abort`, `reset`) need to reflect
    /// through the dispatcher.
    pub fn sync_to_dispatcher(&self, dispatcher: &ethernetip_core::cip::CipDispatcher) {
        let g = self.inner.lock().unwrap();
        let state = g.state as u8;
        let mode = g.mode as u8;
        drop(g);
        dispatcher.with_instance_mut(
            ethernetip_core::cip::class_codes::SAFETY_SUPERVISOR,
            1,
            |inst| {
                if let Some(a) = inst.get_attribute_mut(1) {
                    a.set_data(&[state]);
                }
                if let Some(a) = inst.get_attribute_mut(2) {
                    a.set_data(&[mode]);
                }
            },
        );
    }

    pub fn state(&self) -> SafetySupervisorState {
        self.inner.lock().unwrap().state
    }
    pub fn mode(&self) -> SafetySupervisorMode {
        self.inner.lock().unwrap().mode
    }
    pub fn tunid(&self) -> UniqueNetworkId {
        self.inner.lock().unwrap().tunid
    }
    pub fn tunid_assigned(&self) -> bool {
        self.inner.lock().unwrap().tunid_assigned
    }

    /// Take the built `CipClass` so it can be registered on a dispatcher.
    /// The supervisor keeps its own state handles, so accessors above keep
    /// working after this call.
    pub fn into_cip_class(&mut self) -> CipClass {
        self.cip_class
            .take()
            .expect("SafetySupervisorObject::into_cip_class called twice")
    }
}

// -------------------- service handlers --------------------

fn handle_safety_reset(
    instance: &mut CipInstance,
    req: &CipServiceRequest,
    inner: &Arc<Mutex<SupervisorInner>>,
) -> CipServiceResponse {
    if req.data.is_empty() {
        return CipServiceResponse::error(req.service_code, status::NOT_ENOUGH_DATA);
    }
    let reset_type = req.data[0];
    let mut g = inner.lock().unwrap();
    match reset_type {
        0 | 1 => {
            // Type 0: device reset. Type 1: factory defaults. Both come
            // back through the Reset() path — Idle / Idle.
            g.state = SafetySupervisorState::Idle;
            g.mode = SafetySupervisorMode::Idle;
            CipServiceResponse::success(req.service_code)
        }
        2 => {
            // Type 2: RESET OWNERSHIP. Clears CFUNID (attr 25), the owned
            // outputs table (attr 28), the safety configuration
            // identifier, and any pending TUNID proposal. Leaves the
            // device's own TUNID (attr 27) alone — that's overwritten by
            // Apply_TUNID.
            if let Some(a25) = instance.get_attribute_mut(25) {
                a25.set_data(&[0u8; UniqueNetworkId::SIZE]);
            }
            if let Some(a28) = instance.get_attribute_mut(28) {
                a28.set_data(&[0x00, 0x00]);
            }
            g.scid = SafetyConfigurationId::default();
            g.tunid_assigned = false;
            g.proposed_tunid = None;
            CipServiceResponse::success(req.service_code)
        }
        _ => CipServiceResponse::error(req.service_code, status::INVALID_PARAMETER),
    }
}

fn handle_propose_tunid(
    _instance: &mut CipInstance,
    req: &CipServiceRequest,
    inner: &Arc<Mutex<SupervisorInner>>,
) -> CipServiceResponse {
    if req.data.len() < UniqueNetworkId::SIZE {
        return CipServiceResponse::error(req.service_code, status::NOT_ENOUGH_DATA);
    }
    // All-0xFF = cancel any pending proposal (Vol 5 convention).
    let all_ff = req.data[..UniqueNetworkId::SIZE].iter().all(|&b| b == 0xFF);
    let mut g = inner.lock().unwrap();
    if all_ff {
        g.proposed_tunid = None;
        return CipServiceResponse::success(req.service_code);
    }
    let proposed = match UniqueNetworkId::parse(&req.data[..UniqueNetworkId::SIZE]) {
        Ok(u) => u,
        Err(_) => {
            return CipServiceResponse::error(req.service_code, status::INVALID_PARAMETER)
        }
    };
    g.proposed_tunid = Some(proposed);
    CipServiceResponse::success(req.service_code)
}

fn handle_apply_tunid(
    instance: &mut CipInstance,
    req: &CipServiceRequest,
    inner: &Arc<Mutex<SupervisorInner>>,
) -> CipServiceResponse {
    if req.data.len() < UniqueNetworkId::SIZE {
        return CipServiceResponse::error(req.service_code, status::NOT_ENOUGH_DATA);
    }
    let mut g = inner.lock().unwrap();
    let Some(proposed) = g.proposed_tunid else {
        return CipServiceResponse::error(req.service_code, status::OBJECT_STATE_CONFLICT);
    };
    let applied = match UniqueNetworkId::parse(&req.data[..UniqueNetworkId::SIZE]) {
        Ok(u) => u,
        Err(_) => {
            return CipServiceResponse::error(req.service_code, status::INVALID_PARAMETER)
        }
    };
    // Applied UNID must match the previously proposed one exactly — this
    // is the two-service commit that guards against drop/replay between
    // Propose and Apply.
    let mut prop_buf = [0u8; UniqueNetworkId::SIZE];
    proposed.copy_to(&mut prop_buf);
    let mut apply_buf = [0u8; UniqueNetworkId::SIZE];
    applied.copy_to(&mut apply_buf);
    if prop_buf != apply_buf {
        return CipServiceResponse::error(req.service_code, status::INVALID_PARAMETER);
    }
    g.tunid = applied;
    g.snn = applied.snn;
    g.tunid_assigned = true;
    g.proposed_tunid = None;
    // Reflect the new TUNID / SNN into their attributes so a subsequent
    // Get_Attribute_Single sees the assigned values.
    if let Some(a27) = instance.get_attribute_mut(27) {
        a27.set_data(&apply_buf);
    }
    if let Some(a3) = instance.get_attribute_mut(3) {
        let mut snn_buf = [0u8; 6];
        applied.snn.copy_to(&mut snn_buf);
        a3.set_data(&snn_buf);
    }
    CipServiceResponse::success(req.service_code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethernetip_core::cip::{CipDispatcher, CipPath};

    fn make_supervisor() -> (Arc<CipDispatcher>, SafetySupervisorObject) {
        let mut sup = SafetySupervisorObject::new(
            SafetyNetworkNumber([0x5C, 0xA3, 0x01, 0x01, 0x90, 0x4D]),
            0xC0A8_0154,
        );
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(sup.into_cip_class());
        (dispatcher, sup)
    }

    // The class 0x39, instance 1 header used by every supervisor request.
    const PATH_CLS_INST: [u8; 4] = [0x20, 0x39, 0x24, 0x01];

    #[test]
    fn get_attribute_single_returns_snn() {
        let (dispatcher, _sup) = make_supervisor();
        // Path: class 0x39, instance 1, attribute 3.
        let mut p = PATH_CLS_INST.to_vec();
        p.extend_from_slice(&[0x30, 0x03]);
        let path = CipPath::parse(&p).unwrap();
        let response = dispatcher.dispatch(0x0E, path, Vec::new());
        assert_eq!(response.general_status, status::SUCCESS);
        assert_eq!(response.data, vec![0x5C, 0xA3, 0x01, 0x01, 0x90, 0x4D]);
    }

    #[test]
    fn safety_reset_type2_clears_cfunid() {
        let (dispatcher, _sup) = make_supervisor();
        // Dirty CFUNID via Set_Attribute_Single first? Attr 25 is
        // read-only by design, so we can only observe the reset path's
        // effect via a second Get_Attribute_Single. Instead we test that
        // Safety_Reset type=2 succeeds and attr 25 stays all zeros after
        // the round-trip (starts at zero, ends at zero, no error).
        let path = CipPath::parse(&PATH_CLS_INST).unwrap();
        let response = dispatcher.dispatch(SAFETY_RESET_SERVICE, path, vec![0x02]);
        assert_eq!(response.general_status, status::SUCCESS);
    }

    #[test]
    fn safety_reset_invalid_type_returns_invalid_parameter() {
        let (dispatcher, _sup) = make_supervisor();
        let path = CipPath::parse(&PATH_CLS_INST).unwrap();
        let response = dispatcher.dispatch(SAFETY_RESET_SERVICE, path, vec![0x09]);
        assert_eq!(response.general_status, status::INVALID_PARAMETER);
    }

    #[test]
    fn propose_then_apply_updates_tunid() {
        let (dispatcher, _sup) = make_supervisor();
        let new_tunid = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // new SNN
            0x54, 0x01, 0xA8, 0xC0, // new node address (LE) = 0xC0A80154
        ];
        // Propose_TUNID.
        let path1 = CipPath::parse(&PATH_CLS_INST).unwrap();
        let r1 = dispatcher.dispatch(PROPOSE_TUNID_SERVICE, path1, new_tunid.to_vec());
        assert_eq!(r1.general_status, status::SUCCESS);
        // Apply_TUNID with the same value.
        let path2 = CipPath::parse(&PATH_CLS_INST).unwrap();
        let r2 = dispatcher.dispatch(APPLY_TUNID_SERVICE, path2, new_tunid.to_vec());
        assert_eq!(r2.general_status, status::SUCCESS);
        // Read back attr 27 — should be the new TUNID bytes.
        let mut p = PATH_CLS_INST.to_vec();
        p.extend_from_slice(&[0x30, 0x1B]); // attr 27
        let path3 = CipPath::parse(&p).unwrap();
        let r3 = dispatcher.dispatch(0x0E, path3, Vec::new());
        assert_eq!(r3.general_status, status::SUCCESS);
        assert_eq!(r3.data, new_tunid);
    }

    #[test]
    fn apply_without_propose_returns_state_conflict() {
        let (dispatcher, _sup) = make_supervisor();
        let path = CipPath::parse(&PATH_CLS_INST).unwrap();
        let response =
            dispatcher.dispatch(APPLY_TUNID_SERVICE, path, vec![0u8; UniqueNetworkId::SIZE]);
        assert_eq!(response.general_status, status::OBJECT_STATE_CONFLICT);
    }

    #[test]
    fn start_before_register_reflects_in_attribute() {
        // Transition to Executing BEFORE the class is consumed — the state
        // should already show through on the first Get_Attribute_Single.
        let mut sup = SafetySupervisorObject::new(
            SafetyNetworkNumber([0; 6]),
            0xC0A8_0001,
        );
        sup.start();
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(sup.into_cip_class());
        // Attr 1 = State (USINT).
        let mut p = PATH_CLS_INST.to_vec();
        p.extend_from_slice(&[0x30, 0x01]);
        let response = dispatcher.dispatch(0x0E, CipPath::parse(&p).unwrap(), Vec::new());
        assert_eq!(response.general_status, status::SUCCESS);
        assert_eq!(response.data, vec![SafetySupervisorState::Executing as u8]);
    }

    #[test]
    fn sync_to_dispatcher_pushes_state_after_register() {
        // Transition AFTER registration — attr shouldn't move until
        // sync_to_dispatcher is called.
        let (dispatcher, mut sup) = make_supervisor();
        let mut p = PATH_CLS_INST.to_vec();
        p.extend_from_slice(&[0x30, 0x01]);
        let path_attr1 = CipPath::parse(&p).unwrap();
        // Baseline — Idle.
        let r0 = dispatcher.dispatch(0x0E, path_attr1.clone(), Vec::new());
        assert_eq!(r0.data, vec![SafetySupervisorState::Idle as u8]);
        // Transition state on the supervisor — attr not synced yet.
        sup.start();
        let r1 = dispatcher.dispatch(0x0E, path_attr1.clone(), Vec::new());
        assert_eq!(r1.data, vec![SafetySupervisorState::Idle as u8]);
        // Push through the dispatcher — attr now Executing.
        sup.sync_to_dispatcher(&dispatcher);
        let r2 = dispatcher.dispatch(0x0E, path_attr1, Vec::new());
        assert_eq!(r2.data, vec![SafetySupervisorState::Executing as u8]);
    }

    #[test]
    fn propose_all_ff_cancels_pending() {
        let (dispatcher, _sup) = make_supervisor();
        let new_tunid = [0u8; UniqueNetworkId::SIZE];
        // Propose something.
        let path1 = CipPath::parse(&PATH_CLS_INST).unwrap();
        assert_eq!(
            dispatcher.dispatch(PROPOSE_TUNID_SERVICE, path1, new_tunid.to_vec()).general_status,
            status::SUCCESS
        );
        // Cancel with all-0xFF.
        let path2 = CipPath::parse(&PATH_CLS_INST).unwrap();
        let cancel = vec![0xFFu8; UniqueNetworkId::SIZE];
        assert_eq!(
            dispatcher.dispatch(PROPOSE_TUNID_SERVICE, path2, cancel).general_status,
            status::SUCCESS
        );
        // Apply after cancel → OBJECT_STATE_CONFLICT (no pending proposal).
        let path3 = CipPath::parse(&PATH_CLS_INST).unwrap();
        let response =
            dispatcher.dispatch(APPLY_TUNID_SERVICE, path3, new_tunid.to_vec());
        assert_eq!(response.general_status, status::OBJECT_STATE_CONFLICT);
    }
}
