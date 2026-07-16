//! CIP Connection Manager Object (class 0x06).
//!
//! Class 0x06 owns the eight standard UINT counter attributes on instance 1
//! plus a custom Get_Attribute_Single handler that reads live values from
//! a shared [`ConnectionManagerCounters`]. The adapter calls the record_*
//! methods on that struct whenever it accepts / rejects a Forward_Open or
//! Forward_Close, so a client's `Get_Attribute_Single(0x06/1/N)` returns
//! the actual number of connection events instead of always zero.
//!
//! Forward_Open / Large_Forward_Open / Forward_Close / Unconnected_Send are
//! still handled inline by the safety-adapter and echo-adapter — the C#
//! sibling routes them through the class and owns an IoConnection runtime
//! we don't have on the Rust side. This intermediate design gives clients
//! visibility into connection-lifecycle statistics without that refactor.
//!
//! Instance 1 attribute layout (Vol 1 §3-4.1):
//!
//!  * 1 Open Requests       — successful Forward_Open count
//!  * 2 Open Format Rejects — refused for malformed request
//!  * 3 Open Resource Rejects
//!  * 4 Open Other Rejects
//!  * 5 Close Requests
//!  * 6 Close Format Requests
//!  * 7 Close Other Requests
//!  * 8 Connection Timeouts

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use ethernetip_core::cip::{
    class_codes, standard_services::GET_ATTRIBUTE_SINGLE, status, AttributeAccess,
    CipAttribute, CipClass, CipDataType, CipInstance, CipServiceDefinition,
    CipServiceRequest, CipServiceResponse,
};

/// Live counter block backing the Connection Manager's instance-1 attrs.
/// Every field is an atomic — the adapter's async task increments them
/// without any additional locking.
#[derive(Debug, Default)]
pub struct ConnectionManagerCounters {
    pub open_requests: AtomicU16,
    pub open_format_rejects: AtomicU16,
    pub open_resource_rejects: AtomicU16,
    pub open_other_rejects: AtomicU16,
    pub close_requests: AtomicU16,
    pub close_format_requests: AtomicU16,
    pub close_other_requests: AtomicU16,
    pub connection_timeouts: AtomicU16,
}

impl ConnectionManagerCounters {
    pub fn record_open_success(&self) {
        self.open_requests.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_open_format_reject(&self) {
        self.open_format_rejects.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_open_resource_reject(&self) {
        self.open_resource_rejects.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_open_other_reject(&self) {
        self.open_other_rejects.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_close_success(&self) {
        self.close_requests.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_close_format(&self) {
        self.close_format_requests.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_close_other(&self) {
        self.close_other_requests.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_connection_timeout(&self) {
        self.connection_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    fn read(&self, attr_id: u16) -> Option<u16> {
        let atomic = match attr_id {
            1 => &self.open_requests,
            2 => &self.open_format_rejects,
            3 => &self.open_resource_rejects,
            4 => &self.open_other_rejects,
            5 => &self.close_requests,
            6 => &self.close_format_requests,
            7 => &self.close_other_requests,
            8 => &self.connection_timeouts,
            _ => return None,
        };
        Some(atomic.load(Ordering::Relaxed))
    }
}

/// Build a Connection Manager class with zeroed placeholder counter attrs
/// and no live tracking — reads always return zero. Handy for a device
/// whose adapter doesn't want to plumb an [`Arc<ConnectionManagerCounters>`]
/// through its FO/FC handlers.
pub fn build() -> CipClass {
    let mut cls = CipClass::new(class_codes::CONNECTION_MANAGER, "Connection Manager", 1);
    cls.add_standard_instance_services();
    let inst = cls.create_instance(1);
    for id in 1u16..=8 {
        inst.add_attribute(CipAttribute::from_u16(
            id,
            CipDataType::Uint,
            AttributeAccess::READ,
            0,
        ));
    }
    cls
}

/// Build a Connection Manager class with a shared live-counter block. The
/// class registers a custom `Get_Attribute_Single` handler that reads
/// from the counters instead of the static attribute bytes, so callers
/// see whatever the adapter has recorded via the `record_*` methods.
///
/// Set_Attribute_Single and Get_Attributes_All fall through to the
/// standard handlers, which read the zero placeholder bytes; a
/// commissioning tool that walks Get_Attributes_All against class 0x06
/// won't see the live values (Vol 1 doesn't say counter attributes have
/// to be in Get_Attributes_All anyway). Point queries via
/// Get_Attribute_Single return live counts.
pub fn build_with_counters() -> (CipClass, Arc<ConnectionManagerCounters>) {
    let counters = Arc::new(ConnectionManagerCounters::default());
    let mut cls = build();
    let counters_for_handler = counters.clone();
    cls.add_instance_service(CipServiceDefinition::new(
        GET_ATTRIBUTE_SINGLE,
        "Get_Attribute_Single",
        move |instance, req| handle_get_attribute_live(instance, req, &counters_for_handler),
    ));
    (cls, counters)
}

fn handle_get_attribute_live(
    instance: &mut CipInstance,
    req: &CipServiceRequest,
    counters: &Arc<ConnectionManagerCounters>,
) -> CipServiceResponse {
    let Some(attr_id) = req.path.attribute_id else {
        return CipServiceResponse::error(req.service_code, status::PATH_SEGMENT_ERROR);
    };
    let attr_id16 = attr_id as u16;
    // Attrs 1-8: live counters.
    if let Some(v) = counters.read(attr_id16) {
        return CipServiceResponse::success_with(req.service_code, v.to_le_bytes().to_vec());
    }
    // Anything else: fall through to the plain attribute lookup so future
    // vendor-specific attrs still work through the same handler.
    let Some(attr) = instance.get_attribute(attr_id16) else {
        return CipServiceResponse::error(req.service_code, status::ATTRIBUTE_NOT_SUPPORTED);
    };
    if !attr.access.contains(AttributeAccess::GET_SINGLE) {
        return CipServiceResponse::error(req.service_code, status::ATTRIBUTE_NOT_SUPPORTED);
    }
    CipServiceResponse::success_with(req.service_code, attr.data().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethernetip_core::cip::{CipDispatcher, CipPath};
    use std::sync::Arc;

    #[test]
    fn open_requests_attribute_reads_zero_when_no_counters() {
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(build());
        // Get_Attribute_Single(class 0x06, instance 1, attr 1).
        let path = CipPath::parse(&[0x20, 0x06, 0x24, 0x01, 0x30, 0x01]).unwrap();
        let r = dispatcher.dispatch(0x0E, path, Vec::new());
        assert_eq!(r.general_status, status::SUCCESS);
        assert_eq!(r.data, 0u16.to_le_bytes().to_vec());
    }

    #[test]
    fn all_eight_counters_present() {
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(build());
        for attr_id in 1u8..=8 {
            let path = CipPath::parse(&[0x20, 0x06, 0x24, 0x01, 0x30, attr_id]).unwrap();
            let r = dispatcher.dispatch(0x0E, path, Vec::new());
            assert_eq!(r.general_status, status::SUCCESS, "attr {attr_id} missing");
        }
    }

    #[test]
    fn record_open_success_reflects_via_get_attribute_single() {
        let (cls, counters) = build_with_counters();
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(cls);
        counters.record_open_success();
        counters.record_open_success();
        counters.record_open_success();
        let path = CipPath::parse(&[0x20, 0x06, 0x24, 0x01, 0x30, 0x01]).unwrap();
        let r = dispatcher.dispatch(0x0E, path, Vec::new());
        assert_eq!(r.data, 3u16.to_le_bytes().to_vec());
    }

    #[test]
    fn every_recorder_reaches_its_attribute() {
        let (cls, counters) = build_with_counters();
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(cls);
        counters.record_open_success();
        counters.record_open_format_reject();
        counters.record_open_resource_reject();
        counters.record_open_other_reject();
        counters.record_close_success();
        counters.record_close_format();
        counters.record_close_other();
        counters.record_connection_timeout();
        for attr_id in 1u8..=8 {
            let path = CipPath::parse(&[0x20, 0x06, 0x24, 0x01, 0x30, attr_id]).unwrap();
            let r = dispatcher.dispatch(0x0E, path, Vec::new());
            assert_eq!(r.data, 1u16.to_le_bytes().to_vec(), "attr {attr_id}");
        }
    }
}
