//! CIP Connection Manager Object (class 0x06).
//!
//! Owns the Class 1 connection table AND the Forward_Open / Forward_Close
//! processing — mirrors C# `ConnectionManagerObject`'s
//! `ConcurrentDictionary<uint, IoConnection>` + `HandleForwardOpen` /
//! `HandleForwardClose` pattern. The adapter's session handler delegates
//! the actual work here via [`ConnectionManagerObject::process_forward_open`]
//! and [`process_forward_close`], passing the per-request context
//! (peer UDP, assembly registry, UDP socket, run/idle mode) in a
//! [`ForwardOpenContext`].
//!
//! FO / FC are also registered as CipServiceDefinitions on the class so a
//! commissioning browser walking Class 0x06 sees the services declared,
//! but their CipServiceHandler bodies return SERVICE_NOT_SUPPORTED — the
//! sync (`CipInstance`, `CipServiceRequest`) signature can't carry the
//! per-session context these operations need. The adapter always calls the
//! `process_*` methods directly.
//!
//! Instance 1 attribute layout (Vol 1 §3-4.1):
//!
//!  * 1 Open Requests       — live from ConnectionManagerCounters
//!  * 2 Open Format Rejects
//!  * 3 Open Resource Rejects
//!  * 4 Open Other Rejects
//!  * 5 Close Requests
//!  * 6 Close Format Requests
//!  * 7 Close Other Requests
//!  * 8 Connection Timeouts

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;

use ethernetip_core::cip::{
    class_codes, standard_services::GET_ATTRIBUTE_SINGLE, status, AttributeAccess,
    CipAttribute, CipClass, CipDataType, CipInstance, CipServiceDefinition,
    CipServiceRequest, CipServiceResponse,
};
use ethernetip_core::error::{EipError, Result};

use crate::assembly::AssemblyRegistry;
use crate::forward_open::{
    ForwardCloseRequest, ForwardCloseResponse, ForwardOpenRequest, ForwardOpenResponse,
};

// -------------------- counters --------------------

/// Live counter block backing the Connection Manager's instance-1 attrs.
/// Every field is an atomic — the adapter's async task increments them
/// without any additional locking. Kept as a separate Arc so an app that
/// wants to feed counters from somewhere other than the Rust adapter (a
/// custom transport, tests) can bump them independently.
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

// -------------------- connection table --------------------

/// Publicly-visible summary of one live connection.
#[derive(Debug, Clone)]
pub struct ConnectionSummary {
    pub o_to_t_conn_id: u32,
    pub t_to_o_conn_id: u32,
    pub o_to_t_rpi_us: u32,
    pub t_to_o_rpi_us: u32,
    pub input_assembly: u16,
    pub output_assembly: u16,
    pub peer_udp: SocketAddr,
}

/// Metadata + runtime handles for one live Class 1 connection. Held inside
/// the CM's `ConnectionTable`. The `peer_udp` field is an
/// `Arc<RwLock<SocketAddr>>` so the UDP consumer task can update it to
/// wherever the scanner actually sends O→T from (usually an ephemeral
/// port, not the well-known 2222).
#[derive(Debug)]
pub struct ConnectionRow {
    pub o_to_t_conn_id: u32,
    pub t_to_o_conn_id: u32,
    pub input_assembly: u16,
    pub output_assembly: u16,
    pub peer_udp: Arc<std::sync::RwLock<SocketAddr>>,
    pub o_to_t_rpi_us: u32,
    pub t_to_o_rpi_us: u32,
    pub producer_shutdown: watch::Sender<bool>,
    pub producer_task: JoinHandle<()>,
}

/// Shared connection registry.
#[derive(Debug, Default)]
pub struct ConnectionTable {
    pub rows: HashMap<u32, ConnectionRow>,
}

impl ConnectionTable {
    pub fn summaries(&self) -> Vec<ConnectionSummary> {
        self.rows
            .values()
            .map(|r| ConnectionSummary {
                o_to_t_conn_id: r.o_to_t_conn_id,
                t_to_o_conn_id: r.t_to_o_conn_id,
                o_to_t_rpi_us: r.o_to_t_rpi_us,
                t_to_o_rpi_us: r.t_to_o_rpi_us,
                input_assembly: r.input_assembly,
                output_assembly: r.output_assembly,
                peer_udp: *r.peer_udp.read().unwrap(),
            })
            .collect()
    }
}

// -------------------- Forward_Open context + spawner --------------------

/// Per-request context the adapter passes to [`ConnectionManagerObject::process_forward_open`].
/// Bundles the runtime handles the FO logic needs but the class doesn't
/// want to own permanently (UDP socket, assembly registry snapshot).
///
/// `spawn_producer` is the tokio-task factory the CM invokes when a new
/// connection is accepted. The adapter provides it because the producer
/// loop's implementation is transport-specific — the CM stays
/// transport-agnostic and just calls the closure with `(row_metadata,
/// shutdown_rx)`, receives back the `JoinHandle`, and stores it on the
/// row.
pub struct ForwardOpenContext<'a> {
    pub peer_udp: SocketAddr,
    pub assemblies: &'a AssemblyRegistry,
    pub udp: Arc<UdpSocket>,
    pub run_idle: bool,
}

/// Signature for the adapter-supplied producer task spawner. Called once
/// per accepted Forward_Open with the freshly-allocated connection metadata
/// and a shutdown watch receiver; returns the JoinHandle so
/// process_forward_open can pack it into the ConnectionRow.
pub type ProducerSpawner = Arc<
    dyn Fn(ProducerSpawnArgs, watch::Receiver<bool>) -> JoinHandle<()> + Send + Sync,
>;

/// Arguments passed to the producer-spawner callback: everything the T→O
/// task needs to start streaming this connection's data at the negotiated
/// RPI.
pub struct ProducerSpawnArgs {
    pub connection_id: u32,
    pub udp: Arc<UdpSocket>,
    pub peer_udp: Arc<std::sync::RwLock<SocketAddr>>,
    pub rpi_us: u32,
    pub assemblies: AssemblyRegistry,
    pub input_assembly: u16,
    pub run_idle: bool,
}

// -------------------- Connection Manager object --------------------

/// CIP Connection Manager Object (class 0x06). Construct once at adapter
/// startup, hand its class to the dispatcher via
/// [`ConnectionManagerObject::into_cip_class`], and install its
/// [`ProducerSpawner`] with [`set_producer_spawner`]. From then on the
/// adapter delegates all FO / FC handling to [`process_forward_open`] and
/// [`process_forward_close`].
pub struct ConnectionManagerObject {
    cip_class: Option<CipClass>,
    connections: Arc<Mutex<ConnectionTable>>,
    counters: Arc<ConnectionManagerCounters>,
    next_conn_id: Arc<AtomicU32>,
    producer_spawner: std::sync::Mutex<Option<ProducerSpawner>>,
}

impl std::fmt::Debug for ConnectionManagerObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionManagerObject")
            .field("cip_class", &self.cip_class.as_ref().map(|_| "..."))
            .field("counters", &self.counters)
            .field("next_conn_id", &self.next_conn_id)
            .field(
                "producer_spawner",
                &self.producer_spawner.lock().unwrap().as_ref().map(|_| "..."),
            )
            .finish()
    }
}

impl ConnectionManagerObject {
    /// Build a fresh CM. Counters start at zero; the connection table
    /// starts empty; the producer spawner starts unset. Callers must
    /// register a spawner via [`set_producer_spawner`] before a
    /// Forward_Open lands, otherwise `process_forward_open` returns
    /// `Protocol("no producer spawner registered")`.
    pub fn new() -> Self {
        let counters = Arc::new(ConnectionManagerCounters::default());
        let mut cls = CipClass::new(class_codes::CONNECTION_MANAGER, "Connection Manager", 1);
        cls.add_standard_instance_services();

        // Placeholder attribute bytes — the custom Get_Attribute_Single
        // handler below reads live values from the counters, but attrs
        // 1..=8 still need to exist so Get_Attributes_All finds them.
        let inst = cls.create_instance(1);
        for id in 1u16..=8 {
            inst.add_attribute(CipAttribute::from_u16(
                id,
                CipDataType::Uint,
                AttributeAccess::READ,
                0,
            ));
        }

        // Live-counter Get_Attribute_Single override.
        let counters_for_handler = counters.clone();
        cls.add_instance_service(CipServiceDefinition::new(
            GET_ATTRIBUTE_SINGLE,
            "Get_Attribute_Single",
            move |instance, req| handle_get_attribute_live(instance, req, &counters_for_handler),
        ));

        // Forward_Open (0x54) / Forward_Close (0x4E) service definitions
        // exist on the class so a browser sees them declared. Their bodies
        // return SERVICE_NOT_SUPPORTED — the sync CipServiceHandler
        // signature can't carry the per-session context these need. The
        // adapter always calls process_forward_open / process_forward_close
        // directly.
        cls.add_instance_service(CipServiceDefinition::new(
            0x54,
            "Forward_Open",
            handle_forward_open_dispatch_stub,
        ));
        cls.add_instance_service(CipServiceDefinition::new(
            0x4E,
            "Forward_Close",
            handle_forward_close_dispatch_stub,
        ));

        Self {
            cip_class: Some(cls),
            connections: Arc::new(Mutex::new(ConnectionTable::default())),
            counters,
            // Adapters allocate T→O ids in the upper half of u32 space to
            // avoid colliding with the O→T ids scanners assign — matches
            // the pattern the safety adapter uses.
            next_conn_id: Arc::new(AtomicU32::new(0x8000_0000)),
            producer_spawner: std::sync::Mutex::new(None),
        }
    }

    /// Take the built CipClass so it can be registered on a dispatcher.
    /// Panics if called twice.
    pub fn into_cip_class(&mut self) -> CipClass {
        self.cip_class
            .take()
            .expect("ConnectionManagerObject::into_cip_class called twice")
    }

    /// Shared handle on the live counter block.
    pub fn counters(&self) -> Arc<ConnectionManagerCounters> {
        self.counters.clone()
    }

    /// Shared handle on the connection table — used by the adapter's UDP
    /// consumer task to look up rows by o_to_t_id when frames arrive.
    pub fn connections(&self) -> Arc<Mutex<ConnectionTable>> {
        self.connections.clone()
    }

    /// Shared next-connection-id counter. The adapter and CM share this
    /// so any code path that needs to allocate a T→O connection id sees
    /// the same monotonic sequence.
    pub fn next_conn_id(&self) -> Arc<AtomicU32> {
        self.next_conn_id.clone()
    }

    /// Install the producer-task factory. Must be called before
    /// [`process_forward_open`] runs; the adapter does this during
    /// `start()`.
    pub fn set_producer_spawner<F>(&self, spawner: F)
    where
        F: Fn(ProducerSpawnArgs, watch::Receiver<bool>) -> JoinHandle<()>
            + Send
            + Sync
            + 'static,
    {
        *self.producer_spawner.lock().unwrap() = Some(Arc::new(spawner));
    }

    /// Live connection count.
    pub async fn connection_count(&self) -> usize {
        self.connections.lock().await.rows.len()
    }

    /// Snapshot of every live connection.
    pub async fn snapshot_connections(&self) -> Vec<ConnectionSummary> {
        self.connections.lock().await.summaries()
    }

    /// Process a Forward_Open request. Parses the body, validates the
    /// assembly path against the registry, allocates a T→O connection id,
    /// spawns the producer task via the registered spawner, and inserts
    /// the resulting row into the connection table. Increments
    /// `counters.open_requests` on success, `counters.open_other_rejects`
    /// on any failure. Returns the response the adapter should encode
    /// into its FO reply.
    pub async fn process_forward_open<'a>(
        &self,
        body: &[u8],
        ctx: ForwardOpenContext<'a>,
    ) -> Result<ForwardOpenResponse> {
        let req = ForwardOpenRequest::decode(body).map_err(|e| {
            self.counters.record_open_format_reject();
            e
        })?;
        let (input_asm, output_asm) = parse_connection_path(&req.connection_path)
            .map_err(|e| {
                self.counters.record_open_format_reject();
                e
            })?;

        if ctx.assemblies.snapshot(input_asm).is_none() {
            self.counters.record_open_other_reject();
            return Err(EipError::Protocol(format!(
                "unknown T->O assembly {}",
                input_asm
            )));
        }
        if ctx.assemblies.snapshot(output_asm).is_none() {
            self.counters.record_open_other_reject();
            return Err(EipError::Protocol(format!(
                "unknown O->T assembly {}",
                output_asm
            )));
        }
        // Refuse if the originator asked for the same instance in both
        // directions — matches the guard the C++ port added after the
        // duplicate-assembly bug.
        if input_asm == output_asm {
            self.counters.record_open_other_reject();
            return Err(EipError::Protocol(format!(
                "Forward_Open uses assembly {} in both directions",
                input_asm
            )));
        }

        let assigned_oto_t = self.next_conn_id.fetch_add(1, Ordering::SeqCst);

        // Shared, mutable peer_udp — the consumer will update it to the
        // actual source of received O→T frames once the scanner starts
        // producing, so the producer sends T→O back to the port the peer
        // is actually listening on (typically ephemeral, not 2222).
        let peer_udp = Arc::new(std::sync::RwLock::new(ctx.peer_udp));

        let spawner = self
            .producer_spawner
            .lock()
            .unwrap()
            .as_ref()
            .cloned()
            .ok_or_else(|| {
                self.counters.record_open_other_reject();
                EipError::Protocol("Connection Manager: no producer spawner registered".into())
            })?;

        let (producer_shutdown_tx, producer_shutdown_rx) = watch::channel(false);
        let producer_task = (spawner)(
            ProducerSpawnArgs {
                connection_id: req.t_to_o_connection_id,
                udp: ctx.udp,
                peer_udp: peer_udp.clone(),
                rpi_us: req.t_to_o_rpi_us,
                assemblies: ctx.assemblies.clone(),
                input_assembly: input_asm,
                run_idle: ctx.run_idle,
            },
            producer_shutdown_rx,
        );

        {
            let mut table = self.connections.lock().await;
            table.rows.insert(
                assigned_oto_t,
                ConnectionRow {
                    o_to_t_conn_id: assigned_oto_t,
                    t_to_o_conn_id: req.t_to_o_connection_id,
                    input_assembly: input_asm,
                    output_assembly: output_asm,
                    peer_udp,
                    o_to_t_rpi_us: req.o_to_t_rpi_us,
                    t_to_o_rpi_us: req.t_to_o_rpi_us,
                    producer_shutdown: producer_shutdown_tx,
                    producer_task,
                },
            );
        }

        self.counters.record_open_success();
        Ok(ForwardOpenResponse {
            o_to_t_connection_id: assigned_oto_t,
            t_to_o_connection_id: req.t_to_o_connection_id,
            connection_serial: req.connection_serial,
            originator_vendor: req.originator_vendor,
            originator_serial: req.originator_serial,
            o_to_t_actual_rpi_us: req.o_to_t_rpi_us,
            t_to_o_actual_rpi_us: req.t_to_o_rpi_us,
            app_reply: Vec::new(),
        })
    }

    /// Process a Forward_Close for the given active connection id. If the
    /// connection exists, its producer task is shut down and joined; the
    /// row is removed from the table. Increments `counters.close_requests`
    /// on success, `counters.close_other_requests` on failure (bad body).
    pub async fn process_forward_close(
        &self,
        body: &[u8],
        active_conn_id: Option<u32>,
    ) -> Result<ForwardCloseResponse> {
        let req = ForwardCloseRequest::decode(body).map_err(|e| {
            self.counters.record_close_format();
            e
        })?;
        if let Some(id) = active_conn_id {
            let mut table = self.connections.lock().await;
            if let Some(row) = table.rows.remove(&id) {
                let _ = row.producer_shutdown.send(true);
                drop(table);
                let _ = row.producer_task.await;
            }
        }
        self.counters.record_close_success();
        Ok(ForwardCloseResponse {
            connection_serial: req.connection_serial,
            originator_vendor: req.originator_vendor,
            originator_serial: req.originator_serial,
            app_reply: Vec::new(),
        })
    }
}

impl Default for ConnectionManagerObject {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------- CipServiceHandler implementations --------------------

fn handle_get_attribute_live(
    instance: &mut CipInstance,
    req: &CipServiceRequest,
    counters: &Arc<ConnectionManagerCounters>,
) -> CipServiceResponse {
    let Some(attr_id) = req.path.attribute_id else {
        return CipServiceResponse::error(req.service_code, status::PATH_SEGMENT_ERROR);
    };
    let attr_id16 = attr_id as u16;
    if let Some(v) = counters.read(attr_id16) {
        return CipServiceResponse::success_with(req.service_code, v.to_le_bytes().to_vec());
    }
    let Some(attr) = instance.get_attribute(attr_id16) else {
        return CipServiceResponse::error(req.service_code, status::ATTRIBUTE_NOT_SUPPORTED);
    };
    if !attr.access.contains(AttributeAccess::GET_SINGLE) {
        return CipServiceResponse::error(req.service_code, status::ATTRIBUTE_NOT_SUPPORTED);
    }
    CipServiceResponse::success_with(req.service_code, attr.data().into_owned())
}

fn handle_forward_open_dispatch_stub(
    _inst: &mut CipInstance,
    req: &CipServiceRequest,
) -> CipServiceResponse {
    tracing::warn!(
        "Forward_Open (0x54) reached CipDispatcher on Connection Manager (0x06) — \
         adapters must call ConnectionManagerObject::process_forward_open directly, \
         since the sync CipServiceHandler signature can't carry the per-session \
         context (peer_udp, udp socket, assembly registry) FO needs"
    );
    CipServiceResponse::error(req.service_code, status::SERVICE_NOT_SUPPORTED)
}

fn handle_forward_close_dispatch_stub(
    _inst: &mut CipInstance,
    req: &CipServiceRequest,
) -> CipServiceResponse {
    tracing::warn!(
        "Forward_Close (0x4E) reached CipDispatcher on Connection Manager (0x06) — \
         adapters call ConnectionManagerObject::process_forward_close directly"
    );
    CipServiceResponse::error(req.service_code, status::SERVICE_NOT_SUPPORTED)
}

// -------------------- shared helpers used by the FO handler --------------------

/// Extract the O→T and T→O assembly instances from a Forward_Open
/// connection path. The Logix / Generic Ethernet Module convention is
/// `[route*] Class(4) Instance(config) Connection(consumed) Connection(produced)`,
/// with the class-and-instance segments identifying the config assembly and
/// two more logical-connection-point segments (0x2C) naming the O→T and T→O
/// assemblies.
pub(crate) fn parse_connection_path(path: &[u8]) -> Result<(u16, u16)> {
    let mut i = 0;
    let mut assemblies = Vec::new();
    while i < path.len() {
        let seg = path[i];
        match seg {
            // Port segment (route bytes) — skip.
            0x00..=0x0F => {
                if i + 1 >= path.len() {
                    break;
                }
                i += 2;
            }
            // Logical class segment (8-bit).
            0x20 => i += 2,
            0x21 => i += 4,
            // Logical instance segment (8-bit / 16-bit).
            0x24 => i += 2,
            0x25 => i += 4,
            // Logical connection point (assembly instance) — this is what we want.
            0x2C => {
                if i + 1 >= path.len() {
                    return Err(EipError::Short {
                        expected: i + 2,
                        actual: path.len(),
                    });
                }
                assemblies.push(path[i + 1] as u16);
                i += 2;
            }
            0x2D => {
                if i + 3 >= path.len() {
                    return Err(EipError::Short {
                        expected: i + 4,
                        actual: path.len(),
                    });
                }
                assemblies.push(u16::from_le_bytes([path[i + 2], path[i + 3]]));
                i += 4;
            }
            // Data segments — skip inline config bytes.
            0x80 => {
                if i + 1 >= path.len() {
                    break;
                }
                let word_size = path[i + 1] as usize;
                i += 2 + word_size * 2;
            }
            _ => {
                // Unknown segment — bail out with what we've got.
                break;
            }
        }
    }
    if assemblies.len() < 2 {
        return Err(EipError::Protocol(format!(
            "Forward_Open connection path did not yield 2 assembly instances (got {})",
            assemblies.len()
        )));
    }
    // Convention: first connection-point segment = O→T (consumed by adapter),
    // second = T→O (produced by adapter). This matches the Logix generic
    // Ethernet module Forward_Open path we've matched against the C#,
    // C++, and Python ports.
    Ok((assemblies[1], assemblies[0]))
}

// -------------------- backward-compat helpers --------------------

/// Legacy attribute-only builder — returns just the class with placeholder
/// zero-counter attrs. Kept so callers that don't want the full CM
/// (adapters that don't need FO/FC delegation) can register class 0x06
/// with browse-visible attrs and nothing else.
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

/// Legacy counters-only builder. Prefer [`ConnectionManagerObject::new`]
/// for new code — it wires the counters up alongside the connection
/// table and FO/FC dispatch.
pub fn build_with_counters() -> (CipClass, Arc<ConnectionManagerCounters>) {
    let mut cm = ConnectionManagerObject::new();
    let counters = cm.counters();
    let cls = cm.into_cip_class();
    (cls, counters)
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

    #[test]
    fn fo_service_via_dispatcher_returns_service_not_supported() {
        // Confirm the stub: FORWARD_OPEN routed through the dispatcher
        // gets rejected with SERVICE_NOT_SUPPORTED. Adapters must call
        // process_forward_open directly.
        let (cls, _counters) = build_with_counters();
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(cls);
        let path = CipPath::parse(&[0x20, 0x06, 0x24, 0x01]).unwrap();
        let r = dispatcher.dispatch(0x54, path, Vec::new());
        assert_eq!(r.general_status, status::SERVICE_NOT_SUPPORTED);
    }
}
