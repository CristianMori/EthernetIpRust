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
//! FO / FC are also registered as *real* CipServiceDefinitions on the
//! class — callers routing MR requests through
//! [`CipDispatcher::dispatch_with_context`] with a
//! [`ForwardOpenContext`] (or [`ForwardCloseContext`]) as the request
//! context get the same behavior the direct `process_*` methods provide.
//! Without a context they return `SERVICE_NOT_SUPPORTED` with a
//! diagnostic — see the class-registration code in
//! [`ConnectionManagerObject::new`] for details.
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

use std::any::Any;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;
use tokio::sync::watch;
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
/// Per-request context handed to [`ConnectionManagerObject::process_forward_open`]
/// and, when routed through the dispatcher, downcast from
/// [`CipServiceRequest::context`]. All fields are owned so the struct is
/// `'static` and can be packed into an `Arc<dyn Any>`.
#[derive(Clone)]
pub struct ForwardOpenContext {
    pub peer_udp: SocketAddr,
    pub assemblies: AssemblyRegistry,
    pub udp: Arc<UdpSocket>,
    pub run_idle: bool,
}

/// Per-request context for the Forward_Close path. Holds the session's
/// currently active T→O connection id — the handler removes exactly that
/// row from the connection table.
#[derive(Clone, Debug)]
pub struct ForwardCloseContext {
    pub active_conn_id: Option<u32>,
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
    producer_spawner: Arc<Mutex<Option<ProducerSpawner>>>,
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
        let connections = Arc::new(Mutex::new(ConnectionTable::default()));
        let next_conn_id = Arc::new(AtomicU32::new(0x8000_0000));
        let producer_spawner = Arc::new(Mutex::new(None::<ProducerSpawner>));

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
        let counters_for_get = counters.clone();
        cls.add_instance_service(CipServiceDefinition::new(
            GET_ATTRIBUTE_SINGLE,
            "Get_Attribute_Single",
            move |instance, req| handle_get_attribute_live(instance, req, &counters_for_get),
        ));

        // Real Forward_Open (0x54) handler — captures shared state and
        // downcasts the request context to a ForwardOpenContext.
        // When present, does the actual FO work through the same code
        // path process_forward_open uses. When absent (dispatched via
        // plain `dispatch` instead of `dispatch_with_context`), returns
        // SERVICE_NOT_SUPPORTED with a diagnostic.
        let connections_for_fo = connections.clone();
        let counters_for_fo = counters.clone();
        let next_id_for_fo = next_conn_id.clone();
        let spawner_for_fo = producer_spawner.clone();
        cls.add_instance_service(CipServiceDefinition::new(
            0x54,
            "Forward_Open",
            move |_inst, req| {
                let Some(ctx) = req.context::<ForwardOpenContext>() else {
                    tracing::warn!(
                        "Forward_Open reached CipDispatcher with no ForwardOpenContext — \
                         caller should use CipDispatcher::dispatch_with_context"
                    );
                    return CipServiceResponse::error(req.service_code, status::SERVICE_NOT_SUPPORTED);
                };
                match do_process_forward_open(
                    &req.data,
                    ctx,
                    &connections_for_fo,
                    &counters_for_fo,
                    &next_id_for_fo,
                    &spawner_for_fo,
                ) {
                    Ok(resp) => CipServiceResponse::success_with(req.service_code, resp.encode()),
                    Err(err) => {
                        tracing::warn!("Forward_Open rejected via dispatcher: {err}");
                        CipServiceResponse::error(req.service_code, status::CONNECTION_FAILURE)
                    }
                }
            },
        ));

        // Real Forward_Close (0x4E) handler — same shape.
        let connections_for_fc = connections.clone();
        let counters_for_fc = counters.clone();
        cls.add_instance_service(CipServiceDefinition::new(
            0x4E,
            "Forward_Close",
            move |_inst, req| {
                let Some(ctx) = req.context::<ForwardCloseContext>() else {
                    tracing::warn!(
                        "Forward_Close reached CipDispatcher with no ForwardCloseContext"
                    );
                    return CipServiceResponse::error(req.service_code, status::SERVICE_NOT_SUPPORTED);
                };
                match do_process_forward_close(
                    &req.data,
                    ctx.active_conn_id,
                    &connections_for_fc,
                    &counters_for_fc,
                ) {
                    Ok(resp) => CipServiceResponse::success_with(req.service_code, resp.encode()),
                    Err(_) => CipServiceResponse::error(req.service_code, status::CONNECTION_FAILURE),
                }
            },
        ));

        Self {
            cip_class: Some(cls),
            connections,
            counters,
            next_conn_id,
            producer_spawner,
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

    /// Live connection count. Sync now — the connection table sits behind
    /// a `std::sync::Mutex`; the lock is held only for short lookups.
    pub fn connection_count(&self) -> usize {
        self.connections.lock().unwrap().rows.len()
    }

    /// Snapshot every live connection.
    pub fn snapshot_connections(&self) -> Vec<ConnectionSummary> {
        self.connections.lock().unwrap().summaries()
    }

    /// Process a Forward_Open request. Parses the body, validates the
    /// assembly path against the registry, allocates a T→O connection id,
    /// spawns the producer task via the registered spawner, and inserts
    /// the resulting row into the connection table. Increments
    /// `counters.open_requests` on success, the appropriate reject counter
    /// on failure.
    pub fn process_forward_open(
        &self,
        body: &[u8],
        ctx: &ForwardOpenContext,
    ) -> Result<ForwardOpenResponse> {
        do_process_forward_open(
            body,
            ctx,
            &self.connections,
            &self.counters,
            &self.next_conn_id,
            &self.producer_spawner,
        )
    }

    /// Process a Forward_Close for the given active connection id. The
    /// producer task shutdown watch is signaled; the row is removed from
    /// the table. The producer task exits on the next tick of its own
    /// accord — we don't await its JoinHandle since this method is now
    /// sync. (Old async version awaited; the difference is invisible to
    /// callers.)
    pub fn process_forward_close(
        &self,
        body: &[u8],
        active_conn_id: Option<u32>,
    ) -> Result<ForwardCloseResponse> {
        do_process_forward_close(body, active_conn_id, &self.connections, &self.counters)
    }
}

impl Default for ConnectionManagerObject {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------- Shared FO/FC implementation --------------------
//
// Kept as free functions so both `ConnectionManagerObject::process_*`
// (which the adapter's inline handler calls) AND the class-registered
// CipServiceHandler closures (which capture Arcs to the same shared
// state and downcast the request context) can drive the same code.

fn do_process_forward_open(
    body: &[u8],
    ctx: &ForwardOpenContext,
    connections: &Arc<Mutex<ConnectionTable>>,
    counters: &Arc<ConnectionManagerCounters>,
    next_conn_id: &Arc<AtomicU32>,
    producer_spawner: &Arc<Mutex<Option<ProducerSpawner>>>,
) -> Result<ForwardOpenResponse> {
    let req = ForwardOpenRequest::decode(body).map_err(|e| {
        counters.record_open_format_reject();
        e
    })?;
    let (input_asm, output_asm) = parse_connection_path(&req.connection_path).map_err(|e| {
        counters.record_open_format_reject();
        e
    })?;

    if ctx.assemblies.snapshot(input_asm).is_none() {
        counters.record_open_other_reject();
        return Err(EipError::Protocol(format!(
            "unknown T->O assembly {}",
            input_asm
        )));
    }
    if ctx.assemblies.snapshot(output_asm).is_none() {
        counters.record_open_other_reject();
        return Err(EipError::Protocol(format!(
            "unknown O->T assembly {}",
            output_asm
        )));
    }
    // Refuse if the originator asked for the same instance in both
    // directions — matches the guard the C++ port added after the
    // duplicate-assembly bug.
    if input_asm == output_asm {
        counters.record_open_other_reject();
        return Err(EipError::Protocol(format!(
            "Forward_Open uses assembly {} in both directions",
            input_asm
        )));
    }

    let assigned_oto_t = next_conn_id.fetch_add(1, Ordering::SeqCst);

    // Shared, mutable peer_udp — the consumer updates it to the actual
    // source of received O→T frames once the scanner starts producing,
    // so the producer sends T→O back to the port the peer is actually
    // listening on (typically ephemeral, not 2222).
    let peer_udp = Arc::new(std::sync::RwLock::new(ctx.peer_udp));

    let spawner = producer_spawner
        .lock()
        .unwrap()
        .as_ref()
        .cloned()
        .ok_or_else(|| {
            counters.record_open_other_reject();
            EipError::Protocol("Connection Manager: no producer spawner registered".into())
        })?;

    let (producer_shutdown_tx, producer_shutdown_rx) = watch::channel(false);
    let producer_task = (spawner)(
        ProducerSpawnArgs {
            connection_id: req.t_to_o_connection_id,
            udp: ctx.udp.clone(),
            peer_udp: peer_udp.clone(),
            rpi_us: req.t_to_o_rpi_us,
            assemblies: ctx.assemblies.clone(),
            input_assembly: input_asm,
            run_idle: ctx.run_idle,
        },
        producer_shutdown_rx,
    );

    {
        let mut table = connections.lock().unwrap();
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

    counters.record_open_success();
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

fn do_process_forward_close(
    body: &[u8],
    active_conn_id: Option<u32>,
    connections: &Arc<Mutex<ConnectionTable>>,
    counters: &Arc<ConnectionManagerCounters>,
) -> Result<ForwardCloseResponse> {
    let req = ForwardCloseRequest::decode(body).map_err(|e| {
        counters.record_close_format();
        e
    })?;
    if let Some(id) = active_conn_id {
        let mut table = connections.lock().unwrap();
        if let Some(row) = table.rows.remove(&id) {
            // Signal the producer to stop. Drop the row's JoinHandle;
            // the task's own tokio::select! will see shutdown_rx and
            // exit its loop.
            let _ = row.producer_shutdown.send(true);
        }
    }
    counters.record_close_success();
    Ok(ForwardCloseResponse {
        connection_serial: req.connection_serial,
        originator_vendor: req.originator_vendor,
        originator_serial: req.originator_serial,
        app_reply: Vec::new(),
    })
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
#[deprecated(
    since = "0.1.0",
    note = "prefer ConnectionManagerObject::new().into_cip_class() — the full CM \
            owns the connection table and FO/FC, and its counters stay live"
)]
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
#[deprecated(
    since = "0.1.0",
    note = "prefer ConnectionManagerObject::new() — the full CM owns the connection \
            table, gives you the same counters via .counters(), and hosts real FO/FC \
            handlers on the class"
)]
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
    fn fo_via_dispatcher_without_context_returns_service_not_supported() {
        // Old sanity check preserved: FORWARD_OPEN routed through
        // plain `dispatch` (no context) hits the "no ForwardOpenContext
        // supplied" diagnostic.
        let mut cm = ConnectionManagerObject::new();
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(cm.into_cip_class());
        let path = CipPath::parse(&[0x20, 0x06, 0x24, 0x01]).unwrap();
        let r = dispatcher.dispatch(0x54, path, Vec::new());
        assert_eq!(r.general_status, status::SERVICE_NOT_SUPPORTED);
    }

    // ---- FO / FC integration tests ----
    //
    // Exercise the real code path end to end: build a CM, register a
    // fake ProducerSpawner that returns a no-op JoinHandle, feed the
    // CM a hand-crafted Forward_Open body, verify a row lands in the
    // connection table + the response is sane + counters bumped.

    fn make_asm_registry() -> AssemblyRegistry {
        let reg = AssemblyRegistry::new();
        reg.insert(crate::Assembly::new(100, crate::AssemblyKind::Input, 8)).unwrap();
        reg.insert(crate::Assembly::new(102, crate::AssemblyKind::Output, 8)).unwrap();
        reg.insert(crate::Assembly::new(105, crate::AssemblyKind::Config, 4)).unwrap();
        reg
    }

    /// Minimal Forward_Open body targeting instances 105 (config), 102
    /// (O→T), 100 (T→O) — matches echo-adapter's assembly layout.
    fn build_test_fo_body() -> Vec<u8> {
        // Format: priority/tick(1), timeout_ticks(1), O→T conn id(4),
        // T→O conn id(4), conn serial(2), orig vendor(2), orig serial(4),
        // conn timeout mult(1), reserved(3), O→T rpi(4), O→T net params(2),
        // T→O rpi(4), T→O net params(2), transport(1), conn path size (words)(1),
        // conn path bytes.
        let mut b = Vec::new();
        b.extend_from_slice(&[0x0A, 0x05]); // priority/tick, timeout_ticks
        b.extend_from_slice(&0u32.to_le_bytes()); // O→T id (target assigns)
        b.extend_from_slice(&0xBEEF_1234u32.to_le_bytes()); // T→O id (originator assigns)
        b.extend_from_slice(&0x1111u16.to_le_bytes()); // conn serial
        b.extend_from_slice(&0x0001u16.to_le_bytes()); // orig vendor
        b.extend_from_slice(&0xC0FFEE01u32.to_le_bytes()); // orig serial
        b.push(1); // conn timeout mult
        b.extend_from_slice(&[0, 0, 0]); // reserved
        b.extend_from_slice(&10_000u32.to_le_bytes()); // O→T rpi
        b.extend_from_slice(&0x4400u16.to_le_bytes()); // O→T params
        b.extend_from_slice(&10_000u32.to_le_bytes()); // T→O rpi
        b.extend_from_slice(&0x4400u16.to_le_bytes()); // T→O params
        b.push(0xA0); // transport
        // Connection path: Class 0x04 (Assembly), Instance 105 (config),
        //                  Connection 102 (O→T), Connection 100 (T→O).
        let conn_path = [0x20, 0x04, 0x24, 0x69, 0x2C, 0x66, 0x2C, 0x64];
        b.push((conn_path.len() / 2) as u8); // path size in words
        b.extend_from_slice(&conn_path);
        b
    }

    fn install_noop_spawner(cm: &ConnectionManagerObject) {
        cm.set_producer_spawner(|_args, _shutdown_rx| {
            // Return a task that immediately exits.
            tokio::spawn(async {})
        });
    }

    #[tokio::test]
    async fn process_forward_open_inserts_row_and_bumps_counter() {
        let cm = ConnectionManagerObject::new();
        install_noop_spawner(&cm);

        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ctx = ForwardOpenContext {
            peer_udp: "127.0.0.1:44818".parse().unwrap(),
            assemblies: make_asm_registry(),
            udp,
            run_idle: true,
        };
        let body = build_test_fo_body();
        let resp = cm.process_forward_open(&body, &ctx).unwrap();

        assert_eq!(resp.t_to_o_connection_id, 0xBEEF_1234);
        assert!(resp.o_to_t_connection_id >= 0x8000_0000);
        assert_eq!(cm.connection_count(), 1);
        assert_eq!(cm.counters().open_requests.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn process_forward_close_removes_row_and_bumps_counter() {
        let cm = ConnectionManagerObject::new();
        install_noop_spawner(&cm);
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ctx = ForwardOpenContext {
            peer_udp: "127.0.0.1:44818".parse().unwrap(),
            assemblies: make_asm_registry(),
            udp,
            run_idle: true,
        };
        let resp = cm.process_forward_open(&build_test_fo_body(), &ctx).unwrap();
        assert_eq!(cm.connection_count(), 1);

        // FC body: conn_serial(2) + orig vendor(2) + orig serial(4) +
        // conn timeout mult(1) + reserved(1) + conn path words(1) + reserved(1)
        // + conn path.
        let mut fc = Vec::new();
        fc.extend_from_slice(&[0x0A, 0x05]); // priority/tick, timeout_ticks
        fc.extend_from_slice(&0x1111u16.to_le_bytes()); // conn serial
        fc.extend_from_slice(&0x0001u16.to_le_bytes()); // orig vendor
        fc.extend_from_slice(&0xC0FFEE01u32.to_le_bytes()); // orig serial
        fc.push(2); // path words
        fc.push(0); // reserved
        fc.extend_from_slice(&[0x20, 0x06, 0x24, 0x01]);

        cm.process_forward_close(&fc, Some(resp.o_to_t_connection_id)).unwrap();
        assert_eq!(cm.connection_count(), 0);
        assert_eq!(cm.counters().close_requests.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn fo_via_dispatcher_with_context_works() {
        // Real end-to-end: FO routed through CipDispatcher with a
        // ForwardOpenContext lands in the table just like the direct
        // process_forward_open call.
        let mut cm = ConnectionManagerObject::new();
        install_noop_spawner(&cm);
        let counters_handle = cm.counters();
        let connections_handle = cm.connections();
        let dispatcher = Arc::new(CipDispatcher::new());
        dispatcher.register_class(cm.into_cip_class());

        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ctx: Arc<dyn Any + Send + Sync> = Arc::new(ForwardOpenContext {
            peer_udp: "127.0.0.1:44818".parse().unwrap(),
            assemblies: make_asm_registry(),
            udp,
            run_idle: true,
        });

        let path = CipPath::parse(&[0x20, 0x06, 0x24, 0x01]).unwrap();
        let r = dispatcher.dispatch_with_context(0x54, path, build_test_fo_body(), Some(ctx));
        assert_eq!(r.general_status, status::SUCCESS);
        assert_eq!(connections_handle.lock().unwrap().rows.len(), 1);
        assert_eq!(counters_handle.open_requests.load(Ordering::Relaxed), 1);
    }
}
