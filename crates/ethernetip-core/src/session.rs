//! Asynchronous EtherNet/IP session over a single TCP connection.
//!
//! [`EipSession`] owns the socket, the registered session handle, and a
//! monotonic sender-context counter. It exposes high-level helpers for the
//! two request/response commands the rest of the library needs
//! (`SendRRData` and `SendUnitData`) plus register/unregister.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::ToSocketAddrs;

use crate::cpf::{self, Envelope, Item};
use crate::encap::{self, Command, Header, HEADER_LEN};
use crate::error::{EipError, Result};

/// Default request timeout used by [`EipSession::connect`].
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Owning wrapper around a registered EIP session.
pub struct EipSession {
    stream: TcpStream,
    session_handle: u32,
    peer: SocketAddr,
    ctx_counter: u64,
    registered: bool,
}

impl EipSession {
    /// Open a TCP connection to the peer without registering yet.
    ///
    /// Use [`Self::connect_and_register`] for the common case.
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        let peer = stream.peer_addr()?;
        Ok(Self {
            stream,
            session_handle: 0,
            peer,
            ctx_counter: 0,
            registered: false,
        })
    }

    /// Connect and register in one call.
    pub async fn connect_and_register<A: ToSocketAddrs>(addr: A) -> Result<Self> {
        let mut s = Self::connect(addr).await?;
        s.register().await?;
        Ok(s)
    }

    /// Peer socket address of the underlying TCP connection.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Handle assigned by the target during `RegisterSession` (0 before register).
    pub fn session_handle(&self) -> u32 {
        self.session_handle
    }

    /// Whether `RegisterSession` has completed successfully.
    pub fn is_registered(&self) -> bool {
        self.registered
    }

    /// Send `RegisterSession` and capture the returned session handle.
    pub async fn register(&mut self) -> Result<()> {
        // Payload: protocol_version (u16 LE) = 1, options_flags (u16 LE) = 0.
        let payload: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
        let reply = self
            .exchange(Command::RegisterSession, 0, &payload)
            .await?;
        if reply.payload.len() < 4 {
            return Err(EipError::Short {
                expected: 4,
                actual: reply.payload.len(),
            });
        }
        let version = u16::from_le_bytes([reply.payload[0], reply.payload[1]]);
        if version != 1 {
            return Err(EipError::Protocol(format!(
                "unexpected RegisterSession protocol version {}",
                version
            )));
        }
        self.session_handle = reply.header.session_handle;
        self.registered = true;
        Ok(())
    }

    /// Send `UnRegisterSession`. Does not fail if the peer has already closed.
    pub async fn unregister(&mut self) -> Result<()> {
        if !self.registered {
            return Ok(());
        }
        let frame = encap::encode_frame(
            Command::UnRegisterSession,
            self.session_handle,
            self.next_ctx(),
            &[],
        );
        // Best-effort — target usually just drops the socket.
        let _ = self.stream.write_all(&frame).await;
        self.registered = false;
        Ok(())
    }

    /// Send an unconnected request/reply pair via `SendRRData`.
    ///
    /// `items` are the CPF items to include (typically a null address + one
    /// unconnected-data item carrying the CIP request). `timeout_secs` is
    /// wire-level per-request timeout advertised to the target.
    pub async fn send_rr_data(&mut self, items: &[Item], timeout_secs: u16) -> Result<Envelope> {
        self.require_registered()?;
        let body = cpf::encode_envelope(0, timeout_secs, items);
        let reply = self
            .exchange(Command::SendRRData, self.session_handle, &body)
            .await?;
        Envelope::parse(&reply.payload)
    }

    /// Send an arbitrary CIP service to a class/instance/attribute (idiomatic
    /// wrapper).  Wraps the inner MR in `Unconnected_Send` through the
    /// Connection Manager when `route_path` is non-empty (for backplane
    /// routing to a CPU in another slot); otherwise sends as bare MR.
    ///
    /// Returns `(reply_service, general_status, reply_data)`.
    pub async fn send_generic(
        &mut self,
        service_code: u8,
        class_id: u32,
        instance_id: u32,
        attribute_id: Option<u16>,
        data: &[u8],
        route_path: &[u8],
    ) -> Result<(u8, u8, Vec<u8>)> {
        use crate::cpf::{item_type, Item as CpfItem};
        use crate::path::EpathWriter;
        use crate::unconnected_send;

        // Build the inner path: class(+instance(+attribute)) via the encoder.
        let mut path = EpathWriter::new();
        path.push_class(class_id as u16);
        path.push_instance(instance_id);
        if let Some(attr) = attribute_id {
            path.push_attribute(attr);
        }
        let path_bytes = path.into_bytes();

        let mr = if route_path.is_empty() {
            unconnected_send::build_inner_mr(service_code, &path_bytes, data)?
        } else {
            let inner = unconnected_send::build_inner_mr(service_code, &path_bytes, data)?;
            unconnected_send::wrap(&inner, route_path)?
        };

        let items = [
            CpfItem::null_address(),
            CpfItem::new(item_type::UNCONNECTED_DATA, mr),
        ];
        let envelope = self.send_rr_data(&items, 5).await?;
        let reply = envelope
            .find(item_type::UNCONNECTED_DATA)
            .ok_or_else(|| crate::EipError::Protocol("SendRRData missing UnconnectedData".into()))?;
        // MR reply: service(1) + reserved(1) + status(1) + additional_size(1) + rest.
        if reply.data.len() < 4 {
            return Err(crate::EipError::Protocol("MR reply too short".into()));
        }
        let reply_service = reply.data[0];
        let status = reply.data[2];
        let additional = reply.data[3] as usize;
        let data_start = 4 + additional * 2;
        let body = if reply.data.len() > data_start {
            reply.data[data_start..].to_vec()
        } else {
            Vec::new()
        };
        Ok((reply_service, status, body))
    }

    /// Send a connected (Class 3) request via `SendUnitData`.
    pub async fn send_unit_data(&mut self, items: &[Item]) -> Result<Envelope> {
        self.require_registered()?;
        let body = cpf::encode_envelope(0, 0, items);
        let reply = self
            .exchange(Command::SendUnitData, self.session_handle, &body)
            .await?;
        Envelope::parse(&reply.payload)
    }

    /// Cleanly unregister and drop the socket.
    pub async fn close(mut self) -> Result<()> {
        let _ = self.unregister().await;
        let _ = self.stream.shutdown().await;
        Ok(())
    }

    fn require_registered(&self) -> Result<()> {
        if self.registered {
            Ok(())
        } else {
            Err(EipError::NotRegistered)
        }
    }

    fn next_ctx(&mut self) -> [u8; 8] {
        self.ctx_counter = self.ctx_counter.wrapping_add(1);
        self.ctx_counter.to_le_bytes()
    }

    async fn exchange(
        &mut self,
        command: Command,
        session_handle: u32,
        payload: &[u8],
    ) -> Result<RawReply> {
        let ctx = self.next_ctx();
        let frame = encap::encode_frame(command, session_handle, ctx, payload);
        self.stream.write_all(&frame).await?;

        let mut header_buf = [0u8; HEADER_LEN];
        self.stream.read_exact(&mut header_buf).await?;
        let header = Header::parse(&header_buf)?;

        if header.status != 0 {
            // Drain the payload to keep the stream aligned before returning.
            if header.length > 0 {
                let mut junk = vec![0u8; header.length as usize];
                let _ = self.stream.read_exact(&mut junk).await;
            }
            return Err(EipError::Encap(header.status));
        }

        let mut payload_buf = vec![0u8; header.length as usize];
        if header.length > 0 {
            self.stream.read_exact(&mut payload_buf).await?;
        }
        Ok(RawReply {
            header,
            payload: payload_buf,
        })
    }
}

impl Drop for EipSession {
    fn drop(&mut self) {
        if self.registered {
            // Best effort: build the UnRegisterSession frame and shove it into the
            // socket synchronously. If the runtime is gone we just close.
            let mut buf = BytesMut::with_capacity(HEADER_LEN);
            Header {
                command: Command::UnRegisterSession.as_u16(),
                length: 0,
                session_handle: self.session_handle,
                status: 0,
                sender_context: [0; 8],
                options: 0,
            }
            .write_to(&mut buf);
            let _ = self.stream.try_write(&buf);
        }
    }
}

struct RawReply {
    header: Header,
    payload: Vec<u8>,
}

// Silence the unused-import warning when the buffer helper trait isn't used
// outside `Drop`.
const _: fn(&mut BytesMut) = |b: &mut BytesMut| {
    b.put_u8(0);
};
