//! Dialing the Bitcoin P2P peers with a bounded receive window, and the loopback relay
//! that gives `bip157`'s own sockets the same bound.
//!
//! `[backend] p2p_receive_window_bytes` sets the socket receive buffer (`SO_RCVBUF`) of
//! every outbound P2P connection - the kyoto peers and the P2P mempool feed. Linux derives
//! the TCP window it advertises from that buffer and, with the buffer set by the
//! application, stops autotuning it, so the peer can never have more than that window in
//! flight. At the shipped recommendation of 1448 bytes the advertised window is below one
//! segment, and the peer sends one half-size segment per round trip and never two
//! back-to-back (measured: 1 of 56 segments without an ACK in between; at 2048 bytes the
//! window fits two and the peer sends pairs, 28 of 56). `TCP_WINDOW_CLAMP` is not used:
//! receive-buffer autotuning overwrites it unless the buffer is locked anyway.
//!
//! Why anyone would want this: a network path that loses back-to-back packets but passes
//! spaced ones. Caution's enclave tunnel (a TAP over a vsock byte stream, no framing) is
//! one: of a run of packets arriving together only the first reaches the enclave, so a
//! node's 2000-header answer never gets through and the light client gives up on every
//! peer. Bounding the window at the receiver is the one lever the enclave has. The price
//! is throughput: 724 bytes per round trip, about 3.8 kB/s at 190 ms and 360 kB/s at
//! 2 ms, so it only makes sense with peers close by, and never for a mainnet first sync
//! (bip157 drops a peer whose 999-filter batch takes over 20 s).
//!
//! `bip157` opens its sockets itself, so [`WindowRelay`] listens on loopback for each
//! configured peer, dials the real peer with the bound, and copies bytes both ways; the
//! light client is given the loopback addresses. Loopback never crosses the tunnel.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::task::JoinHandle;
use tracing::debug;

/// The receive-buffer size that keeps a peer to one segment in flight on a 1500-byte MTU
/// path (one MSS); the `zecd.example.toml` recommendation.
pub const ONE_SEGMENT_WINDOW_BYTES: u32 = 1448;

/// Connect to `addr`, with the socket receive buffer set to `receive_window` bytes first
/// when given (it must be set before `connect` to govern the window the SYN advertises).
pub async fn connect(addr: SocketAddr, receive_window: Option<u32>) -> io::Result<TcpStream> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if let Some(bytes) = receive_window {
        socket.set_recv_buffer_size(bytes)?;
    }
    socket.connect(addr).await
}

/// Loopback listeners standing in for the configured kyoto peers, each forwarding to its
/// real peer over a connection dialed with the bounded window.
pub struct WindowRelay {
    /// `(loopback address the light client dials, the real peer)`.
    map: Vec<(SocketAddr, SocketAddr)>,
    listeners: Vec<std::net::TcpListener>,
    receive_window: u32,
    tasks: Vec<JoinHandle<()>>,
}

impl WindowRelay {
    /// Bind one loopback listener per peer. Needs no runtime; [`Self::serve`] starts the
    /// forwarding inside one.
    pub fn bind(peers: &[SocketAddr], receive_window: u32) -> io::Result<Self> {
        let mut map = Vec::with_capacity(peers.len());
        let mut listeners = Vec::with_capacity(peers.len());
        for peer in peers {
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            listener.set_nonblocking(true)?;
            map.push((listener.local_addr()?, *peer));
            listeners.push(listener);
        }
        Ok(Self {
            map,
            listeners,
            receive_window,
            tasks: Vec::new(),
        })
    }

    /// The loopback address to dial for each real peer, in the order given to `bind`.
    pub fn loopback_peers(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.map.iter().map(|(local, _)| *local)
    }

    /// Start accepting, on the runtime entered by the caller. Every accepted connection
    /// gets its own bounded dial to the real peer and a bidirectional copy; the tasks end
    /// with the runtime or on [`Drop`].
    pub fn serve(&mut self) -> io::Result<()> {
        let receive_window = self.receive_window;
        for (listener, (_, peer)) in self.listeners.drain(..).zip(self.map.iter()) {
            let listener = TcpListener::from_std(listener)?;
            let peer = *peer;
            self.tasks.push(tokio::spawn(async move {
                loop {
                    let (mut inbound, _) = match listener.accept().await {
                        Ok(accepted) => accepted,
                        Err(e) => {
                            debug!("window relay for {peer}: accept failed: {e}");
                            break;
                        }
                    };
                    tokio::spawn(async move {
                        match connect(peer, Some(receive_window)).await {
                            Ok(mut outbound) => {
                                if let Err(e) =
                                    tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await
                                {
                                    debug!("window relay to {peer} ended: {e}");
                                }
                            }
                            Err(e) => debug!("window relay could not dial {peer}: {e}"),
                        }
                    });
                }
            }));
        }
        Ok(())
    }
}

impl Drop for WindowRelay {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn connect_sets_the_receive_buffer_before_dialing() {
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = server.local_addr().unwrap();
        let client = connect(addr, Some(ONE_SEGMENT_WINDOW_BYTES)).await.unwrap();
        // The kernel reports at least what was asked (Linux doubles it for bookkeeping);
        // an autotuned default would be tens of kilobytes or more.
        let got = socket2::SockRef::from(&client).recv_buffer_size().unwrap();
        assert!(
            (ONE_SEGMENT_WINDOW_BYTES as usize..=4 * ONE_SEGMENT_WINDOW_BYTES as usize)
                .contains(&got),
            "receive buffer {got} is not the bounded one"
        );
    }

    #[tokio::test]
    async fn relay_forwards_both_ways_and_dials_with_the_bound() {
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let real = server.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut s, _) = server.accept().await.unwrap();
            let got = socket2::SockRef::from(&s).recv_buffer_size().unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
            // The server side's own buffer is untouched; the client side of this
            // connection (the relay's dial) is the bounded one, checked below.
            assert!(got > 4 * ONE_SEGMENT_WINDOW_BYTES as usize);
        });
        let mut relay = WindowRelay::bind(&[real], ONE_SEGMENT_WINDOW_BYTES).unwrap();
        relay.serve().unwrap();
        let via = relay.loopback_peers().next().unwrap();
        assert_ne!(via, real);
        let mut client = TcpStream::connect(via).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"hello");
        echo.await.unwrap();
    }
}
