use std::{
    collections::{HashMap, HashSet, hash_map::DefaultHasher},
    error::Error,
    hash::{Hash, Hasher},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use ::futures::stream::StreamExt;
use asynchronous_codec::{Framed, JsonCodec};
use futures_util::SinkExt;
use libp2p::{
    PeerId, Stream,
    core::upgrade::{InboundUpgrade, OutboundUpgrade, UpgradeInfo},
    gossipsub, identify,
    identity::{self, PublicKey, ed25519},
    noise,
    swarm::{
        ConnectionHandler, ConnectionHandlerEvent, NetworkBehaviour, SubstreamProtocol, SwarmEvent,
        derive_prelude::*, handler::ListenUpgradeError,
    },
    tcp, yamux,
};
use serde::{Deserialize, Serialize};
use tokio::{io, io::AsyncBufReadExt, select};
use tracing_subscriber::EnvFilter;
// use ed25519::PublicKey;

// enum SignError {
//     SignatureNotCorrespondsPublicKey,
// }
//
// trait Signer {
//     fn sign(
//         data: &Vec<u8>,
//         signer: &PublicKey, /* secret key is handled by the service lib */
//     ) -> Result<Vec<u8>, SignError>;
// }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeMessage {
    pub app_public_key: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct InboundSetupUpgrade {
    pub app_public_key: PublicKey,
    pub tid_to_app_pk: Arc<Mutex<HashMap<PeerId, PublicKey>>>,
    pub app_pk_banned: Arc<Mutex<HashSet<PublicKey>>>,
}

impl InboundSetupUpgrade {
    pub fn new(
        app_public_key: PublicKey,
        tid_to_app_pk: Arc<Mutex<HashMap<PeerId, PublicKey>>>,
        app_pk_banned: Arc<Mutex<HashSet<PublicKey>>>,
    ) -> Self {
        Self {
            app_public_key,
            tid_to_app_pk,
            app_pk_banned,
        }
    }
}

impl UpgradeInfo for InboundSetupUpgrade {
    type Info = &'static str;
    type InfoIter = std::iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once("/handshake/1.0.0")
    }
}

pub enum InboundError {
    IoError(io::Error),
    Banned(PublicKey),
    AppPkDecodingError,
}

impl InboundUpgrade<Stream> for InboundSetupUpgrade {
    type Output = HandshakeMessage;
    type Error = InboundError;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_inbound(self, stream: Stream, _: Self::Info) -> Self::Future {
        Box::pin(async move {
            let mut framed = Framed::new(
                stream,
                JsonCodec::<HandshakeMessage, HandshakeMessage>::new(),
            );
            match StreamExt::next(&mut framed).await {
                Some(Ok(msg)) => {
                    println!("We got message: {:?}", msg);
                    let app_pk_maybe: Result<ed25519::PublicKey, identity::DecodingError> =
                        ed25519::PublicKey::try_from_bytes(&msg.app_public_key);
                    if let Ok(app_pk_successfully_decoded) = app_pk_maybe {
                        let app_pk = PublicKey::from(app_pk_successfully_decoded);
                        if let Some(_) = self.app_pk_banned.lock().unwrap().get(&app_pk) {
                            println!("And its banned {:?}", msg);
                            Err(InboundError::Banned(app_pk))
                        } else {
                            println!("And its not banned {:?}", msg);
                            Ok(msg)
                        }
                    } else {
                        Err(InboundError::AppPkDecodingError)
                    }
                }
                Some(Err(e)) => Err(InboundError::IoError(io::Error::new(
                    io::ErrorKind::InvalidData,
                    e,
                ))),
                None => Err(InboundError::IoError(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "stream closed",
                ))),
            }
        })
    }
}

#[derive(Debug, Clone)]
pub struct OutboundSetupUpgrade {
    pub app_public_key: PublicKey,
    pub tid_to_app_pk: Arc<Mutex<HashMap<PeerId, PublicKey>>>,
    pub app_pk_banned: Arc<Mutex<HashSet<PublicKey>>>,
}

impl OutboundSetupUpgrade {
    pub fn new(
        app_public_key: PublicKey,
        tid_to_app_pk: Arc<Mutex<HashMap<PeerId, PublicKey>>>,
        app_pk_banned: Arc<Mutex<HashSet<PublicKey>>>,
    ) -> Self {
        Self {
            app_public_key,
            tid_to_app_pk,
            app_pk_banned,
        }
    }
}

impl UpgradeInfo for OutboundSetupUpgrade {
    type Info = &'static str;
    type InfoIter = std::iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once("/handshake/1.0.0")
    }
}

impl OutboundUpgrade<Stream> for OutboundSetupUpgrade {
    type Output = ();
    type Error = io::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_outbound(self, stream: Stream, _: Self::Info) -> Self::Future {
        Box::pin(async move {
            let app_message = HandshakeMessage {
                app_public_key: self.app_public_key.try_into_ed25519().unwrap().to_bytes(),
            };
            let mut framed = Framed::new(
                stream,
                JsonCodec::<HandshakeMessage, HandshakeMessage>::new(),
            );
            framed
                .send(app_message)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            framed
                .close()
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
        })
    }
}

pub struct SetupHandler {
    outbound_substream: Option<SubstreamProtocol<OutboundSetupUpgrade, ()>>,
    pending_events: Vec<ConnectionHandlerEvent<OutboundSetupUpgrade, (), SetupHandlerEvent>>,
    app_public_key: PublicKey,
    tid_to_app_pk: Arc<Mutex<HashMap<PeerId, PublicKey>>>,
    app_pk_banned: Arc<Mutex<HashSet<PublicKey>>>,
}

#[derive(Debug, Clone)]
pub enum SetupHandlerEvent {
    AppKeyReceived { app_public_key: PublicKey },
    HandshakeComplete,
    ReceivedFromBannedPeer { app_public_key: PublicKey },
    DecodingError,
    IoError,
}

#[derive(Debug, Clone)]
pub enum SetupBehaviourEvent {
    AppKeyReceived {
        peer_id: PeerId,
        app_public_key: PublicKey,
    },
    HandshakeComplete {
        peer_id: PeerId,
    },
    ReceivedFromBannedPeer {
        peer_id: PeerId,
        app_public_key: PublicKey,
    },
    DecodingError {
        peer_id: PeerId,
    },
    IoError {
        peer_id: PeerId,
    },
}
impl SetupHandler {
    pub fn new(
        app_public_key: PublicKey,
        tid_to_app_pk: Arc<Mutex<HashMap<PeerId, PublicKey>>>,
        app_pk_banned: Arc<Mutex<HashSet<PublicKey>>>,
    ) -> Self {
        Self {
            outbound_substream: Some(SubstreamProtocol::new(
                OutboundSetupUpgrade::new(
                    app_public_key.clone(),
                    tid_to_app_pk.clone(),
                    app_pk_banned.clone(),
                ),
                (),
            )),
            pending_events: Vec::new(),
            app_public_key,
            tid_to_app_pk,
            app_pk_banned,
        }
    }
}

impl ConnectionHandler for SetupHandler {
    type FromBehaviour = ();
    type ToBehaviour = SetupHandlerEvent;
    type InboundProtocol = InboundSetupUpgrade;
    type OutboundProtocol = OutboundSetupUpgrade;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, ()> {
        SubstreamProtocol::new(
            InboundSetupUpgrade::new(
                self.app_public_key.clone(),
                self.tid_to_app_pk.clone(),
                self.app_pk_banned.clone(),
            ),
            (),
        )
    }

    fn poll(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<ConnectionHandlerEvent<Self::OutboundProtocol, (), Self::ToBehaviour>> {
        if let Some(event) = self.pending_events.pop() {
            return Poll::Ready(event);
        }

        if let Some(substream) = self.outbound_substream.take() {
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: substream,
            });
        }

        Poll::Pending
    }

    fn on_behaviour_event(&mut self, _: Self::FromBehaviour) {}

    fn on_connection_event(
        &mut self,
        event: libp2p::swarm::handler::ConnectionEvent<
            Self::InboundProtocol,
            Self::OutboundProtocol,
        >,
    ) {
        match event {
            libp2p::swarm::handler::ConnectionEvent::FullyNegotiatedInbound(inbound) => {
                let handshake_msg = inbound.protocol;
                let public_key = PublicKey::from(
                    ed25519::PublicKey::try_from_bytes(&handshake_msg.app_public_key).unwrap(),
                );
                self.pending_events
                    .push(ConnectionHandlerEvent::NotifyBehaviour(
                        SetupHandlerEvent::AppKeyReceived {
                            app_public_key: public_key,
                        },
                    ));
            }
            libp2p::swarm::handler::ConnectionEvent::FullyNegotiatedOutbound(_outbound) => {
                self.pending_events
                    .push(ConnectionHandlerEvent::NotifyBehaviour(
                        SetupHandlerEvent::HandshakeComplete {},
                    ));
            }
            libp2p::swarm::handler::ConnectionEvent::DialUpgradeError(_) => {
                // Handle dial upgrade error
            }
            libp2p::swarm::handler::ConnectionEvent::ListenUpgradeError(ListenUpgradeError {
                info: _info,
                error,
            }) => {
                // Handle listen upgrade error
                match error {
                    InboundError::AppPkDecodingError => {
                        self.pending_events
                            .push(ConnectionHandlerEvent::NotifyBehaviour(
                                SetupHandlerEvent::DecodingError,
                            ));
                    }
                    InboundError::Banned(app_pk) => {
                        self.pending_events
                            .push(ConnectionHandlerEvent::NotifyBehaviour(
                                SetupHandlerEvent::ReceivedFromBannedPeer {
                                    app_public_key: app_pk,
                                },
                            ));
                    }
                    InboundError::IoError(_) => {}
                }
            }
            _ => {}
        }
    }

    fn connection_keep_alive(&self) -> bool {
        true
    }
}

#[derive(Debug)]
pub struct SetupBehaviour {
    app_public_key: PublicKey,
    tid_to_app_keys: Arc<Mutex<HashMap<PeerId, PublicKey>>>,
    app_pk_banned: Arc<Mutex<HashSet<PublicKey>>>,
    events: Vec<SetupBehaviourEvent>,
}

impl SetupBehaviour {
    pub fn new(
        app_public_key: PublicKey,
        tid_to_app_pk: Arc<Mutex<HashMap<PeerId, PublicKey>>>,
        app_pk_banned: Arc<Mutex<HashSet<PublicKey>>>,
    ) -> Self {
        Self {
            app_public_key,
            tid_to_app_keys: tid_to_app_pk,
            events: Vec::new(),
            app_pk_banned,
        }
    }

    pub fn get_app_key(&self, peer_id: &PeerId) -> Option<PublicKey> {
        self.tid_to_app_keys.lock().unwrap().get(peer_id).cloned()
    }
}

impl NetworkBehaviour for SetupBehaviour {
    type ConnectionHandler = SetupHandler;
    type ToSwarm = SetupBehaviourEvent;

    fn handle_established_inbound_connection(
        &mut self,
        _: libp2p::swarm::ConnectionId,
        _: PeerId,
        _: &libp2p::Multiaddr,
        _: &libp2p::Multiaddr,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        Ok(SetupHandler::new(
            self.app_public_key.clone(),
            self.tid_to_app_keys.clone(),
            self.app_pk_banned.clone(),
        ))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: libp2p::swarm::ConnectionId,
        _: PeerId,
        _: &libp2p::Multiaddr,
        _: libp2p::core::Endpoint,
        _: PortUse,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        Ok(SetupHandler::new(
            self.app_public_key.clone(),
            self.tid_to_app_keys.clone(),
            self.app_pk_banned.clone(),
        ))
    }

    fn on_swarm_event(&mut self, _: libp2p::swarm::FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        _: libp2p::swarm::ConnectionId,
        event: libp2p::swarm::THandlerOutEvent<Self>,
    ) {
        match event {
            SetupHandlerEvent::AppKeyReceived { app_public_key, .. } => {
                self.tid_to_app_keys
                    .lock()
                    .unwrap()
                    .insert(peer_id, app_public_key.clone());
                self.events.push(SetupBehaviourEvent::AppKeyReceived {
                    peer_id,
                    app_public_key,
                });
            }
            SetupHandlerEvent::HandshakeComplete { .. } => {
                self.events
                    .push(SetupBehaviourEvent::HandshakeComplete { peer_id });
            }
            SetupHandlerEvent::ReceivedFromBannedPeer { app_public_key } => {
                self.events
                    .push(SetupBehaviourEvent::ReceivedFromBannedPeer {
                        peer_id,
                        app_public_key,
                    })
            }
            SetupHandlerEvent::IoError => {
                self.events.push(SetupBehaviourEvent::IoError { peer_id })
            }
            SetupHandlerEvent::DecodingError => self
                .events
                .push(SetupBehaviourEvent::DecodingError { peer_id }),
        }
    }

    fn poll(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<libp2p::swarm::ToSwarm<Self::ToSwarm, libp2p::swarm::THandlerInEvent<Self>>> {
        if let Some(event) = self.events.pop() {
            return Poll::Ready(libp2p::swarm::ToSwarm::GenerateEvent(event));
        }
        Poll::Pending
    }
}

// We create a custom network behaviour that combines Gossipsub, Identify, and Handshake.
#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    handshake: SetupBehaviour,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let transport_kp = identity::Keypair::generate_ed25519();

    let mut app_kp1 = Vec::from([
        0xe6, 0x47, 0x24, 0x96, 0xaa, 0x6b, 0xa0, 0xb8, 0xe5, 0xa5, 0x42, 0xbc, 0x96, 0x3e, 0x1c,
        0x29, 0x2e, 0xba, 0x32, 0x40, 0x46, 0x81, 0x10, 0x37, 0xb8, 0x19, 0x3a, 0xeb, 0x91, 0x27,
        0x36, 0xa1,
    ]);
    let mut app_kp2 = Vec::from([
        0xd1, 0xc0, 0x5e, 0x44, 0xc9, 0x72, 0xce, 0x14, 0xd7, 0xd9, 0x6c, 0x7a, 0x7d, 0xc1, 0x08,
        0x71, 0x61, 0x5e, 0x07, 0x97, 0x29, 0x3c, 0x7a, 0x44, 0x1d, 0xc7, 0x1a, 0xaa, 0xfe, 0xb6,
        0xd7, 0x45,
    ]);
    let _app_kp3 = Vec::from([
        0x91, 0x33, 0xfd, 0xd7, 0xb3, 0xe4, 0x92, 0x83, 0x41, 0x9e, 0xa6, 0x89, 0x77, 0xc6, 0xbb,
        0x47, 0xd8, 0x0f, 0xd0, 0xff, 0xfa, 0x04, 0x52, 0x4d, 0x52, 0xe3, 0x46, 0xe4, 0x20, 0x2f,
        0x6d, 0xce,
    ]);
    let _app_kp4 = Vec::from([
        0x83, 0x20, 0xbc, 0x1d, 0xd3, 0x21, 0x67, 0xdb, 0xc3, 0xf2, 0xd7, 0x7c, 0x1f, 0xf0, 0x6f,
        0xad, 0x0c, 0xf7, 0x4f, 0x14, 0x0f, 0x9d, 0x07, 0xdb, 0xc7, 0x88, 0xdb, 0x6b, 0x07, 0x9f,
        0x98, 0x9e,
    ]);
    let mut app_kp5 = Vec::from([
        0xba, 0x35, 0x69, 0x3f, 0x23, 0x20, 0xd4, 0xc3, 0xda, 0xab, 0xb5, 0xe8, 0x41, 0x6e, 0xba,
        0x46, 0x80, 0xea, 0xb8, 0x0f, 0xf8, 0x4a, 0x55, 0x9e, 0x65, 0xf1, 0x50, 0x20, 0x57, 0x97,
        0x42, 0x90,
    ]);

    println!("app_kp creating, {}", app_kp1.len());
    let app_kp = libp2p::identity::Keypair::ed25519_from_bytes(&mut app_kp1)?;

    let tid_to_app_pk: Arc<Mutex<HashMap<PeerId, PublicKey>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let app_pk_banned: Arc<Mutex<HashSet<PublicKey>>> = Arc::new(Mutex::new(HashSet::new()));

    println!("app_kp5 creating");
    app_pk_banned
        .lock()
        .unwrap()
        .insert(libp2p::identity::Keypair::ed25519_from_bytes(&mut app_kp5)?.public());

    println!(
        "app_pk: {:?}",
        hex::encode(app_kp.public().try_into_ed25519().unwrap().to_bytes())
    );

    println!("transport_id: {}", transport_kp.public().to_peer_id());

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(transport_kp)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|key| {
            // To content-address message, we can take the hash of message and use it as an ID.
            let message_id_fn = |message: &gossipsub::Message| {
                let mut s = DefaultHasher::new();
                message.data.hash(&mut s);
                gossipsub::MessageId::from(s.finish().to_string())
            };

            // Set a custom gossipsub configuration
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
                .validation_mode(gossipsub::ValidationMode::Permissive) // This sets the kind of message validation. The default is Strict (enforce message
                // signing)
                .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
                .build()
                .map_err(io::Error::other)?; // Temporary hack because `build` does not return a proper `std::error::Error`.

            // build a gossipsub network behaviour
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Author(key.public().to_peer_id()),
                gossipsub_config,
            )?;

            let identify =
                identify::Behaviour::new(identify::Config::new("/ipfs/0.1.0".into(), key.public()));

            let handshake = SetupBehaviour::new(app_kp.public(), tid_to_app_pk, app_pk_banned);

            Ok(MyBehaviour {
                gossipsub,
                identify,
                handshake,
            })
        })?
        .build();

    // Create a Gossipsub topic
    let topic = gossipsub::IdentTopic::new("test-net");
    // subscribes to our topic
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

    // Read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines();

    // Listen on all interfaces and whatever port the OS assigns
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    println!("Enter messages via STDIN and they will be sent to connected peers using Gossipsub");
    println!("Commands:");
    println!("  /connect <multiaddr> - Connect to a peer");
    println!("  /keys - Show transport_kp => app_kp mapping for all peers");
    println!("  /getconnectedpeers - Show getconnectedpeers");
    println!("  Any other text will be sent as a message");

    // Kick it off
    loop {
        select! {
            Ok(Some(line)) = stdin.next_line() => {
                if line.starts_with("/connect ") {
                    if let Some(addr) = line.strip_prefix("/connect ") {
                        match addr.parse::<libp2p::Multiaddr>() {
                            Ok(multiaddr) => {
                                match swarm.dial(multiaddr) {
                                    Ok(_) => println!("Dialing {addr}..."),
                                    Err(e) => println!("Failed to dial {addr}: {e:?}"),
                                }
                            }
                            Err(e) => println!("Invalid multiaddr '{addr}': {e:?}"),
                        }
                    } else {
                        println!("Usage: /connect <multiaddr>");
                    }
                } else if line == "/keys" {
                    println!("Transport Key => App Key mapping:");
                    for (peer_id, app_key) in swarm.behaviour().handshake.tid_to_app_keys.lock().unwrap().iter() {
                        println!("  {peer_id} => {}", hex::encode(app_key.clone().try_into_ed25519()?.to_bytes()));
                    }
                } else if line == "/getconnectedpeers" {
                    println!("ConnectPeers:");
                    println!("{:?}",swarm.connected_peers().collect::<Vec<_>>());
                } else {
                    if let Err(e) = swarm
                        .behaviour_mut().gossipsub
                        .publish(topic.clone(), line.as_bytes()) {
                        println!("Publish error: {e:?}");
                    }
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(MyBehaviourEvent::Identify(identify::Event::Received {
                    peer_id,
                    info: _,
                    connection_id: _,
                })) => {
                    println!("Identify received from peer: {peer_id}");
                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Identify(identify::Event::Sent {
                    peer_id,
                    connection_id: _,
                })) => {
                    println!("Identify sent to peer: {peer_id}");
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Handshake(SetupBehaviourEvent::AppKeyReceived {
                    peer_id,
                    app_public_key: _
                })) => {
                    println!("Handshake: Received app key from peer {peer_id}");
                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Handshake(SetupBehaviourEvent::HandshakeComplete {
                    peer_id
                })) => {
                    println!("Handshake: Completed with peer {peer_id}");
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Handshake(SetupBehaviourEvent::DecodingError {
                    peer_id
                })) => {
                    println!("Setup: decoding of secret key error {peer_id}");
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Handshake(SetupBehaviourEvent::ReceivedFromBannedPeer {
                    peer_id,
                    app_public_key
                })) => {
                    println!("Setup: an attempt to connect from a banned user {peer_id} {app_public_key:?}");
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Handshake(SetupBehaviourEvent::IoError {
                    peer_id,
                })) => {
                    println!("Setup: IoError {peer_id}");
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message_id: id,
                    message,
                })) => println!(
                        "Got message: '{}' with id: {id} from peer: {peer_id}",
                        String::from_utf8_lossy(&message.data),
                    ),
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Local node is listening on {address}");
                }
                SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                    println!("Connected to peer {peer_id} at {}", endpoint.get_remote_address());
                }
                SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                    println!("Connection to peer {peer_id} closed: {cause:?}");
                }
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    if let Some(peer_id) = peer_id {
                        println!("Failed to connect to peer {peer_id}: {error:?}");
                    } else {
                        println!("Failed to establish outgoing connection: {error:?}");
                    }
                }
                _ => {}
            }
        }
    }
}
