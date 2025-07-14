use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    error::Error,
    hash::{Hash, Hasher},
    time::Duration,
    task::{Context, Poll},
    pin::Pin,
};

use ::futures::stream::StreamExt;
use libp2p::{
    gossipsub, identity, identify, noise, 
    swarm::{NetworkBehaviour, SwarmEvent, ConnectionHandler, ConnectionHandlerEvent, 
           SubstreamProtocol, derive_prelude::*},
    tcp, yamux, PeerId, Stream,
    core::upgrade::{InboundUpgrade, OutboundUpgrade, UpgradeInfo},
};
use tokio::{io, io::AsyncBufReadExt, select};
use serde::{Deserialize, Serialize};
use asynchronous_codec::{Framed, JsonCodec};
use futures_util::SinkExt;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeMessage {
    pub app_public_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct HandshakeProtocol;

impl UpgradeInfo for HandshakeProtocol {
    type Info = &'static str;
    type InfoIter = std::iter::Once<Self::Info>;
    
    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once("/handshake/1.0.0")
    }
}

impl InboundUpgrade<Stream> for HandshakeProtocol {
    type Output = HandshakeMessage;
    type Error = io::Error;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_inbound(self, stream: Stream, _: Self::Info) -> Self::Future {
        Box::pin(async move {
            let mut framed = Framed::new(stream, JsonCodec::<HandshakeMessage, HandshakeMessage>::new());
            match StreamExt::next(&mut framed).await {
                Some(Ok(msg)) => Ok(msg),
                Some(Err(e)) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
                None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "stream closed")),
            }
        })
    }
}

impl OutboundUpgrade<Stream> for HandshakeProtocol {
    type Output = ();
    type Error = io::Error;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_outbound(self, stream: Stream, _: Self::Info) -> Self::Future {
        Box::pin(async move {
            let app_message = HandshakeMessage { 
                app_public_key: vec![] // This will be set from the handler's app_public_key
            };
            let mut framed = Framed::new(stream, JsonCodec::<HandshakeMessage, HandshakeMessage>::new());
            framed.send(app_message).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            framed.close().await.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
        })
    }
}

pub struct HandshakeHandler {
    app_public_key: Vec<u8>,
    outbound_substream: Option<SubstreamProtocol<HandshakeProtocol, ()>>,
    pending_events: Vec<ConnectionHandlerEvent<HandshakeProtocol, (), HandshakeEvent>>,
}

#[derive(Debug, Clone)]
pub enum HandshakeEvent {
    AppKeyReceived { peer_id: PeerId, app_public_key: Vec<u8> },
    HandshakeComplete { peer_id: PeerId },
}

impl HandshakeHandler {
    pub fn new(app_public_key: Vec<u8>) -> Self {
        Self {
            app_public_key,
            outbound_substream: Some(SubstreamProtocol::new(HandshakeProtocol, ())),
            pending_events: Vec::new(),
        }
    }
}

impl ConnectionHandler for HandshakeHandler {
    type FromBehaviour = ();
    type ToBehaviour = HandshakeEvent;
    type InboundProtocol = HandshakeProtocol;
    type OutboundProtocol = HandshakeProtocol;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, ()> {
        SubstreamProtocol::new(HandshakeProtocol, ())
    }

    fn poll(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<
            Self::OutboundProtocol,
            (),
            Self::ToBehaviour,
        >,
    > {
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
                self.pending_events.push(ConnectionHandlerEvent::NotifyBehaviour(
                    HandshakeEvent::AppKeyReceived {
                        peer_id: PeerId::random(),
                        app_public_key: handshake_msg.app_public_key,
                    },
                ));
            }
            libp2p::swarm::handler::ConnectionEvent::FullyNegotiatedOutbound(_outbound) => {
                self.pending_events.push(ConnectionHandlerEvent::NotifyBehaviour(
                    HandshakeEvent::HandshakeComplete {
                        peer_id: PeerId::random(),
                    },
                ));
            }
            libp2p::swarm::handler::ConnectionEvent::DialUpgradeError(_) => {
                // Handle dial upgrade error
            }
            libp2p::swarm::handler::ConnectionEvent::ListenUpgradeError(_) => {
                // Handle listen upgrade error
            }
            _ => {}
        }
    }

    fn connection_keep_alive(&self) -> bool {
        true
    }
}

#[derive(Debug)]
pub struct HandshakeBehaviour {
    app_public_key: Vec<u8>,
    pub peer_app_keys: HashMap<PeerId, Vec<u8>>,
    events: Vec<HandshakeEvent>,
}

impl HandshakeBehaviour {
    pub fn new(app_public_key: Vec<u8>) -> Self {
        Self {
            app_public_key,
            peer_app_keys: HashMap::new(),
            events: Vec::new(),
        }
    }

    pub fn get_app_key(&self, peer_id: &PeerId) -> Option<&Vec<u8>> {
        self.peer_app_keys.get(peer_id)
    }
}

impl NetworkBehaviour for HandshakeBehaviour {
    type ConnectionHandler = HandshakeHandler;
    type ToSwarm = HandshakeEvent;

    fn handle_established_inbound_connection(
        &mut self,
        _: libp2p::swarm::ConnectionId,
        _: PeerId,
        _: &libp2p::Multiaddr,
        _: &libp2p::Multiaddr,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        Ok(HandshakeHandler::new(self.app_public_key.clone()))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: libp2p::swarm::ConnectionId,
        _: PeerId,
        _: &libp2p::Multiaddr,
        _: libp2p::core::Endpoint,
        _: PortUse,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        Ok(HandshakeHandler::new(self.app_public_key.clone()))
    }

    fn on_swarm_event(&mut self, _: libp2p::swarm::FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        _: libp2p::swarm::ConnectionId,
        event: libp2p::swarm::THandlerOutEvent<Self>,
    ) {
        match event {
            HandshakeEvent::AppKeyReceived { app_public_key, .. } => {
                self.peer_app_keys.insert(peer_id, app_public_key.clone());
                self.events.push(HandshakeEvent::AppKeyReceived {
                    peer_id,
                    app_public_key,
                });
            }
            HandshakeEvent::HandshakeComplete { .. } => {
                self.events.push(HandshakeEvent::HandshakeComplete { peer_id });
            }
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
    handshake: HandshakeBehaviour,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let transport_kp = identity::Keypair::generate_ed25519();
    let app_kp = identity::Keypair::generate_ed25519();
    
    println!("app_pk: {}", hex::encode(app_kp.public().encode_protobuf()));
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
                gossipsub::MessageAuthenticity::Author(app_kp.public().to_peer_id()),
                gossipsub_config,
            )?;

            let identify = identify::Behaviour::new(identify::Config::new(
                "/ipfs/0.1.0".into(),
                key.public(),
            ));
            
            let handshake = HandshakeBehaviour::new(app_kp.public().encode_protobuf());
            
            Ok(MyBehaviour { gossipsub, identify, handshake })
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
                    for (peer_id, app_key) in swarm.behaviour().handshake.peer_app_keys.iter() {
                        println!("  {peer_id} => {}", hex::encode(app_key));
                    }
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
                SwarmEvent::Behaviour(MyBehaviourEvent::Handshake(HandshakeEvent::AppKeyReceived { 
                    peer_id, 
                    app_public_key: _ 
                })) => {
                    println!("Handshake: Received app key from peer {peer_id}");
                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Handshake(HandshakeEvent::HandshakeComplete { 
                    peer_id 
                })) => {
                    println!("Handshake: Completed with peer {peer_id}");
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
