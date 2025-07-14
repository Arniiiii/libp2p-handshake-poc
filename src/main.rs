use std::{
    collections::hash_map::DefaultHasher,
    error::Error,
    hash::{Hash, Hasher},
    time::Duration,
};

use futures::stream::StreamExt;
use libp2p::{gossipsub, identity, identify, noise, swarm::{NetworkBehaviour, SwarmEvent}, tcp, yamux};
use tokio::{io, io::AsyncBufReadExt, select};
use tracing_subscriber::EnvFilter;

// We create a custom network behaviour that combines Gossipsub and Identify.
#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let transport_kp = identity::Keypair::generate_ed25519();
    let app_kp = identity::Keypair::generate_ed25519();

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
            Ok(MyBehaviour { gossipsub, identify })
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
