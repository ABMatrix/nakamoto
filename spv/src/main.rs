/// RUST_LOG=client=trace  cargo run --release --bin spv
use std::{net, thread};

use nakamoto::client::network::{Network, Services};
use nakamoto::client::traits::Handle as _;
use nakamoto::client::{Client, Config, Error};

/// The network reactor we're going to use.
type Reactor = nakamoto::net::poll::Reactor<net::TcpStream>;

/// Run the light-client.
fn main() -> Result<(), Error> {
    env_logger::init();

    let cfg = Config::new(Network::Testnet, "./".into(), None);

    // Create a client using the above network reactor.
    let client = Client::<Reactor>::new()?;
    let handle = client.handle();

    // Run the client on a different thread, to not block the main thread.
    thread::spawn(|| client.run(cfg).unwrap());

    // Wait for the client to be connected to a peer.
    handle.wait_for_peers(5, Services::default())?;

    std::thread::park();
    // Ask the client to terminate.
    handle.shutdown()?;

    Ok(())
}
