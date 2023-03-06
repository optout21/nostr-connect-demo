use nostr::nips::nip46::{Message, Request};
use nostr_sdk::prelude::*;
use std::str::FromStr;
use std::time::Duration;

const SAMPLE_NOSTR_CONNECT_URL: &str = "nostrconnect://79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3?relay=wss%3A%2F%2Fnos.lol%2F&metadata=%7B%22name%22%3A%22NoConnect-Client%22%2C%22url%22%3A%22https%3A%2F%2Fexample.com%2F%22%7D";
// Key of the signer identity
const USER_SECRET_KEY: &str = "nsec1mx076pc0mqggw826dcz0cl9s2pe9rsvguq3zul9jedu2m52slg5q44p8xf";

#[tokio::main]
async fn main() -> Result<()> {
    let signer_keys = Keys::generate();
    println!("My pubkey {}", signer_keys.public_key());

    println!("User pubkey {}", user_public_key());

    let nostr_connect_uri: NostrConnectURI =
        NostrConnectURI::from_str(SAMPLE_NOSTR_CONNECT_URL).unwrap();
    let app_pubkey = nostr_connect_uri.public_key.clone();
    let relay = &nostr_connect_uri.relay_url;
    println!("NostrConnect URI: {nostr_connect_uri}");
    println!(
        "App key: {} {}",
        app_pubkey,
        app_pubkey.to_bech32().unwrap()
    );
    println!("Relay: {relay}");

    let opts = Options::new().wait_for_send(true);
    let relay_client = Client::new_with_opts(&signer_keys, opts);
    relay_client.add_relay(relay.to_string(), None).await?;
    relay_client.connect().await;
    println!("Connected to relay {relay}");

    let res = wait_and_handle_messages(&relay_client);

    // Send connect ACK
    let msg = Message::request(Request::Connect(signer_keys.public_key()));
    let _ = send_message(&relay_client, &msg, &app_pubkey).await?;

    res.await?;

    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    Keys(#[from] nostr_sdk::nostr::key::Error),
    #[error(transparent)]
    Builder(#[from] nostr_sdk::nostr::event::builder::Error),
    #[error(transparent)]
    Client(#[from] nostr_sdk::client::Error),
    #[error(transparent)]
    Nip46(#[from] nostr_sdk::nostr::nips::nip46::Error),
    #[error(transparent)]
    JSON(#[from] serde_json::Error),
    #[error(transparent)]
    SigningError(#[from] nostr::secp256k1::Error),
}

fn user_public_key() -> XOnlyPublicKey {
    user_keys().public_key()
}

fn user_keys() -> Keys {
    let secret_key = SecretKey::from_bech32(USER_SECRET_KEY).unwrap();
    Keys::new(secret_key)
}

fn message_method(msg: &Message) -> String {
    match &msg {
        Message::Request { method, .. } => format!("request {method}"),
        Message::Response { .. } => "response".to_string(),
    }
}

async fn send_message(
    relay_client: &Client,
    msg: &Message,
    receiver_pubkey: &XOnlyPublicKey,
) -> Result<(), Error> {
    let keys = relay_client.keys();
    let event =
        EventBuilder::nostr_connect(&keys, *receiver_pubkey, msg.clone())?.to_event(&keys)?;
    relay_client.send_event(event).await?;
    println!("Message sent, {}", message_method(&msg),);
    Ok(())
}

async fn wait_and_handle_messages(relay_client: &Client) -> Result<(), Error> {
    let keys = relay_client.keys();

    relay_client
        .subscribe(vec![Filter::new()
            .pubkey(keys.public_key())
            .kind(Kind::NostrConnect)
            .since(Timestamp::now() - Duration::from_secs(10))])
        .await;
    println!("Subscribed to relay events ...");
    println!("Waiting for messages ...");

    loop {
        let mut notifications = relay_client.notifications();
        while let Ok(notification) = notifications.recv().await {
            if let RelayPoolNotification::Event(_url, event) = notification {
                if event.kind == Kind::NostrConnect {
                    match decrypt(&keys.secret_key()?, &event.pubkey, &event.content) {
                        Ok(msg) => {
                            let msg = Message::from_json(msg)?;
                            let _ =
                                handle_request_message(&relay_client, &msg, &event.pubkey).await?;
                        }
                        Err(e) => eprintln!("Impossible to decrypt NIP46 message: {e}"),
                    }
                }
            }
        }
    }
    // relay_client.unsubscribe().await;
}

async fn handle_request_message(
    relay_client: &Client,
    msg: &Message,
    sender_pubkey: &XOnlyPublicKey,
) -> Result<(), Error> {
    println!("New message received {}", message_method(msg));

    if let Message::Request { id, .. } = msg {
        if let Ok(req) = msg.to_request() {
            match req {
                Request::Describe => {
                    println!("Describe received");
                    let values = serde_json::json!(["describe", "get_public_key", "sign_event"]);
                    let response_msg = Message::response(id.clone(), Response::Describe(values));
                    let _ = send_message(relay_client, &response_msg, sender_pubkey).await?;
                }
                Request::GetPublicKey => {
                    println!("GetPublicKey received");
                    let response_msg =
                        Message::response(id.clone(), Response::GetPublicKey(user_public_key()));
                    let _ = send_message(relay_client, &response_msg, sender_pubkey).await?;
                }
                Request::SignEvent(unsigned_event) => {
                    println!("SignEvent received");
                    let unsigned_id = unsigned_event.id;
                    let key_pair = user_keys().key_pair()?;
                    let signature = SECP256K1.sign_schnorr(
                        &nostr::secp256k1::Message::from_slice(unsigned_id.as_bytes())?,
                        &key_pair,
                    );
                    let response_msg =
                        Message::response(id.clone(), Response::SignEvent(signature));
                    let _ = send_message(relay_client, &response_msg, sender_pubkey).await?;
                }
                _ => {
                    println!("Unhandled Request {:?}", msg.to_request());
                }
            };
        } else {
            println!("Could not extract Request, ignoring");
        }
    } else {
        println!("Not a Request, ignoring");
    }
    Ok(())
}
