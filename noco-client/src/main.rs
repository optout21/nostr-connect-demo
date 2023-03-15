use nostr::nips::nip46::{Message, Request};
use nostr_sdk::prelude::*;
use std::time::Duration;

/// Could be random, using fixed so that the Connect URI is constant, for testing convenience
const APP_SECRET_KEY: &str = "nsec1ufnus6pju578ste3v90xd5m2decpuzpql2295m3sknqcjzyys9ls0qlc85";
const APP_RELAY: &str = "wss://nos.lol";

#[tokio::main]
async fn main() -> Result<()> {
    let app_secret_key = SecretKey::from_bech32(APP_SECRET_KEY)?;
    let app_keys = Keys::new(app_secret_key);
    println!("My pubkey {}", app_keys.public_key());

    let nostr_connect_uri: NostrConnectURI = NostrConnectURI::new(
        app_keys.public_key(),
        Url::parse(APP_RELAY)?,
        "NoConnect-Client",
    )
    .url(Url::parse("https://example.com")?);
    println!("Nostr Connect URI: \n\n{nostr_connect_uri}\n");

    let opts = Options::new().wait_for_send(true);
    let relay_client = Client::new_with_opts(&app_keys, opts);
    relay_client.add_relay(APP_RELAY, None).await?;
    // Warning: error is not handled here, should check back status
    relay_client.connect().await;
    println!("Connected to relay {APP_RELAY}");

    let mut state = State::default();
    let res = wait_and_handle_messages(&relay_client, &mut state);
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
    Unsigned(#[from] nostr_sdk::prelude::unsigned::Error),
}

#[derive(Default)]
struct State {
    signer_app_pubkey: Option<XOnlyPublicKey>,
    signer_signer_pubkey: Option<XOnlyPublicKey>,
    outstanding_describe_req_id: Option<String>,
    outstanding_get_pub_key_req_id: Option<String>,
    outstanding_sign_req_id: Option<String>,
    outstanding_sign_unsigned_event: Option<UnsignedEvent>,
    post_count: u32,
}

fn message_method(msg: &Message) -> String {
    match &msg {
        Message::Request { method, .. } => format!("request {method}"),
        Message::Response { .. } => "response".to_string(),
    }
}

async fn wait_and_handle_messages(relay_client: &Client, state: &mut State) -> Result<(), Error> {
    let keys = relay_client.keys();

    relay_client
        .subscribe(vec![Filter::new()
            .pubkey(keys.public_key())
            .kind(Kind::NostrConnect)
            .since(Timestamp::now() - Duration::from_secs(10))])
        .await;
    println!("Subscribed to relay events ...");
    println!("Waiting for messages, first for a 'connect' from a signer ...");

    loop {
        let mut notifications = relay_client.notifications();
        while let Ok(notification) = notifications.recv().await {
            if let RelayPoolNotification::Event(_url, event) = notification {
                if event.kind == Kind::NostrConnect {
                    match decrypt(&keys.secret_key()?, &event.pubkey, &event.content) {
                        Ok(msg) => {
                            let msg = Message::from_json(msg)?;
                            let _ = handle_request_message(&relay_client, &msg, state).await?;
                        }
                        Err(e) => eprintln!("Impossible to decrypt NIP46 message: {e}"),
                    }
                }
            }
        }
    }
    // relay_client.unsubscribe().await;
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

async fn send_describe(relay_client: &Client, state: &mut State) -> Result<(), Error> {
    println!("Sending Describe ...");
    let msg_to_send = Message::request(Request::Describe);
    let _ = send_message(
        relay_client,
        &msg_to_send,
        &state.signer_app_pubkey.unwrap(),
    )
    .await?;
    state.outstanding_describe_req_id = Some(msg_to_send.id());
    Ok(())
}

async fn send_sign(relay_client: &Client, state: &mut State) -> Result<(), Error> {
    println!("Sending Sign ...");

    let signer_pubkey = state.signer_signer_pubkey.unwrap();
    // compose unsigned event
    state.post_count = state.post_count + 1;
    let unsigned_event = EventBuilder::new_text_note(
        format!(
            "This is a signer-signed message, count {}",
            state.post_count
        ),
        &[],
    )
    .to_unsigned_event(signer_pubkey);
    let msg_to_send = Message::request(Request::SignEvent(unsigned_event.clone()));
    let _ = send_message(
        relay_client,
        &msg_to_send,
        &state.signer_app_pubkey.unwrap(),
    )
    .await?;
    state.outstanding_sign_req_id = Some(msg_to_send.id());
    state.outstanding_sign_unsigned_event = Some(unsigned_event);
    Ok(())
}

async fn send_get_public_key(relay_client: &Client, state: &mut State) -> Result<(), Error> {
    println!("Sending GetPublicKey ...");
    let msg_to_send = Message::request(Request::GetPublicKey);
    let _ = send_message(
        relay_client,
        &msg_to_send,
        &state.signer_app_pubkey.unwrap(),
    )
    .await?;
    state.outstanding_get_pub_key_req_id = Some(msg_to_send.id());
    Ok(())
}

async fn handle_request_message(
    relay_client: &Client,
    msg: &Message,
    state: &mut State,
) -> Result<(), Error> {
    println!("New message received {}", message_method(msg));

    if let Message::Request { .. } = &msg {
        if let Ok(Request::Connect(pubkey)) = msg.to_request() {
            println!("Got connect request, from pubkey {:?}", pubkey);
            state.signer_app_pubkey = Some(pubkey);
            state.signer_signer_pubkey = None;

            send_describe(relay_client, state).await?;
        }
    } else if let Message::Response { id, result, .. } = &msg {
        if state
            .outstanding_describe_req_id
            .as_ref()
            .unwrap_or(&"".to_string())
            == id
        {
            if let Some(value) = result {
                state.outstanding_describe_req_id = None;
                let values = serde_json::from_value::<Vec<String>>(value.to_owned())?;
                println!("Got Describe response, {:?}", values);

                send_get_public_key(relay_client, state).await?;
            } else {
                println!("Error");
            }
        } else if state
            .outstanding_get_pub_key_req_id
            .as_ref()
            .unwrap_or(&"".to_string())
            == id
        {
            if let Some(value) = result {
                state.outstanding_get_pub_key_req_id = None;
                let pubkey = serde_json::from_value::<XOnlyPublicKey>(value.to_owned())?;
                println!("Got PublicKey response, {:?}", pubkey);
                state.signer_signer_pubkey = Some(pubkey);

                send_sign(relay_client, state).await?;
            } else {
                println!("Error");
            }
        } else if state
            .outstanding_sign_req_id
            .as_ref()
            .unwrap_or(&"".to_string())
            == id
        {
            if let Some(value) = result {
                state.outstanding_sign_req_id = None;
                let signature = serde_json::from_value::<nostr_sdk::secp256k1::schnorr::Signature>(
                    value.to_owned(),
                )?;
                println!("Got SignEvent response, {:?}", signature);

                let unsigned_event = state
                    .outstanding_sign_unsigned_event
                    .as_ref()
                    .unwrap()
                    .clone();
                let event = unsigned_event.add_signature(signature)?;
                let id = relay_client.send_event(event).await?;
                println!("Published event, count {}, id {}", state.post_count, id);
            } else {
                println!("Error");
            }
        }
    } else {
        println!("Not a Response, ignoring");
    }

    Ok(())
}
