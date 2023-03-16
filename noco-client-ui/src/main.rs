use nostr::nips::nip46::{Message, Request};
use nostr_sdk::prelude::*;

use iced::widget::{button, column, row, text, text_input};
use iced::{
    executor, subscription, Alignment, Application, Command, Element, Length, Settings,
    Subscription, Theme,
};

use crossbeam::channel;
use once_cell::sync::Lazy;

use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Relay to use
const DEFAULT_APP_RELAY: &str = "wss://nos.lol";
/// Could be random, using fixed so that the Connect URI is constant, for testing convenience
const APP_SECRET_KEY: &str = "nsec1ufnus6pju578ste3v90xd5m2decpuzpql2295m3sknqcjzyys9ls0qlc85";
/// Included in connect URI, has no real relevance here
const SAMPLE_WEB_URL: &str = "https://example.com";

/// Mostly non-changing state variables
#[derive(Clone)]
struct StateStatic {
    relay_str: String,
    nostr_connect_str: String,
    relay_client: Client,
}

/// The dynamically changing part of the state, single-thread usage
#[derive(Clone, Default)]
struct StateDynamicSingle {
    /// Client pubkey of the signer, if connected (we can send to this pubkey)
    signer_app_pubkey: Option<XOnlyPublicKey>,
    /// Signer pubkey of the signer, if connected and retrieved (it will sign with this)
    signer_signer_pubkey: Option<XOnlyPublicKey>,
    /// The capabilities of the Signer, as returned by describe, stored for display
    signer_capabilities: Option<String>,
    outstanding_describe_req_id: Option<String>,
    outstanding_get_pubkey_req_id: Option<String>,
    outstanding_sign_req_id: Option<String>,
    outstanding_sign_unsigned_event: Option<UnsignedEvent>,
    count_sign_requests: u32,
    count_posts: u32,
}

/// Dynamic state, thread-safe version
struct StateDynamic {
    st: RwLock<StateDynamicSingle>,
}

/// Static event queue used to send notifications to the UI
static EVENT_QUEUE: Lazy<EventQueue> = Lazy::new(|| EventQueue::new());

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
    #[error(transparent)]
    InternalAsyncError(#[from] crossbeam::channel::RecvError),
    #[error(transparent)]
    ParseError(#[from] ParseError),
    #[error("No Signer is connected, or no signer key is available")]
    NoSignerConnected,
    #[error("Internal event queue send error")]
    InternalEventQueueSend,
}

/// Events that can affect the UI
#[derive(Clone, Debug)]
pub enum Event {
    RelayConnected,
    SignerConnected,
    SignerCapabsObtained,
    SignerPubkeyObtained,
    SignRequestSent,
    PostPublished,
}

/// Used to notify the UI from the background workers
pub(crate) struct EventQueue {
    sender: channel::Sender<Event>,
    receiver: channel::Receiver<Event>,
}

/// Struct for the App with UI
struct DemoApp {
    state: Arc<StateStatic>,
    state_dynamic: Arc<StateDynamic>,
    post_text: String,
}

/// Signer connection status: connected or not, or connection pending
#[derive(Debug)]
enum ConnectionStatus {
    NotConnected,
    Connecting,
    Connected,
}

impl StateStatic {
    fn init() -> Result<Self, Error> {
        let app_secret_key = SecretKey::from_bech32(APP_SECRET_KEY).unwrap();
        let app_keys = Keys::new(app_secret_key);
        let relay_str = DEFAULT_APP_RELAY.to_string();
        let nostr_connect_uri: NostrConnectURI = NostrConnectURI::new(
            app_keys.public_key(),
            Url::parse(&relay_str)?,
            "NoCon-Demo UI Client",
        )
        .url(Url::parse(SAMPLE_WEB_URL)?);
        let nostr_connect_str = nostr_connect_uri.to_string();

        // Create relay client now, but do not connect it yet
        let opts = Options::new().wait_for_send(true);
        let relay_client = Client::new_with_opts(&app_keys, opts);

        Ok(Self {
            relay_str,
            nostr_connect_str,
            relay_client,
        })
    }
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

async fn send_describe(
    relay_client: &Client,
    signer_app_pubkey: &XOnlyPublicKey,
    state_dynamic: Arc<StateDynamic>,
) -> Result<(), Error> {
    println!("DEBUG: Sending Describe ...");
    let msg_to_send = Message::request(Request::Describe);
    let _ = send_message(relay_client, &msg_to_send, signer_app_pubkey).await?;
    state_dynamic
        .st
        .write()
        .unwrap()
        .outstanding_describe_req_id = Some(msg_to_send.id());
    Ok(())
}

async fn send_get_public_key(
    relay_client: &Client,
    signer_app_pubkey: &XOnlyPublicKey,
    state_dynamic: Arc<StateDynamic>,
) -> Result<(), Error> {
    println!("DEBUG: Sending GetPublicKey ...");
    let msg_to_send = Message::request(Request::GetPublicKey);
    let _ = send_message(relay_client, &msg_to_send, signer_app_pubkey).await?;
    state_dynamic
        .st
        .write()
        .unwrap()
        .outstanding_get_pubkey_req_id = Some(msg_to_send.id());
    Ok(())
}

async fn send_sign(
    relay_client: &Client,
    signer_app_pubkey: &XOnlyPublicKey,
    signer_signer_pubkey: XOnlyPublicKey,
    text: &str,
    state_dynamic: Arc<StateDynamic>,
) -> Result<(), Error> {
    println!("DEBUG Sending Sign ...");

    // compose unsigned event
    let unsigned_event =
        EventBuilder::new_text_note(text, &[]).to_unsigned_event(signer_signer_pubkey);
    let msg_to_send = Message::request(Request::SignEvent(unsigned_event.clone()));
    let _ = send_message(relay_client, &msg_to_send, signer_app_pubkey).await?;
    let mut sd = state_dynamic.st.write().unwrap();
    sd.outstanding_sign_req_id = Some(msg_to_send.id());
    sd.outstanding_sign_unsigned_event = Some(unsigned_event);
    sd.count_sign_requests = sd.count_sign_requests + 1;

    // UI notification
    EVENT_QUEUE.push(Event::SignRequestSent)?;

    Ok(())
}

fn send_sign_blocking(
    relay_client: &Client,
    signer_app_pubkey: &XOnlyPublicKey,
    signer_signer_pubkey: XOnlyPublicKey,
    text: &str,
    state_dynamic: Arc<StateDynamic>,
) -> Result<(), Error> {
    let (tx, rx) = channel::bounded(1);
    let relay_client_clone = relay_client.clone();
    let signer_app_pubkey_clone = signer_app_pubkey.clone();
    let text_clone = text.to_owned();
    let handle = tokio::runtime::Handle::current();
    handle.spawn(async move {
        let _ = send_sign(
            &relay_client_clone,
            &signer_app_pubkey_clone,
            signer_signer_pubkey,
            &text_clone,
            state_dynamic,
        )
        .await;
        let _ = tx.send(1);
    });
    let _ = rx.recv()?;
    Ok(())
}

/// Handle a message/request received (from relay)
async fn handle_request_message(
    relay_client: &Client,
    msg: &Message,
    state_dynamic: Arc<StateDynamic>,
) -> Result<(), Error> {
    println!("DEBUG: New message received {}", message_method(msg));

    let signer_app_pubkey = state_dynamic.get_signer_app_pubkey().clone();

    if let Message::Request { .. } = &msg {
        if let Ok(Request::Connect(pubkey)) = msg.to_request() {
            println!("DEBUG: Got connect request, from pubkey {:?}", pubkey);

            let new_signer_app_pubkey = pubkey;
            {
                let mut st = state_dynamic.st.write().unwrap();
                st.signer_app_pubkey = Some(new_signer_app_pubkey);
                st.signer_signer_pubkey = None;
            }

            // UI notification
            EVENT_QUEUE.push(Event::SignerConnected)?;

            // Continue to obtain capabilities
            send_describe(relay_client, &new_signer_app_pubkey, state_dynamic).await?;
        }
    } else if let Message::Response { id, result, .. } = &msg {
        if &state_dynamic.get_outstanding_describe_req_id() == id {
            if let Some(value) = result {
                state_dynamic
                    .st
                    .write()
                    .unwrap()
                    .outstanding_describe_req_id = None;
                let values = serde_json::from_value::<Vec<String>>(value.to_owned())?;
                println!("DEBUG: Got Describe response, {:?}", values);

                // store result
                {
                    let mut st = state_dynamic.st.write().unwrap();
                    st.signer_capabilities = Some(values.join(","));
                }
                // UI notification
                EVENT_QUEUE.push(Event::SignerCapabsObtained)?;

                // Continue to obtain signer public key
                send_get_public_key(relay_client, &signer_app_pubkey.unwrap(), state_dynamic)
                    .await?;
            } else {
                println!("ERROR: ID mismatch");
            }
        } else if &state_dynamic.get_outstanding_get_pubkey_req_id() == id {
            if let Some(value) = result {
                state_dynamic
                    .st
                    .write()
                    .unwrap()
                    .outstanding_get_pubkey_req_id = None;
                let pubkey = serde_json::from_value::<XOnlyPublicKey>(value.to_owned())?;
                println!("DEBUG: Got PublicKey response, {:?}", pubkey);

                state_dynamic.st.write().unwrap().signer_signer_pubkey = Some(pubkey);

                // UI notification
                EVENT_QUEUE.push(Event::SignerPubkeyObtained)?;
            } else {
                println!("ERROR: ID mismatch");
            }
        } else if &state_dynamic.get_outstanding_get_sign_req_id() == id {
            if let Some(value) = result {
                state_dynamic.st.write().unwrap().outstanding_sign_req_id = None;
                let signature = serde_json::from_value::<nostr_sdk::secp256k1::schnorr::Signature>(
                    value.to_owned(),
                )?;
                println!("DEBUG: Got SignEvent response, {:?}", signature);

                let unsigned_event = state_dynamic
                    .st
                    .read()
                    .unwrap()
                    .outstanding_sign_unsigned_event
                    .as_ref()
                    .unwrap()
                    .clone();
                let event = unsigned_event.add_signature(signature)?;
                let id = relay_client.send_event(event).await?;
                println!("DEBUG: Published event, id {}", id);

                let mut sd = state_dynamic.st.write().unwrap();
                sd.count_posts = sd.count_posts + 1;

                // UI notification
                EVENT_QUEUE.push(Event::PostPublished)?;
            } else {
                println!("ERROR: ID mismatch");
            }
        }
    } else {
        println!("Not a Response, ignoring");
    }

    Ok(())
}

/// Listening loop
async fn wait_and_handle_messages(
    relay_client: &Client,
    state_dynamic: Arc<StateDynamic>,
) -> Result<(), Error> {
    let keys = relay_client.keys();

    relay_client
        .subscribe(vec![Filter::new()
            .pubkey(keys.public_key())
            .kind(Kind::NostrConnect)
            .since(Timestamp::now() - Duration::from_secs(10))])
        .await;
    println!("DEBUG: Subscribed to relay events ...");
    println!("DEBUG: Waiting for messages, first for a 'connect' from a signer ...");

    // UI notification
    EVENT_QUEUE.push(Event::RelayConnected)?;

    loop {
        let mut notifications = relay_client.notifications();
        while let Ok(notification) = notifications.recv().await {
            if let RelayPoolNotification::Event(_url, event) = notification {
                if event.kind == Kind::NostrConnect {
                    match decrypt(&keys.secret_key()?, &event.pubkey, &event.content) {
                        Ok(msg) => {
                            let msg = Message::from_json(msg)?;
                            let _ =
                                handle_request_message(&relay_client, &msg, state_dynamic.clone())
                                    .await?;
                        }
                        Err(e) => eprintln!("Impossible to decrypt NIP46 message: {e}"),
                    }
                }
            }
        }
    }
    // relay_client.unsubscribe().await;
}

/// Connect to relay and start listening for messages, handle them, async version
async fn connect_and_handle_async(
    state_static: Arc<StateStatic>,
    state_dynamic: Arc<StateDynamic>,
) -> Result<(), Error> {
    let relay_client = &state_static.relay_client;
    relay_client
        .add_relay(&state_static.relay_str, None)
        .await?;
    // Note: SDK does not give an error here
    relay_client.connect().await;

    // UI notification
    EVENT_QUEUE.push(Event::RelayConnected)?;

    let _ = wait_and_handle_messages(relay_client, state_dynamic).await?;

    Ok(())
}

/// Connect to relay and start listening for messages, handle them, just start it in background
fn connect_and_handle(
    state_static: Arc<StateStatic>,
    state_dynamic: Arc<StateDynamic>,
) -> Result<(), Error> {
    let handle = tokio::runtime::Handle::current();
    handle.spawn(async move { connect_and_handle_async(state_static, state_dynamic).await });
    // don't wait
    Ok(())
}

/// Get number of relays that are Connected / Connecting
async fn get_connected_count_async(relay_client: &Client) -> (u32, u32) {
    let relays = relay_client.relays().await;
    let (mut cnt_cncted, mut cnt_cncting) = (0, 0);
    for (_k, r) in relays {
        match r.status().await {
            RelayStatus::Connected => cnt_cncted = cnt_cncted + 1,
            RelayStatus::Connecting => cnt_cncting = cnt_cncting + 1,
            _ => (),
        }
    }
    (cnt_cncted, cnt_cncting)
}

/// Get number of relays that are Connected / Connecting, blocking version
fn get_connected_count(relay_client: &Client) -> Result<(u32, u32), Error> {
    let (tx, rx) = channel::bounded(1);
    let relay_client_clone = relay_client.clone();
    let handle = tokio::runtime::Handle::current();
    handle.spawn(async move {
        let count = get_connected_count_async(&relay_client_clone).await;
        let _ = tx.send(count);
    });
    Ok(rx.recv()?)
}

fn get_connection_status(relay_client: &Client) -> ConnectionStatus {
    let (connected, connecting) = match get_connected_count(relay_client) {
        Err(_) => return ConnectionStatus::NotConnected,
        Ok(tupl) => tupl,
    };
    if connected > 0 {
        ConnectionStatus::Connected
    } else if connecting > 0 {
        ConnectionStatus::Connecting
    } else {
        ConnectionStatus::NotConnected
    }
}

impl StateDynamicSingle {
    fn get_signer_pubkey(&self) -> String {
        match self.signer_signer_pubkey {
            None => "-".to_string(),
            Some(pk) => pk.to_bech32().unwrap(),
        }
    }
}

fn option_string_to_string(os: &Option<String>) -> String {
    match os {
        None => "-".to_string(),
        Some(s) => s.clone(),
    }
}

impl StateDynamic {
    fn init() -> Result<Self, Error> {
        Ok(Self {
            st: RwLock::new(StateDynamicSingle::default()),
        })
    }

    fn get_outstanding_describe_req_id(&self) -> String {
        option_string_to_string(&self.st.read().unwrap().outstanding_describe_req_id)
    }

    fn get_outstanding_get_pubkey_req_id(&self) -> String {
        option_string_to_string(&self.st.read().unwrap().outstanding_get_pubkey_req_id)
    }

    fn get_outstanding_get_sign_req_id(&self) -> String {
        option_string_to_string(&self.st.read().unwrap().outstanding_sign_req_id)
    }

    fn get_signer_app_pubkey(&self) -> Option<XOnlyPublicKey> {
        self.st.read().unwrap().signer_app_pubkey.clone()
    }

    fn get_signer_signer_pubkey(&self) -> Option<XOnlyPublicKey> {
        self.st.read().unwrap().signer_signer_pubkey.clone()
    }
}

impl EventQueue {
    fn new() -> Self {
        let (sender, receiver) = channel::bounded::<Event>(100);
        Self { sender, receiver }
    }

    pub fn push(&self, e: Event) -> Result<(), Error> {
        self.sender
            .send(e)
            .map_err(|_e| Error::InternalEventQueueSend)
    }

    pub fn pop(&self) -> Result<Event, Error> {
        let e = self.receiver.recv()?;
        Ok(e)
    }
}

#[derive(Clone, Debug)]
enum UiMessage {
    Event(Event),
    ChangedReadonly,
    SetPostText(String),
    SendSignRequest,
}

impl DemoApp {
    pub fn new() -> Result<Self, Error> {
        let app = Self {
            state: Arc::new(StateStatic::init()?),
            state_dynamic: Arc::new(StateDynamic::init()?),
            post_text: String::default(),
        };
        connect_and_handle(app.state.clone(), app.state_dynamic.clone())?;
        Ok(app)
    }

    fn send_sign_request(&self) -> Result<(), Error> {
        let text = self.post_text.clone();
        let signer_app_pubkey = match self.state_dynamic.get_signer_app_pubkey() {
            None => return Err(Error::NoSignerConnected),
            Some(k) => k,
        };
        let signer_signer_pubkey = match self.state_dynamic.get_signer_signer_pubkey() {
            None => return Err(Error::NoSignerConnected),
            Some(k) => k,
        };
        let _ = send_sign_blocking(
            &self.state.relay_client,
            &signer_app_pubkey,
            signer_signer_pubkey,
            &text,
            self.state_dynamic.clone(),
        )?;
        Ok(())
    }

    fn view_text_readonly(&self, label: &str, value: &str) -> Element<UiMessage> {
        let label_width = Length::Fixed(150.0);
        row![
            column![text(label).size(15)]
                .align_items(Alignment::Start)
                .width(label_width)
                .padding(0),
            text(&value).size(15),
        ]
        .spacing(10)
        .padding(0)
        .into()
    }
}

pub enum SubscriptionState {
    Uninited,
    Inited,
}

impl Application for DemoApp {
    type Message = UiMessage;
    type Theme = Theme;
    type Executor = executor::Default;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<UiMessage>) {
        match DemoApp::new() {
            Err(e) => panic!("Error {:?}", e),
            Ok(app) => (app, Command::none()),
        }
    }

    fn title(&self) -> String {
        String::from("Nostr Connect Demo Client")
    }

    fn subscription(&self) -> Subscription<UiMessage> {
        subscription::unfold(
            std::any::TypeId::of::<DemoApp>(),
            SubscriptionState::Uninited,
            move |state| async move {
                match state {
                    SubscriptionState::Uninited => (None, SubscriptionState::Inited),
                    SubscriptionState::Inited => match EVENT_QUEUE.pop() {
                        Err(e) => {
                            println!("DEBUG: Subscription: error {:?}", e);
                            (None, SubscriptionState::Inited)
                        }
                        Ok(event) => {
                            println!("DEBUG: Subscription: Got event {:?}", event);
                            (Some(UiMessage::Event(event)), SubscriptionState::Inited)
                        }
                    },
                }
            },
        )
    }

    fn update(&mut self, message: UiMessage) -> Command<UiMessage> {
        match message {
            UiMessage::ChangedReadonly => {}
            UiMessage::Event(_) => {
                // implicit UI refresh is enough here, no more action needed
            }
            UiMessage::SetPostText(s) => self.post_text = s,
            UiMessage::SendSignRequest => {
                let _ = self.send_sign_request();
            }
        }
        Command::none()
    }

    fn view(&self) -> Element<UiMessage> {
        let state = &*(self.state);
        let state_dynamic = &*self.state_dynamic.st.read().unwrap();
        let connection_status = get_connection_status(&state.relay_client);
        column![
            text("Nostr Connect Client").size(25),
            iced::widget::rule::Rule::horizontal(5),
            text(match connection_status {
                ConnectionStatus::NotConnected => "Not connected to relay!",
                ConnectionStatus::Connecting => "Connecting to relay...",
                ConnectionStatus::Connected => {
                    match state_dynamic.signer_signer_pubkey {
                        None => "Connect with a Signer using the nostrconnect URI below!",
                        Some(_) => "Enter text for a post below, and request Signning!",
                    }
                }
            })
            .size(20),
            iced::widget::rule::Rule::horizontal(5),
            text("Nostr Connect URI:  You need to copy this to the Signer").size(15),
            text_input(
                "Connect URI will be shown here",
                &state.nostr_connect_str,
                move |_| { UiMessage::ChangedReadonly }
            )
            .size(15),
            iced::widget::rule::Rule::horizontal(5),
            row![
                text("Post text:").size(15),
                text_input(
                    "Enter message text here",
                    &self.post_text,
                    UiMessage::SetPostText
                ),
            ]
            .spacing(10)
            .padding(0),
            button("Request Signing").on_press(UiMessage::SendSignRequest),
            iced::widget::rule::Rule::horizontal(5),
            self.view_text_readonly("Relay:", &state.relay_str),
            self.view_text_readonly("App URL:", SAMPLE_WEB_URL),
            self.view_text_readonly(
                "Relay connection status:",
                &format!("{:?}", connection_status)
            ),
            self.view_text_readonly("Signer signer pubkey:", &state_dynamic.get_signer_pubkey()),
            self.view_text_readonly(
                "Signer capabilities:",
                &state_dynamic
                    .signer_capabilities
                    .as_ref()
                    .unwrap_or(&"-".to_string())
            ),
            self.view_text_readonly(
                "Sign requests sent:",
                &state_dynamic.count_sign_requests.to_string()
            ),
            self.view_text_readonly("Posts published:", &state_dynamic.count_posts.to_string()),
            iced::widget::rule::Rule::horizontal(5),
        ]
        .align_items(Alignment::Fill)
        .spacing(5)
        .padding(20)
        .max_width(600)
        .into()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let _res = DemoApp::run(Settings::default());

    Ok(())
}
