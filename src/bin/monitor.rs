use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use clap::Clap;
use futures::future::{select, Either};
use hyper::{
    service::{make_service_fn, service_fn},
    Body, Request, Response, Server,
};
use lazy_static::lazy_static;
use serde::Deserialize;

static NEVER_HAPPENING: &str = "NEVER_HAPPENING";
static ONE_HOUR_FIFTEEN_MINUTES: u128 = 4_500_000_000_000;
static TWO_SECONDS: u128 = 2_000_000_000;
static ONE_SECOND: u128 = 1_000_000_000;

#[derive(Clap)]
#[clap(version = "1.0", author = "François")]
struct CliOpts {
    /// conf path
    #[clap(short = "c", long = "config", default_value = "gardena.conf")]
    config: String,
}

#[derive(Deserialize)]
struct Opts {
    username: String,
    password: String,
    application_key: String,
}

lazy_static! {
    static ref STATE: Arc<RwLock<HashMap<String, State>>> = Arc::new(RwLock::new(HashMap::new()));
    static ref INFLUXDB_CHANGES: Arc<RwLock<Vec<String>>> = Arc::new(RwLock::new(vec![]));
}

fn ts_nano() -> u128 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    (since_the_epoch.as_secs() as u128 * 1_000 + since_the_epoch.subsec_millis() as u128)
        * 1_000_000
}

async fn serve_req(_req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let mut changes = INFLUXDB_CHANGES.write().unwrap();
    let to_display = changes.join("\n");
    changes.clear();
    Ok(Response::new(Body::from(to_display)))
}

async fn run_server(addr: SocketAddr) {
    println!("Listening on http://{}", addr);

    let serve_future = Server::bind(&addr).serve(make_service_fn(|_| async {
        {
            Ok::<_, hyper::Error>(service_fn(serve_req))
        }
    }));

    if let Err(e) = serve_future.await {
        eprintln!("server error: {}", e);
    }
}

macro_rules! diff_string {
    ($old: ident, $new:ident, $field:ident, $category:expr, $id: ident, $changes:ident) => {
        if $old.$field.value != $new.$field.value {
            if $old.$field.value != NEVER_HAPPENING {
                $changes.push(format!(
                    "{},id={},{}={} {}_count=1 {}",
                    $category,
                    $id,
                    stringify!($field),
                    $old.$field.value,
                    stringify!($field),
                    $new.$field.ts - TWO_SECONDS
                ));
                $changes.push(format!(
                    "{},id={},{}={} {}_count=0 {}",
                    $category,
                    $id,
                    stringify!($field),
                    $old.$field.value,
                    stringify!($field),
                    $new.$field.ts - ONE_SECOND
                ));
            }
            $changes.push(format!(
                "{},id={},{}={} {}_count=1 {}",
                $category,
                $id,
                stringify!($field),
                $new.$field.value,
                stringify!($field),
                $new.$field.ts
            ));
        } else if $old.$field.ts + ONE_HOUR_FIFTEEN_MINUTES > $new.$field.ts {
            $changes.push(format!(
                "{},id={},{}={} {}_count=1 {}",
                $category,
                $id,
                stringify!($field),
                $new.$field.value,
                stringify!($field),
                $new.$field.ts
            ));
        } else {
            $new.$field.ts = $old.$field.ts;
        }
    };
}
macro_rules! diff_number {
    ($old: ident, $new:ident, $field:ident, $category:expr, $id:ident, $changes:ident) => {
        if $old.$field.value != $new.$field.value {
            $changes.push(format!(
                "{},id={} {}={} {}",
                $category,
                $id,
                stringify!($field),
                $new.$field.value,
                $new.$field.ts
            ));
        } else if $old.$field.ts + ONE_HOUR_FIFTEEN_MINUTES > $new.$field.ts {
            $changes.push(format!(
                "{},id={} {}={} {}",
                $category,
                $id,
                stringify!($field),
                $new.$field.value,
                $new.$field.ts
            ));
        } else {
            $new.$field.ts = $old.$field.ts;
        }
    };
}

#[derive(Debug, Clone)]
struct TsValue<T> {
    value: T,
    ts: u128,
}

#[derive(Debug)]
struct StateCommon {
    battery_level: TsValue<u8>,
    battery_state: TsValue<String>,
    rf_link_level: TsValue<u8>,
    rf_link_state: TsValue<String>,
}
impl StateCommon {
    fn init_changes(&mut self, id: String) -> Vec<String> {
        StateCommon {
            battery_level: TsValue {
                value: std::u8::MAX,
                ts: 0,
            },
            battery_state: TsValue {
                value: String::from(NEVER_HAPPENING),
                ts: 0,
            },
            rf_link_level: TsValue {
                value: std::u8::MAX,
                ts: 0,
            },
            rf_link_state: TsValue {
                value: String::from(NEVER_HAPPENING),
                ts: 0,
            },
        }
        .diff_with(self, id)
    }

    fn diff_with(&self, new_state: &mut StateCommon, id: String) -> Vec<String> {
        let category = "common";
        let mut changes = vec![];

        diff_number!(self, new_state, battery_level, category, id, changes);
        diff_string!(self, new_state, battery_state, category, id, changes);
        diff_number!(self, new_state, rf_link_level, category, id, changes);
        diff_string!(self, new_state, rf_link_state, category, id, changes);

        changes
    }
}

#[derive(Debug)]
struct StateMower {
    state: TsValue<String>,
    activity: TsValue<String>,
    last_error_code: TsValue<Option<String>>,
    operating_hours: TsValue<u16>,
}
impl StateMower {
    fn init_changes(&mut self, id: String) -> Vec<String> {
        StateMower {
            state: TsValue {
                value: String::from(NEVER_HAPPENING),
                ts: 0,
            },
            activity: TsValue {
                value: String::from(NEVER_HAPPENING),
                ts: 0,
            },
            last_error_code: TsValue {
                value: Some(String::from(NEVER_HAPPENING)),
                ts: 0,
            },
            operating_hours: TsValue {
                value: std::u16::MAX,
                ts: 0,
            },
        }
        .diff_with(self, id)
    }
    fn diff_with(&self, new_state: &mut StateMower, id: String) -> Vec<String> {
        let category = "mower";
        let mut changes = vec![];

        diff_string!(self, new_state, state, category, id, changes);
        diff_string!(self, new_state, activity, category, id, changes);
        diff_number!(self, new_state, operating_hours, category, id, changes);

        if self.last_error_code.value != new_state.last_error_code.value {
            let old_last_error_code = self
                .last_error_code
                .value
                .clone()
                .unwrap_or_else(|| String::from("NO_MESSAGE"));
            if old_last_error_code != NEVER_HAPPENING {
                changes.push(format!(
                    "{},id={},last_error_code={} last_error_code_count=1 {}",
                    category,
                    id,
                    old_last_error_code,
                    new_state.last_error_code.ts - TWO_SECONDS
                ));
                changes.push(format!(
                    "{},id={},last_error_code={} last_error_code_count=0 {}",
                    category,
                    id,
                    old_last_error_code,
                    new_state.last_error_code.ts - ONE_SECOND
                ));
            }
            changes.push(format!(
                "{},id={},last_error_code={} last_error_code_count=1 {}",
                category,
                id,
                new_state
                    .last_error_code
                    .value
                    .clone()
                    .unwrap_or_else(|| String::from("NO_MESSAGE")),
                new_state.last_error_code.ts
            ));
        } else if self.last_error_code.ts + ONE_HOUR_FIFTEEN_MINUTES > new_state.last_error_code.ts
        {
            changes.push(format!(
                "{},id={},last_error_code={} last_error_code_count=1 {}",
                category,
                id,
                new_state
                    .last_error_code
                    .value
                    .clone()
                    .unwrap_or_else(|| String::from("NO_MESSAGE")),
                new_state.last_error_code.ts
            ));
        } else {
            new_state.last_error_code.ts = self.last_error_code.ts;
        }

        changes
    }
}

#[derive(Debug)]
enum State {
    Common(StateCommon),
    Mower(StateMower),
    Unused,
}
impl State {
    fn init_changes(&mut self, id: String) -> Vec<String> {
        match self {
            State::Common(state) => state.init_changes(id),
            State::Mower(state) => state.init_changes(id),
            State::Unused => vec![],
        }
    }
    fn diff_with(&self, new_state: &mut State, id: String) -> Vec<String> {
        match (self, new_state) {
            (State::Common(old), State::Common(new)) => old.diff_with(new, id),
            (State::Mower(old), State::Mower(new)) => old.diff_with(new, id),
            (State::Unused, State::Unused) => vec![],
            (_, _) => vec![],
        }
    }
}

fn gardena_object_to_state(object: &gardena_rs::Object) -> (String, State) {
    let ts = ts_nano();
    match object {
        gardena_rs::Object::Common { id, attributes, .. } => (
            format!("{}-COMMON", id),
            State::Common(StateCommon {
                battery_level: TsValue {
                    value: attributes.battery_level.value,
                    ts,
                },
                battery_state: TsValue {
                    value: attributes.battery_state.value.clone(),
                    ts,
                },
                rf_link_level: TsValue {
                    value: attributes.rf_link_level.value,
                    ts,
                },
                rf_link_state: TsValue {
                    value: attributes.rf_link_state.value.clone(),
                    ts,
                },
            }),
        ),
        gardena_rs::Object::Mower { id, attributes, .. } => (
            format!("{}-MOWER", id),
            State::Mower(StateMower {
                state: TsValue {
                    value: attributes.state.value.clone(),
                    ts,
                },
                activity: TsValue {
                    value: attributes.activity.value.clone(),
                    ts,
                },
                last_error_code: TsValue {
                    value: attributes.last_error_code.as_ref().map(|a| a.value.clone()),
                    ts,
                },
                operating_hours: TsValue {
                    value: attributes.operating_hours.value,
                    ts,
                },
            }),
        ),
        gardena_rs::Object::Device { .. }
        | gardena_rs::Object::Location { .. }
        | gardena_rs::Object::Websocket { .. }
        | gardena_rs::Object::PowerSocket { .. }
        | gardena_rs::Object::Valve { .. }
        | gardena_rs::Object::ValveSet { .. }
        | gardena_rs::Object::Sensor { .. } => (String::from("unused"), State::Unused),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli_opts: CliOpts = CliOpts::parse();

    let opts: Opts = hocon::HoconLoader::new()
        .load_file(&cli_opts.config)
        .and_then(|hc| hc.resolve())
        .unwrap();

    let gardena = gardena_rs::Gardena::new(opts.username, opts.password, opts.application_key);
    let locations = gardena.list_locations().await?;

    if let gardena_rs::Object::Location { ref id, .. } = locations[0] {
        let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
        let server = run_server(addr);
        futures::pin_mut!(server);
        let mut server = server;
        loop {
            let ws_client = refresh_and_listen(&gardena, id);
            futures::pin_mut!(ws_client);
            match select(ws_client, server).await {
                Either::Left((_, b)) => {
                    server = b;
                }
                Either::Right(_) => break,
            }
        }
    }

    Ok(())
}

fn update_state_and_changes(object: &gardena_rs::Object) {
    let (id, mut new_state) = gardena_object_to_state(object);
    let state_read_lock = STATE.read().unwrap();
    let old_state = state_read_lock.get(&id);
    let mut changes = if let Some(old_state) = old_state {
        old_state.diff_with(&mut new_state, id.clone())
    } else {
        new_state.init_changes(id.clone())
    };
    // releasing read lock manually in case there are changes to write
    std::mem::drop(state_read_lock);

    if !changes.is_empty() {
        STATE.write().unwrap().insert(id, new_state);
        INFLUXDB_CHANGES.write().unwrap().append(&mut changes);
    }
}

async fn refresh_and_listen(
    gardena: &gardena_rs::Gardena,
    id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // renew token
    gardena.login().await?;
    let ws_info = gardena.get_websocket_url(&id).await?;
    if let gardena_rs::Object::Websocket { ref attributes, .. } = ws_info {
        gardena.get_location(id).await?.iter().for_each(|object| {
            update_state_and_changes(object);
        });

        println!("opening socket");
        gardena_rs::tokio::connect_to_websocket(attributes.url.clone(), |msg| {
            update_state_and_changes(&msg);
        })
        .await?;
    }
    Ok(())
}
