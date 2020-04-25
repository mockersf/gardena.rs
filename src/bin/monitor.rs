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
    ($old: ident, $new:ident, $field:ident, $category:expr, $id: ident, $ts:ident, $changes:ident) => {
        if $old.$field != $new.$field {
            $changes.push(format!(
                "{},id={},{}={} {}_count=1 {}",
                $category,
                $id,
                stringify!($field),
                $new.$field,
                stringify!($field),
                $ts
            ));
        }
    };
}
macro_rules! diff_number {
    ($old: ident, $new:ident, $field:ident, $category:expr, $id:ident, $ts:ident, $changes:ident) => {
        if $old.$field != $new.$field {
            $changes.push(format!(
                "{},id={} {}={} {}",
                $category,
                $id,
                stringify!($field),
                $new.$field,
                $ts
            ));
        }
    };
}

#[derive(Debug)]
struct StateCommon {
    name: String,
    battery_level: u8,
    battery_state: String,
    rf_link_level: u8,
    rf_link_state: String,
}
impl StateCommon {
    fn init_changes(&self, id: String) -> Vec<String> {
        StateCommon {
            name: String::from("NEVER_HAPPENING"),
            battery_level: std::u8::MAX,
            battery_state: String::from("NEVER_HAPPENING"),
            rf_link_level: std::u8::MAX,
            rf_link_state: String::from("NEVER_HAPPENING"),
        }
        .diff_with(self, id)
    }

    fn diff_with(&self, new_state: &StateCommon, id: String) -> Vec<String> {
        let ts = ts_nano();
        let category = "common";
        let mut changes = vec![];

        diff_string!(self, new_state, name, category, id, ts, changes);
        diff_number!(self, new_state, battery_level, category, id, ts, changes);
        diff_string!(self, new_state, battery_state, category, id, ts, changes);
        diff_number!(self, new_state, rf_link_level, category, id, ts, changes);
        diff_string!(self, new_state, rf_link_state, category, id, ts, changes);

        changes
    }
}

#[derive(Debug)]
struct StateMower {
    state: String,
    activity: String,
    last_error_code: Option<String>,
    operating_hours: u16,
}
impl StateMower {
    fn init_changes(&self, id: String) -> Vec<String> {
        StateMower {
            state: String::from("NEVER_HAPPENING"),
            activity: String::from("NEVER_HAPPENING"),
            last_error_code: Some(String::from("NEVER_HAPPENING")),
            operating_hours: std::u16::MAX,
        }
        .diff_with(self, id)
    }
    fn diff_with(&self, new_state: &StateMower, id: String) -> Vec<String> {
        let ts = ts_nano();
        let category = "mower";
        let mut changes = vec![];

        diff_string!(self, new_state, state, category, id, ts, changes);
        diff_string!(self, new_state, activity, category, id, ts, changes);
        diff_number!(self, new_state, operating_hours, category, id, ts, changes);

        if self.last_error_code != new_state.last_error_code {
            changes.push(format!(
                "{},id={},last_error_code={} last_error_code_count=1 {}",
                category,
                id,
                new_state
                    .last_error_code
                    .clone()
                    .unwrap_or_else(|| String::from("NO_MESSAGE")),
                ts
            ));
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
    fn init_changes(&self, id: String) -> Vec<String> {
        match self {
            State::Common(state) => state.init_changes(id),
            State::Mower(state) => state.init_changes(id),
            State::Unused => vec![],
        }
    }
    fn diff_with(&self, new_state: &State, id: String) -> Vec<String> {
        match (self, new_state) {
            (State::Common(old), State::Common(new)) => old.diff_with(new, id),
            (State::Mower(old), State::Mower(new)) => old.diff_with(new, id),
            (State::Unused, State::Unused) => vec![],
            (_, _) => vec![],
        }
    }
}

fn gardena_object_to_state(object: &gardena_rs::Object) -> (String, State) {
    match object {
        gardena_rs::Object::Common { id, attributes, .. } => (
            format!("{}-COMMON", id),
            State::Common(StateCommon {
                name: attributes.name.value.clone(),
                battery_level: attributes.battery_level.value,
                battery_state: attributes.battery_state.value.clone(),
                rf_link_level: attributes.rf_link_level.value,
                rf_link_state: attributes.rf_link_state.value.clone(),
            }),
        ),
        gardena_rs::Object::Mower { id, attributes, .. } => (
            format!("{}-MOWER", id),
            State::Mower(StateMower {
                state: attributes.state.value.clone(),
                activity: attributes.activity.value.clone(),
                last_error_code: attributes.last_error_code.as_ref().map(|a| a.value.clone()),
                operating_hours: attributes.operating_hours.value,
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

async fn refresh_and_listen(
    gardena: &gardena_rs::Gardena,
    id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // renew token
    gardena.login().await?;
    let ws_info = gardena.get_websocket_url(&id).await?;
    if let gardena_rs::Object::Websocket { ref attributes, .. } = ws_info {
        gardena.get_location(id).await?.iter().for_each(|object| {
            let (id, state) = gardena_object_to_state(object);
            INFLUXDB_CHANGES
                .write()
                .unwrap()
                .append(&mut state.init_changes(id.clone()));
            STATE.write().unwrap().insert(id, state);
        });

        println!("opening socket");
        gardena_rs::tokio::connect_to_websocket(attributes.url.clone(), |msg| {
            let (id, new_state) = gardena_object_to_state(&msg);
            let state_read_lock = STATE.read().unwrap();
            let old_state = state_read_lock.get(&id);
            let mut changes = if let Some(old_state) = old_state {
                old_state.diff_with(&new_state, id.clone())
            } else {
                vec![]
            };
            // releasing read lock manually in case there are changes to write
            std::mem::drop(state_read_lock);

            if !changes.is_empty() {
                STATE.write().unwrap().insert(id, new_state);
                INFLUXDB_CHANGES.write().unwrap().append(&mut changes);
            }
        })
        .await?;
    }
    Ok(())
}
