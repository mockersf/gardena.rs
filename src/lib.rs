//! Bindings for the Gardena API
//!
//! # Note on enums
//!
//! All enums also have an `Other(String)` variant, as the possible values are not listed in the documentation. This
//! variant will be used when the API reports a value that I did not encounter. You are welcome to report those values
//! so that they can be added.
//!
//! For devices that I don't own, those kind of fields reported by the API are left as `String`
//!

#![deny(
    warnings,
    missing_debug_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces,
    unused_qualifications,
    missing_docs
)]

use std::cell::RefCell;
use std::fmt;
use std::str::FromStr;

use log::debug;
use rand::{thread_rng, Rng};
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};

static AUTH_URL: &str = "https://api.authentication.husqvarnagroup.dev/v1/oauth2/token";

static API_BASE_URL: &str = "https://api.smart.gardena.dev/v1";

#[derive(Deserialize, Debug)]
struct TokenInfo {
    access_token: String,
    scope: String,
    expires_in: u16,
    refresh_token: String,
    provider: String,
    user_id: String,
    token_type: String,
}

/// Wrapper type of a response
#[derive(Deserialize, Debug)]
pub struct Response<T> {
    /// Data of the response
    pub data: T,
    /// List of objects that are included
    #[serde(default)]
    pub included: Vec<Object>,
}

/// Link to another gardena object, by it's ID and type
#[derive(Deserialize, Debug)]
pub struct ObjectLink {
    /// ID of the object linked to
    pub id: String,
    /// Type of the object linked to
    #[serde(rename = "type")]
    pub ty: String,
}

/// A list of devices
#[derive(Deserialize, Debug)]
pub struct DeviceList {
    /// The list of devices, as links
    pub devices: Response<Vec<ObjectLink>>,
}

/// Relations of a device
#[derive(Deserialize, Debug)]
pub struct DeviceRelationShips {
    /// It's location
    pub location: Response<ObjectLink>,
    /// The objects that compose it
    pub services: Response<Vec<ObjectLink>>,
}

/// Wrapper type for an attribute that has a timestamp
#[derive(Deserialize, Debug)]
pub struct Attribute<T> {
    /// Value of the attribute
    pub value: T,
    /// Timestamp for this value
    pub timestamp: Option<String>,
}

/// Relationship to a single device
#[derive(Deserialize, Debug)]
pub struct DeviceRelationShip {
    /// Link to a device
    pub device: Response<ObjectLink>,
}

/// State of a mower
#[derive(Debug, PartialEq, Clone, enum_utils::IterVariants, enum_utils::FromStr)]
#[enumeration(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MowerState {
    /// In error (errors like [`MowerErrorCode::Lifted`](enum.MowerErrorCode.html#variant.Lifted))
    Error,
    /// Ok
    Ok,
    /// Warning (errors like [`MowerErrorCode::ParkedDailyLimitReached`](enum.MowerErrorCode.html#variant.ParkedDailyLimitReached))
    Warning,
    /// Other values (see note on Enums)
    #[enumeration(skip)]
    Other(String),
}
impl MowerState {
    /// Get an iterator on all variants of this enum
    pub fn to_iter() -> impl Iterator<Item = Self> + Clone {
        Self::iter()
    }
}
impl std::fmt::Display for MowerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MowerState::Error => write!(f, "ERROR"),
            MowerState::Ok => write!(f, "OK"),
            MowerState::Warning => write!(f, "WARNING"),
            MowerState::Other(value) => {
                debug!("unknown value for MowerState encountered: {}", value);
                write!(f, "{}", value)
            }
        }
    }
}
struct MowerStateVisitor;
impl<'de> Visitor<'de> for MowerStateVisitor {
    type Value = MowerState;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string")
    }
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(match MowerState::from_str(value) {
            Ok(v) => v,
            _ => MowerState::Other(String::from(value)),
        })
    }
}
impl<'de> Deserialize<'de> for MowerState {
    fn deserialize<D>(deserializer: D) -> Result<MowerState, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(MowerStateVisitor)
    }
}

/// What the mower is doing
#[derive(Debug, PartialEq, Clone, enum_utils::IterVariants, enum_utils::FromStr)]
#[enumeration(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MowerActivity {
    /// Nothing, probably with an error
    None,
    /// Charging
    OkCharging,
    /// Cutting according to schedule
    OkCutting,
    /// Cutting on user override
    OkCuttingTimerOverridden,
    /// Leaving the base
    OkLeaving,
    /// Searching for the base
    OkSearching,
    /// Park on user overridee
    ParkedParkSelected,
    /// Park according to schedule
    ParkedTimer,
    /// Paused
    Paused,
    /// Other values (see note on Enums)
    #[enumeration(skip)]
    Other(String),
}
impl MowerActivity {
    /// Get an iterator on all variants of this enum
    pub fn to_iter() -> impl Iterator<Item = Self> + Clone {
        Self::iter()
    }
}
impl std::fmt::Display for MowerActivity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MowerActivity::None => write!(f, "NONE"),
            MowerActivity::OkCharging => write!(f, "OK_CHARGING"),
            MowerActivity::OkCutting => write!(f, "OK_CUTTING"),
            MowerActivity::OkCuttingTimerOverridden => write!(f, "OK_CUTTING_TIMER_OVERRIDDEN"),
            MowerActivity::OkLeaving => write!(f, "OK_LEAVING"),
            MowerActivity::OkSearching => write!(f, "OK_SEARCHING"),
            MowerActivity::ParkedParkSelected => write!(f, "PARKED_PARK_SELECTED"),
            MowerActivity::ParkedTimer => write!(f, "PARKED_TIMER"),
            MowerActivity::Paused => write!(f, "PAUSED"),
            MowerActivity::Other(value) => {
                debug!("unknown value for MowerActivity encountered: {}", value);
                write!(f, "{}", value)
            }
        }
    }
}
struct MowerActivityVisitor;
impl<'de> Visitor<'de> for MowerActivityVisitor {
    type Value = MowerActivity;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string")
    }
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(match MowerActivity::from_str(value) {
            Ok(v) => v,
            _ => MowerActivity::Other(String::from(value)),
        })
    }
}
impl<'de> Deserialize<'de> for MowerActivity {
    fn deserialize<D>(deserializer: D) -> Result<MowerActivity, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(MowerActivityVisitor)
    }
}

/// Error code for a mower
#[derive(Debug, PartialEq, Clone, enum_utils::IterVariants, enum_utils::FromStr)]
#[enumeration(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MowerErrorCode {
    /// Couldn't reach base as path is blocked
    ChargingStationBlocked,
    /// Issue with front collision sensor
    CollisionSensorProblemFront,
    /// Mower has been lifted
    Lifted,
    /// Issue with loop wire
    NoLoopSignal,
    /// Hatch is open
    OffHatchOpen,
    /// Outside of it's working area
    OutsideWorkingArea,
    /// Reached it's daily limit
    ParkedDailyLimitReached,
    /// Other values (see note on Enums)
    #[enumeration(skip)]
    Other(String),
}
impl MowerErrorCode {
    /// Get an iterator on all variants of this enum
    pub fn to_iter() -> impl Iterator<Item = Self> + Clone {
        Self::iter()
    }
}
impl std::fmt::Display for MowerErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MowerErrorCode::ChargingStationBlocked => write!(f, "CHARGING_STATION_BLOCKED"),
            MowerErrorCode::CollisionSensorProblemFront => {
                write!(f, "COLLISION_SENSOR_PROBLEM_FRONT")
            }
            MowerErrorCode::Lifted => write!(f, "LIFTED"),
            MowerErrorCode::NoLoopSignal => write!(f, "NO_LOOP_SIGNAL"),
            MowerErrorCode::OffHatchOpen => write!(f, "OFF_HATCH_OPEN"),
            MowerErrorCode::OutsideWorkingArea => write!(f, "OUTSIDE_WORKING_AREA"),
            MowerErrorCode::ParkedDailyLimitReached => write!(f, "PARKED_DAILY_LIMIT_REACHED"),
            MowerErrorCode::Other(value) => {
                debug!("unknown value for MowerErrorCode encountered: {}", value);
                write!(f, "{}", value)
            }
        }
    }
}
struct MowerErrorCodeVisitor;
impl<'de> Visitor<'de> for MowerErrorCodeVisitor {
    type Value = MowerErrorCode;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string")
    }
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(match MowerErrorCode::from_str(value) {
            Ok(v) => v,
            _ => MowerErrorCode::Other(String::from(value)),
        })
    }
}
impl<'de> Deserialize<'de> for MowerErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<MowerErrorCode, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(MowerErrorCodeVisitor)
    }
}

/// Attributes of a mower
#[derive(Deserialize, Debug)]
pub struct MowerAttributes {
    /// It's state
    pub state: Attribute<MowerState>,
    /// What it is doing
    pub activity: Attribute<MowerActivity>,
    #[serde(rename = "lastErrorCode")]
    /// Current error code, if there is one
    pub last_error_code: Option<Attribute<MowerErrorCode>>,
    #[serde(rename = "operatingHours")]
    /// Number of hours it's been operating
    pub operating_hours: Attribute<u16>,
}

/// Attributes of a power socket
#[derive(Deserialize, Debug)]
pub struct PowerSocketAttributes {
    /// It's state
    pub state: Attribute<String>,
    /// What it is doing
    pub activity: Attribute<String>,
    /// Current error code, if there is one
    #[serde(rename = "lastErrorCode")]
    pub last_error_code: Option<Attribute<String>>,
    /// For how long
    pub duration: Attribute<u16>,
}

/// Attributes of a valve
#[derive(Deserialize, Debug)]
pub struct ValveAttributes {
    /// It's name
    pub name: Attribute<String>,
    /// It's state
    pub state: Attribute<String>,
    /// What it is doing
    pub activity: Attribute<String>,
    /// Current error code, if there is one
    #[serde(rename = "lastErrorCode")]
    pub last_error_code: Option<Attribute<String>>,
    /// For how long
    pub duration: Attribute<u16>,
}

/// Attributes of a valve set
#[derive(Deserialize, Debug)]
pub struct ValveSetAttributes {
    /// It's state
    pub state: Attribute<String>,
    /// Current error code, if there is one
    #[serde(rename = "lastErrorCode")]
    pub last_error_code: Option<Attribute<String>>,
}

/// Attributes of a sensor
#[derive(Deserialize, Debug)]
pub struct SensorAttributes {
    /// Soil humidity
    #[serde(rename = "soilHumidity")]
    pub soil_humidity: Attribute<f32>,
    /// Soil temperature
    #[serde(rename = "soilTemperature")]
    pub soil_temperature: Attribute<f32>,
    /// Ambient temperature
    #[serde(rename = "ambientTemperature")]
    pub ambient_temperature: Attribute<f32>,
    /// Light intensity
    #[serde(rename = "lightIntensity")]
    pub light_intensity: Attribute<f32>,
}

/// State of the battery of an object
#[derive(Debug, PartialEq, Clone, enum_utils::IterVariants, enum_utils::FromStr)]
#[enumeration(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CommonBatteryState {
    /// Charging
    Charging,
    /// Full
    Ok,
    /// Other values (see note on Enums)
    #[enumeration(skip)]
    Other(String),
}
impl CommonBatteryState {
    /// Get an iterator on all variants of this enum
    pub fn to_iter() -> impl Iterator<Item = Self> + Clone {
        Self::iter()
    }
}
impl std::fmt::Display for CommonBatteryState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommonBatteryState::Charging => write!(f, "CHARGING"),
            CommonBatteryState::Ok => write!(f, "OK"),
            CommonBatteryState::Other(value) => {
                debug!(
                    "unknown value for CommonBatteryState encountered: {}",
                    value
                );
                write!(f, "{}", value)
            }
        }
    }
}
struct CommonBatteryStateVisitor;
impl<'de> Visitor<'de> for CommonBatteryStateVisitor {
    type Value = CommonBatteryState;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string")
    }
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(match CommonBatteryState::from_str(value) {
            Ok(v) => v,
            _ => CommonBatteryState::Other(String::from(value)),
        })
    }
}
impl<'de> Deserialize<'de> for CommonBatteryState {
    fn deserialize<D>(deserializer: D) -> Result<CommonBatteryState, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(CommonBatteryStateVisitor)
    }
}

/// State of the connection to the Smart Gateway
#[derive(Debug, PartialEq, Clone, enum_utils::IterVariants, enum_utils::FromStr)]
#[enumeration(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CommonRfLinkState {
    /// Online
    Online,
    /// Other values (see note on Enums)
    #[enumeration(skip)]
    Other(String),
}
impl CommonRfLinkState {
    /// Get an iterator on all variants of this enum
    pub fn to_iter() -> impl Iterator<Item = Self> + Clone {
        Self::iter()
    }
}
impl std::fmt::Display for CommonRfLinkState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommonRfLinkState::Online => write!(f, "ONLINE"),
            CommonRfLinkState::Other(value) => {
                debug!("unknown value for CommonRfLinkState encountered: {}", value);
                write!(f, "{}", value)
            }
        }
    }
}
struct CommonRfLinkStateVisitor;
impl<'de> Visitor<'de> for CommonRfLinkStateVisitor {
    type Value = CommonRfLinkState;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string")
    }
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(match CommonRfLinkState::from_str(value) {
            Ok(v) => v,
            _ => CommonRfLinkState::Other(String::from(value)),
        })
    }
}
impl<'de> Deserialize<'de> for CommonRfLinkState {
    fn deserialize<D>(deserializer: D) -> Result<CommonRfLinkState, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(CommonRfLinkStateVisitor)
    }
}

/// Common attribute to all devices
#[derive(Deserialize, Debug)]
pub struct CommonAttributes {
    /// It's name
    pub name: Attribute<String>,
    #[serde(rename = "batteryLevel")]
    /// It's battery level
    pub battery_level: Attribute<u8>,
    /// It's battery state
    #[serde(rename = "batteryState")]
    pub battery_state: Attribute<CommonBatteryState>,
    /// It's rf link level to the Smart Gateway
    #[serde(rename = "rfLinkLevel")]
    pub rf_link_level: Attribute<u8>,
    /// It's rf link state to the Smart Gateway
    #[serde(rename = "rfLinkState")]
    pub rf_link_state: Attribute<CommonRfLinkState>,
    /// It's serial number
    pub serial: Attribute<String>,
    #[serde(rename = "modelType")]
    /// It's model type
    pub model_type: Attribute<String>,
}

/// A websocket request attributes
#[derive(Deserialize, Debug)]
pub struct WebsocketAttributes {
    /// How long is the url valid
    pub validity: u16,
    /// URL to connect to thee websocket
    pub url: String,
}

/// Attributes of a location
#[derive(Deserialize, Debug)]
pub struct LocationAttributes {
    /// It's name
    name: String,
}

/// Object that can be manipulated through the API
#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Object {
    /// A location
    #[serde(rename = "LOCATION")]
    Location {
        /// It's ID
        id: String,
        /// It's attributes
        attributes: LocationAttributes,
        /// It's relationship to other devices
        relationships: Option<DeviceList>,
    },
    /// A websocket connection
    #[serde(rename = "WEBSOCKET")]
    Websocket {
        /// It's ID
        id: String,
        /// It's attributes
        attributes: WebsocketAttributes,
    },
    /// A general device. This type is used to list all objects available on a device
    #[serde(rename = "DEVICE")]
    Device {
        /// It's ID
        id: String,
        /// It's relationship to other objects
        relationships: Option<DeviceRelationShips>,
    },
    /// The common attributes of most objects
    #[serde(rename = "COMMON")]
    Common {
        /// It's ID
        id: String,
        /// The device it's related to
        relationships: Option<DeviceRelationShip>,
        /// Common attributes of most objects
        attributes: CommonAttributes,
    },
    /// Mower specific attributes
    #[serde(rename = "MOWER")]
    Mower {
        /// It's ID
        id: String,
        /// The device it's related to
        relationships: Option<DeviceRelationShip>,
        /// Mower specific attributes
        attributes: MowerAttributes,
    },
    /// Power socket specific attributes
    #[serde(rename = "POWER_SOCKET")]
    PowerSocket {
        /// It's ID
        id: String,
        /// The device it's related to
        relationships: Option<DeviceRelationShip>,
        /// Power socket specific attributes
        attributes: PowerSocketAttributes,
    },
    /// Valve specific attributes
    #[serde(rename = "VALVE")]
    Valve {
        /// It's ID
        id: String,
        /// The device it's related to
        relationships: Option<DeviceRelationShip>,
        /// Valve specific attributes
        attributes: ValveAttributes,
    },
    /// Valve set specific attributes
    #[serde(rename = "VALVE_SET")]
    ValveSet {
        /// It's ID
        id: String,
        /// The device it's related to
        relationships: Option<DeviceRelationShip>,
        /// Valve set specific attributes
        attributes: ValveSetAttributes,
    },
    /// Sensor specific attributes
    #[serde(rename = "SENSOR")]
    Sensor {
        /// It's ID
        id: String,
        /// The device it's related to
        relationships: Option<DeviceRelationShip>,
        /// Sensor specific attributes
        attributes: SensorAttributes,
    },
}

#[derive(Serialize, Debug)]
struct LocationIdRequested {
    #[serde(rename = "locationId")]
    location_id: String,
}

#[derive(Serialize, Debug)]
struct WebsocketRequest {
    id: String,
    #[serde(rename = "type")]
    ty: String,
    attributes: LocationIdRequested,
}

#[derive(Serialize, Debug)]
struct Request<T> {
    data: T,
}

/// Gardena API Client
#[derive(Debug)]
pub struct Gardena {
    client: reqwest::Client,
    username: String,
    password: String,
    application_key: String,
    token_info: RefCell<Option<TokenInfo>>,
}

impl Gardena {
    /// Create a new Gardena API client
    pub fn new(username: String, password: String, application_key: String) -> Gardena {
        Gardena {
            client: reqwest::Client::new(),
            username,
            password,
            application_key,
            token_info: RefCell::new(None),
        }
    }

    /// login to the API, getting a new token
    pub async fn login(&self) -> Result<(), Box<dyn std::error::Error>> {
        let token_info = self
            .client
            .post(AUTH_URL)
            .form(&[
                ("grant_type", "password"),
                ("username", &self.username),
                ("password", &self.password),
                ("client_id", &self.application_key),
            ])
            .send()
            .await?
            .json::<TokenInfo>()
            .await?;

        self.token_info.replace(Some(token_info));

        Ok(())
    }

    async fn add_headers(
        &self,
        request_builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, Box<dyn std::error::Error>> {
        let request_builder = request_builder.header("X-Api-Key", self.application_key.clone());
        if self.token_info.borrow().is_none() {
            self.login().await?;
        }

        let token_info = self.token_info.borrow();

        let request_builder = request_builder.header(
            "Authorization-Provider",
            token_info.as_ref().unwrap().provider.clone(),
        );

        let request_builder = request_builder.header(
            "Authorization",
            format!(
                "{} {}",
                token_info.as_ref().unwrap().token_type.clone(),
                token_info.as_ref().unwrap().access_token.clone()
            ),
        );

        Ok(request_builder)
    }

    /// List the locations linked to the Gardena account.
    pub async fn list_locations(&self) -> Result<Vec<Object>, Box<dyn std::error::Error>> {
        Ok(self
            .add_headers(self.client.get(&format!("{}/locations", API_BASE_URL)))
            .await?
            .send()
            .await?
            .json::<Response<Vec<Object>>>()
            .await?
            .data)
    }

    /// Get details from a location, to list all its objects
    pub async fn get_location(
        &self,
        location_id: &str,
    ) -> Result<Vec<Object>, Box<dyn std::error::Error>> {
        Ok(self
            .add_headers(
                self.client
                    .get(&format!("{}/locations/{}", API_BASE_URL, location_id)),
            )
            .await?
            .send()
            .await?
            .json::<Response<Object>>()
            .await?
            .included)
    }

    /// Get the websocket URL to get updates from a location
    pub async fn get_websocket_url(
        &self,
        location_id: &str,
    ) -> Result<Object, Box<dyn std::error::Error>> {
        let mut request = self
            .add_headers(self.client.post(&format!("{}/websocket", API_BASE_URL)))
            .await?
            .json(&Request {
                data: WebsocketRequest {
                    id: thread_rng()
                        .sample_iter(&rand::distributions::Alphanumeric)
                        .take(15)
                        .collect(),
                    ty: String::from("WEBSOCKET"),
                    attributes: LocationIdRequested {
                        location_id: String::from(location_id),
                    },
                },
            })
            .build()?;
        let headers = request.headers_mut();
        headers.insert(
            "Content-Type",
            reqwest::header::HeaderValue::from_static("application/vnd.api+json"),
        );
        Ok(self
            .client
            .execute(request)
            .await?
            .json::<Response<Object>>()
            .await?
            .data)
    }
}

/// websocket management using async std runtime
#[cfg(feature = "websocket-asyncstd")]
pub mod asyncstd {
    use futures::{future::Either, prelude::*};
    use log::warn;

    /// Connect and manage the websocket using asyncstd runtime.
    ///
    /// The websocket is closed by Gardena every 60-ish minutes as it's token expires and the url needs to be renewed
    /// using the get_websocket_url method
    pub async fn connect_to_websocket<F>(
        url: String,
        act: F,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        F: Fn(super::Object) -> (),
    {
        let (ws_stream, _) = async_tungstenite::async_std::connect_async(url).await?;

        let should_break = std::sync::Mutex::new(false);

        let (mut write, read) = ws_stream.split();
        let act_on_messages = {
            read.for_each(|message| async {
                if let Ok(data) = message {
                    let data = data.into_data();
                    if let Ok(msg) = serde_json::from_slice::<super::Object>(&data) {
                        act(msg);
                    } else {
                        warn!("error parsing data from socket");
                        warn!("{:?}", std::str::from_utf8(&data).unwrap());
                        *should_break.lock().unwrap() = true;
                    }
                } else {
                    warn!("error reading data from socket");
                    *should_break.lock().unwrap() = true;
                }
            })
        };

        futures::pin_mut!(act_on_messages);

        // force websocket to die after 70 minutes as it should only last 60 minutes anyway
        let force_kill = async_std::task::sleep(core::time::Duration::from_secs(4_200));
        futures::pin_mut!(force_kill);
        let mut ws_or_scheduled_death = futures::future::select(
            // futures::future::poll_fn(|cx| force_kill.poll_tick(cx)),
            force_kill,
            act_on_messages,
        );
        loop {
            // send ping message every 120 secondes
            let ping_interval = async_std::task::sleep(core::time::Duration::from_secs(120));
            futures::pin_mut!(ping_interval);

            let first_done = futures::future::select(
                // futures::future::poll_fn(|cx| ping_interval.poll_tick(cx)),
                ping_interval,
                ws_or_scheduled_death,
            )
            .await;
            match first_done {
                // ping future is first, refresh web socket listener future
                Either::Left((_, b)) => {
                    ws_or_scheduled_death = b;
                }
                // web socket listener future ended, exit
                Either::Right((_, _)) => break,
            }

            // break as websocket received an unknown message
            if *should_break.lock().unwrap() {
                break;
            }

            // ping future was the first future to end, send ping
            write
                .send(async_tungstenite::tungstenite::Message::text("Ping"))
                .await?;
        }

        Ok(())
    }
}

/// websocket management using tokio runtime
#[cfg(feature = "websocket-tokio")]
pub mod tokio {
    use futures::{future::Either, prelude::*};
    use log::warn;

    /// Connect and manage the websocket using tokio runtime.
    ///
    /// The websocket is closed by Gardena every 60-ish minutes as it's token expires and the url needs to be renewed
    /// using the get_websocket_url method
    pub async fn connect_to_websocket<F>(
        url: String,
        act: F,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        F: Fn(super::Object) -> (),
    {
        let (ws_stream, _) = async_tungstenite::tokio::connect_async(url).await?;

        let should_break = std::sync::Mutex::new(false);

        let (mut write, read) = ws_stream.split();
        let act_on_messages = {
            read.for_each(|message| async {
                if let Ok(data) = message {
                    let data = data.into_data();
                    if let Ok(msg) = serde_json::from_slice::<super::Object>(&data) {
                        act(msg);
                    } else {
                        warn!("error parsing data from socket");
                        warn!("{:?}", std::str::from_utf8(&data).unwrap());
                        *should_break.lock().unwrap() = true;
                    }
                } else {
                    warn!("error reading data from socket");
                    *should_break.lock().unwrap() = true;
                }
            })
        };

        futures::pin_mut!(act_on_messages);

        // send ping message every 120 secondes
        let mut ping_interval = tokio::time::interval(core::time::Duration::from_secs(120));
        // wait first iteration as first is now
        ping_interval.tick().await;

        // force websocket to die after 70 minutes as it should only last 60 minutes anyway
        let mut force_kill = tokio::time::interval(core::time::Duration::from_secs(4_200));
        // wait first iteration as first is now
        force_kill.tick().await;
        let mut ws_or_scheduled_death = futures::future::select(
            futures::future::poll_fn(|cx| force_kill.poll_tick(cx)),
            act_on_messages,
        );

        loop {
            let first_done = futures::future::select(
                futures::future::poll_fn(|cx| ping_interval.poll_tick(cx)),
                ws_or_scheduled_death,
            )
            .await;
            match first_done {
                // ping future is first, refresh web socket listener future
                Either::Left((_, b)) => {
                    ws_or_scheduled_death = b;
                }
                // web socket listener future ended, exit
                Either::Right((_, _)) => break,
            }

            // break as websocket received an unknown message
            if *should_break.lock().unwrap() {
                break;
            }

            // ping future was the first future to end, send ping
            write
                .send(async_tungstenite::tungstenite::Message::text("Ping"))
                .await?;
        }

        Ok(())
    }
}
