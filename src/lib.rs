use std::cell::RefCell;
use std::fmt;
use std::str::FromStr;

use rand::{thread_rng, Rng};
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};

static AUTH_URL: &str = "https://api.authentication.husqvarnagroup.dev/v1/oauth2/token";

static API_BASE_URL: &str = "https://api.smart.gardena.dev/v1";

#[derive(Deserialize, Debug)]
pub struct TokenInfo {
    access_token: String,
    scope: String,
    expires_in: u16,
    refresh_token: String,
    provider: String,
    user_id: String,
    token_type: String,
}

#[derive(Deserialize, Debug)]
pub struct Response<T> {
    data: T,
    #[serde(default)]
    included: Vec<Object>,
}

#[derive(Deserialize, Debug)]
pub struct ObjectLink {
    pub id: String,
    #[serde(rename = "type")]
    pub ty: String,
}

#[derive(Deserialize, Debug)]
pub struct DeviceList {
    pub devices: Response<Vec<ObjectLink>>,
}

#[derive(Deserialize, Debug)]
pub struct DeviceRelationShips {
    pub location: Response<ObjectLink>,
    pub services: Response<Vec<ObjectLink>>,
}

#[derive(Deserialize, Debug)]
pub struct Attribute<T> {
    pub value: T,
    pub timestamp: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct DeviceRelationShip {
    pub device: Response<ObjectLink>,
}

#[derive(Debug, PartialEq, Clone, enum_utils::IterVariants, enum_utils::FromStr)]
#[enumeration(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MowerState {
    Error,
    Ok,
    Warning,
    #[enumeration(skip)]
    Other(String),
}
impl MowerState {
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
            MowerState::Other(value) => write!(f, "{}", value),
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

#[derive(Debug, PartialEq, Clone, enum_utils::IterVariants, enum_utils::FromStr)]
#[enumeration(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MowerActivity {
    None,
    OkCharging,
    OkCutting,
    OkCuttingTimerOverridden,
    OkLeaving,
    OkSearching,
    ParkedParkSelected,
    ParkedTimer,
    Paused,
    #[enumeration(skip)]
    Other(String),
}
impl MowerActivity {
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
            MowerActivity::Other(value) => write!(f, "{}", value),
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

#[derive(Debug, PartialEq, Clone, enum_utils::IterVariants, enum_utils::FromStr)]
#[enumeration(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MowerErrorCode {
    ChargingStationBlocked,
    CollisionSensorProblemFront,
    Lifted,
    NoLoopSignal,
    OffHatchOpen,
    OutsideWorkingArea,
    ParkedDailyLimitReached,
    #[enumeration(skip)]
    Other(String),
}
impl MowerErrorCode {
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
            MowerErrorCode::Other(value) => write!(f, "{}", value),
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

#[derive(Deserialize, Debug)]
pub struct MowerAttributes {
    pub state: Attribute<MowerState>,
    pub activity: Attribute<MowerActivity>,
    #[serde(rename = "lastErrorCode")]
    pub last_error_code: Option<Attribute<MowerErrorCode>>,
    #[serde(rename = "operatingHours")]
    pub operating_hours: Attribute<u16>,
}

#[derive(Deserialize, Debug)]
pub struct PowerSocketAttributes {
    pub state: Attribute<String>,
    pub activity: Attribute<String>,
    #[serde(rename = "lastErrorCode")]
    pub last_error_code: Option<Attribute<String>>,
    pub duration: Attribute<u16>,
}

#[derive(Deserialize, Debug)]
pub struct ValveAttributes {
    pub name: Attribute<String>,
    pub state: Attribute<String>,
    pub activity: Attribute<String>,
    #[serde(rename = "lastErrorCode")]
    pub last_error_code: Option<Attribute<String>>,
    pub duration: Attribute<u16>,
}

#[derive(Deserialize, Debug)]
pub struct ValveSetAttributes {
    pub state: Attribute<String>,
    #[serde(rename = "lastErrorCode")]
    pub last_error_code: Option<Attribute<String>>,
}

#[derive(Deserialize, Debug)]
pub struct SensorAttributes {
    #[serde(rename = "soilHumidity")]
    pub soil_humidity: Attribute<f32>,
    #[serde(rename = "soilTemperature")]
    pub soil_temperature: Attribute<f32>,
    #[serde(rename = "ambientTemperature")]
    pub ambient_temperature: Attribute<f32>,
    #[serde(rename = "lightIntensity")]
    pub light_intensity: Attribute<f32>,
}

#[derive(Debug, PartialEq, Clone, enum_utils::IterVariants, enum_utils::FromStr)]
#[enumeration(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CommonBatteryState {
    Charging,
    Ok,
    #[enumeration(skip)]
    Other(String),
}
impl CommonBatteryState {
    pub fn to_iter() -> impl Iterator<Item = Self> + Clone {
        Self::iter()
    }
}
impl std::fmt::Display for CommonBatteryState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommonBatteryState::Charging => write!(f, "CHARGING"),
            CommonBatteryState::Ok => write!(f, "OK"),
            CommonBatteryState::Other(value) => write!(f, "{}", value),
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

#[derive(Debug, PartialEq, Clone, enum_utils::IterVariants, enum_utils::FromStr)]
#[enumeration(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CommonRfLinkState {
    Online,
    #[enumeration(skip)]
    Other(String),
}
impl CommonRfLinkState {
    pub fn to_iter() -> impl Iterator<Item = Self> + Clone {
        Self::iter()
    }
}
impl std::fmt::Display for CommonRfLinkState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommonRfLinkState::Online => write!(f, "ONLINE"),
            CommonRfLinkState::Other(value) => write!(f, "{}", value),
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

#[derive(Deserialize, Debug)]
pub struct CommonAttributes {
    pub name: Attribute<String>,
    #[serde(rename = "batteryLevel")]
    pub battery_level: Attribute<u8>,
    #[serde(rename = "batteryState")]
    pub battery_state: Attribute<CommonBatteryState>,
    #[serde(rename = "rfLinkLevel")]
    pub rf_link_level: Attribute<u8>,
    #[serde(rename = "rfLinkState")]
    pub rf_link_state: Attribute<CommonRfLinkState>,
    pub serial: Attribute<String>,
    #[serde(rename = "modelType")]
    pub model_type: Attribute<String>,
}

#[derive(Deserialize, Debug)]
pub struct WebsocketAttributes {
    pub validity: u16,
    pub url: String,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Object {
    #[serde(rename = "LOCATION")]
    Location {
        id: String,
        attributes: std::collections::HashMap<String, String>,
        relationships: Option<DeviceList>,
    },
    #[serde(rename = "WEBSOCKET")]
    Websocket {
        id: String,
        attributes: WebsocketAttributes,
    },
    #[serde(rename = "DEVICE")]
    Device {
        id: String,
        relationships: Option<DeviceRelationShips>,
    },
    #[serde(rename = "COMMON")]
    Common {
        id: String,
        relationships: Option<DeviceRelationShip>,
        attributes: CommonAttributes,
    },
    #[serde(rename = "MOWER")]
    Mower {
        id: String,
        relationships: Option<DeviceRelationShip>,
        attributes: MowerAttributes,
    },
    #[serde(rename = "POWER_SOCKET")]
    PowerSocket {
        id: String,
        relationships: Option<DeviceRelationShip>,
        attributes: PowerSocketAttributes,
    },
    #[serde(rename = "VALVE")]
    Valve {
        id: String,
        relationships: Option<DeviceRelationShip>,
        attributes: ValveAttributes,
    },
    #[serde(rename = "VALVE_SET")]
    ValveSet {
        id: String,
        relationships: Option<DeviceRelationShip>,
        attributes: ValveSetAttributes,
    },
    #[serde(rename = "SENSOR")]
    Sensor {
        id: String,
        relationships: Option<DeviceRelationShip>,
        attributes: SensorAttributes,
    },
}

#[derive(Serialize, Debug)]
pub struct LocationIdRequested {
    #[serde(rename = "locationId")]
    location_id: String,
}

#[derive(Serialize, Debug)]
pub struct WebsocketRequest {
    id: String,
    #[serde(rename = "type")]
    ty: String,
    attributes: LocationIdRequested,
}

#[derive(Serialize, Debug)]
pub struct Request<T> {
    data: T,
}

pub struct Gardena {
    client: reqwest::Client,
    username: String,
    password: String,
    application_key: String,
    token_info: RefCell<Option<TokenInfo>>,
}

impl Gardena {
    pub fn new(username: String, password: String, application_key: String) -> Gardena {
        Gardena {
            client: reqwest::Client::new(),
            username,
            password,
            application_key,
            token_info: RefCell::new(None),
        }
    }

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
#[cfg(feature = "websocket-asyncstd")]
pub mod asyncstd {
    use futures::prelude::*;

    pub async fn connect_to_websocket<F>(
        url: String,
        act: F,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        F: Fn(super::Object) -> (),
    {
        let (ws_stream, _) = asyncstd_tungstenite::async_std::connect_async(url).await?;

        let (_, read) = ws_stream.split();
        let act_on_messages = {
            read.for_each(|message| async {
                let data = message.unwrap().into_data();
                if let Ok(msg) = serde_json::from_slice::<super::Object>(&data) {
                    act(msg);
                } else {
                    dbg!(std::str::from_utf8(&data).unwrap());
                }
            })
        };

        act_on_messages.await;

        Ok(())
    }
}

#[cfg(feature = "websocket-tokio")]
pub mod tokio {
    use futures::{future::Either, prelude::*};

    pub async fn connect_to_websocket<F>(
        url: String,
        act: F,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        F: Fn(super::Object) -> (),
    {
        let (ws_stream, _) = tokio_tungstenite::tokio::connect_async(url).await?;

        let should_break = std::sync::Mutex::new(false);

        let (mut write, read) = ws_stream.split();
        let act_on_messages = {
            read.for_each(|message| async {
                if let Ok(data) = message {
                    let data = data.into_data();
                    if let Ok(msg) = serde_json::from_slice::<super::Object>(&data) {
                        act(msg);
                    } else {
                        println!("error parsing data from socket");
                        dbg!(std::str::from_utf8(&data).unwrap());
                        *should_break.lock().unwrap() = true;
                    }
                } else {
                    println!("error reading data from socket");
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
                .send(tokio_tungstenite::tungstenite::Message::text("Ping"))
                .await?;
        }

        Ok(())
    }
}
