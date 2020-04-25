use std::cell::RefCell;

use rand::{thread_rng, Rng};
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

#[derive(Deserialize, Debug)]
pub struct MowerAttributes {
    pub state: Attribute<String>,
    pub activity: Attribute<String>,
    #[serde(rename = "lastErrorCode")]
    pub last_error_code: Option<Attribute<String>>,
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

#[derive(Deserialize, Debug)]
pub struct CommonAttributes {
    pub name: Attribute<String>,
    #[serde(rename = "batteryLevel")]
    pub battery_level: Attribute<u8>,
    #[serde(rename = "batteryState")]
    pub battery_state: Attribute<String>,
    #[serde(rename = "rfLinkLevel")]
    pub rf_link_level: Attribute<u8>,
    #[serde(rename = "rfLinkState")]
    pub rf_link_state: Attribute<String>,
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
        let mut act_on_messages = act_on_messages;

        let mut ping_interval = tokio::time::interval(core::time::Duration::from_secs(120));
        // wait first iteration as first is now
        ping_interval.tick().await;

        loop {
            let first_done = futures::future::select(
                futures::future::poll_fn(|cx| ping_interval.poll_tick(cx)),
                act_on_messages,
            )
            .await;
            match first_done {
                // ping future is first, refresh web socket listener future
                Either::Left((_, b)) => {
                    act_on_messages = b;
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
