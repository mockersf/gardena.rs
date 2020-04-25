use clap::Clap;

use gardena_rs;

#[derive(Clap)]
#[clap(version = "1.0", author = "François")]
struct Opts {
    /// username
    #[clap(short = "u", long = "username")]
    username: String,

    /// password
    #[clap(short = "p", long = "password")]
    password: String,

    /// application_key
    #[clap(short = "k", long = "application_key")]
    application_key: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts: Opts = Opts::parse();
    let gardena = gardena_rs::Gardena::new(opts.username, opts.password, opts.application_key);
    let locations = dbg!(gardena.list_locations().await?);
    if let gardena_rs::Object::Location { ref id, .. } = locations[0] {
        dbg!(gardena.get_location(&id).await?);
        let ws_info = dbg!(gardena.get_websocket_url(&id).await?);
        if let gardena_rs::Object::Websocket { ref attributes, .. } = ws_info {
            gardena_rs::asyncstd::connect_to_websocket(attributes.url.clone(), |msg| {
                println!("{:?}", msg)
            })
            .await?;
        }
    }

    Ok(())
}
