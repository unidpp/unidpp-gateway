//! Entrypoint: environment-driven configuration, then serve forever.

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let config = unidpp_gateway::Config::from_env();
    if let Some(url) = &config.issuer_url {
        eprintln!("unidpp-gateway: issuer upstream {url} (fixtures remain the fallback)");
    }
    unidpp_gateway::run(config).await
}
