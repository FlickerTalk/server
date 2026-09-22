use tokio::net::TcpListener;

const DEFAULT_ADDRESS: &str = "0.0.0.0:8787";

/// Where to listen: `FT_ROUTER_ADDR` if set, else every interface on port 8787.
fn listen_address(configured: Option<String>) -> String {
    configured.filter(|address| !address.is_empty()).unwrap_or_else(|| DEFAULT_ADDRESS.to_owned())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_address(std::env::var("FT_ROUTER_ADDR").ok())).await?;
    axum::serve(listener, ft_router::app()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listens_on_port_8787_unless_told_otherwise() {
        assert_eq!(listen_address(None), "0.0.0.0:8787");
        assert_eq!(listen_address(Some(String::new())), "0.0.0.0:8787");
        assert_eq!(listen_address(Some("127.0.0.1:9000".to_owned())), "127.0.0.1:9000");
    }
}
