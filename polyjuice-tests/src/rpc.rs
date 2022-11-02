use jsonrpsee_core::client::ClientT;
use jsonrpsee_http_client::{types::ParamsSer, HttpClient, HttpClientBuilder};

const MAINNET_URL: &str = "https://v1.mainnet.godwoken.io:443/rpc";
const TESTNET_URL: &str = "https://godwoken-testnet-v1.ckbapp.dev:443";
pub enum EnvType {
    MainNet,
    TestNet,
}

pub(crate) struct RPC {
    client: HttpClient,
}

impl RPC {
    pub(crate) fn new(env_type: EnvType) -> anyhow::Result<Self> {
        let url = match env_type {
            EnvType::MainNet => MAINNET_URL,
            EnvType::TestNet => TESTNET_URL,
        };
        let client = HttpClientBuilder::default().build(url)?;
        Ok(Self { client })
    }

    pub(crate) async fn get_code(&self, address: &str) -> anyhow::Result<String> {
        let address = if address.starts_with("0x") {
            address.to_string()
        } else {
            format!("0x{}", address)
        };
        let code = self
            .client
            .request(
                "eth_getCode",
                Some(ParamsSer::Array(vec![address.into(), "latest".into()])),
            )
            .await?;
        Ok(code)
    }

    pub(crate) async fn get_storage_at(&self, address: &str, index: u32) -> anyhow::Result<String> {
        let address = if address.starts_with("0x") {
            address.to_string()
        } else {
            format!("0x{}", address)
        };

        let index = format!("{index:#x}");
        let value = self
            .client
            .request(
                "eth_getStorageAt",
                Some(ParamsSer::Array(vec![
                    address.into(),
                    index.into(),
                    "latest".into(),
                ])),
            )
            .await?;
        Ok(value)
    }
}
