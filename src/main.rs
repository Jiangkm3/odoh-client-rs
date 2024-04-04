pub mod config;
pub mod dns_utils;
use anyhow::{anyhow, Context, Result};
use clap::{App, Arg};
use config::Config;
use dns_utils::{create_dns_query, parse_dns_answer};
use odoh_rs::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use reqwest::{
    header::{HeaderMap, ACCEPT, CACHE_CONTROL, CONTENT_TYPE},
    Client, Response, StatusCode,
};
use std::{convert::TryInto, env, fs::File, io::Read};
use url::Url;

use std::time::Instant;

const USE_PROXIES: bool = true;
// const NUM_HOPS: usize = 1;
const NUM_PROXIES: usize = 1;

const PKG_NAME: &str = env!("CARGO_PKG_NAME");
const PKG_AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const PKG_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

const QUERY_PATH: &str = "/dns-query";
const WELL_KNOWN: &str = "/.well-known/odohconfigs";

#[derive(Clone, Debug)]
struct ClientSession {
    pub client: Client,
    pub target: Url,
    pub proxy: String,
    pub client_secret: Option<[u8; 16]>,
    pub target_config: ObliviousDoHConfigContents,
    pub query: Option<ObliviousDoHMessagePlaintext>,
}

impl ClientSession {
    /// Create a new ClientSession
    pub async fn new(config: Config) -> Result<Self> {
        let mut target = Url::parse(&config.server.target)?;
        target.set_path(QUERY_PATH);
        let proxy = "".to_string();

        // fetch `odohconfigs` by querying well known endpoint using GET request
        let mut odohconfigs = reqwest::get(&format!("{}{}", config.server.target, WELL_KNOWN))
            .await?
            .bytes()
            .await?;
        let configs: ObliviousDoHConfigs = parse(&mut odohconfigs).context("invalid configs")?;
        let target_config = configs
            .into_iter()
            .next()
            .context("no available config")?
            .into();

        Ok(Self {
            client: Client::new(),
            target,
            proxy,
            client_secret: None,
            target_config,
            query: None,
        })
    }

    /// Create an oblivious query from a domain and query type
    pub async fn create_request<const USE_PROXIES: bool>(&mut self, domain: &str, qtype: &str, proxy_names: &Vec<String>, proxy_keys: &Vec<&ObliviousDoHConfigContents>, num_hops: usize) -> Result<(usize, Vec<u8>)> {
        // create a DNS message
        let dns_msg = create_dns_query(domain, qtype)?;
        let query = ObliviousDoHMessagePlaintext::new(&dns_msg, 1);
        self.query = Some(query.clone());
        let mut rng = StdRng::from_entropy();

        if USE_PROXIES {
            let (first_proxy, oblivious_query, client_secret) = encrypt_query_with_proxies(
                &query, 
                &self.target.host_str().unwrap().to_string(), 
                &self.target_config,
                num_hops,
                proxy_names,
                proxy_keys, 
                &mut rng
            ).context("failed to encrypt query")?;
            let query_body = compose(&oblivious_query)
                .context("failed to compose query body")?
                .freeze();

            self.client_secret = Some(client_secret);
            Ok((first_proxy, query_body.to_vec()))
        } else {
            let (oblivious_query, client_secret) = encrypt_query(
                &query, 
                &self.target_config,
                &mut rng
            ).context("failed to encrypt query")?;
            let query_body = compose(&oblivious_query)
                .context("failed to compose query body")?
                .freeze();
    
            self.client_secret = Some(client_secret);
            Ok((0, query_body.to_vec()))
        }
    }

    /// Set headers and build an HTTP request to send the oblivious query to the proxy/target.
    /// If a proxy is specified, the request will be sent to the proxy. However, if a proxy is absent,
    /// it will be sent directly to the target. Note that not specifying a proxy effectively nullifies
    /// the entire purpose of using ODoH.
    pub async fn send_request<const USE_PROXIES: bool>(
        &mut self, 
        request: &[u8],
    ) -> Result<Response> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, ODOH_HTTP_HEADER.parse()?);
        headers.insert(ACCEPT, ODOH_HTTP_HEADER.parse()?);
        headers.insert(CACHE_CONTROL, "no-cache, no-store".parse()?);

        let proxy = reqwest::Proxy::https(&self.proxy)?;
        let mut buf = Vec::new();
        File::open("../third-wheel/ca/ca_certs/cert.pem")?.read_to_end(&mut buf)?;
        let cert = reqwest::Certificate::from_pem(&buf)?;
        self.client = reqwest::Client::builder()
            .add_root_certificate(cert)
            .proxy(proxy)
            .danger_accept_invalid_certs(true)
            .build()?;
        let builder = if USE_PROXIES {
            // Set target to a blind website
            let mut blind = Url::parse("https://www.google.com")?;
            blind.set_path(QUERY_PATH);
            self.client.post(blind.clone()).headers(headers)
        } else {
            self.client.post(self.target.clone()).headers(headers)
        };
        let resp = builder.body(request.to_vec()).send().await?;
        Ok(resp)
    }

    /// Parse the received response from the resolver and print the answer.
    pub async fn parse_response(&self, resp: Response) -> Result<String> {
        if resp.status() != StatusCode::OK {
            return Err(anyhow!(
                "query failed with response status code {}",
                resp.status().as_u16()
            ));
        }
        let mut data = resp.bytes().await?;
        let parse_timer = if USE_PROXIES {
            let parse_timer_bytes_len = data.split_to(1)[0] as usize;
            String::from_utf8(data.split_to(parse_timer_bytes_len).to_vec()).unwrap()
        } else {
            "".to_string()
        };
        let response_body = parse(&mut data).context("failed to parse response body")?;
        let response = decrypt_response(
            &self.query.clone().unwrap(),
            &response_body,
            self.client_secret.clone().unwrap(),
        )
        .context("failed to decrypt response")?;
        // parse_dns_answer(&response.into_msg())?;
        Ok(parse_timer)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let proxy_names: Vec<String> = (0..NUM_PROXIES).map(|i| format!("http://localhost:{}", 8080 + i)).collect();
    let mut rng_list: Vec<StdRng> = (0..NUM_PROXIES).map(|i| StdRng::seed_from_u64(i.try_into().unwrap())).collect();
    let keypair_list: Vec<ObliviousDoHKeyPair> = rng_list.iter_mut().map(|r| ObliviousDoHKeyPair::new(r)).collect();
    let proxy_keys: Vec<&ObliviousDoHConfigContents> = keypair_list.iter().map(|i| i.public()).collect();

    let matches = App::new(PKG_NAME)
        .version(PKG_VERSION)
        .author(PKG_AUTHORS)
        .about(PKG_DESCRIPTION)
        .arg(
            Arg::with_name("config_file")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Path to the config.toml config file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("domain")
                .help("Domain to query")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("type")
                .help("Query type")
                .required(true)
                .index(2),
        )
        .get_matches();

    let config_file = matches
        .value_of("config_file")
        .unwrap_or("tests/config.toml");
    let config = Config::from_path(config_file)?;
    let domain = matches.value_of("domain").unwrap();
    let qtype = matches.value_of("type").unwrap();
    let mut session = ClientSession::new(config.clone()).await?;

    let num_hops = 1;
    // for num_hops in 1..11 {
        // println!("\n--\nPOOL = 16, HOP = {}", num_hops);
        // for _ in 0..5 {
            let init_timer = Instant::now();
            let (first_proxy, request) = session.create_request::<USE_PROXIES>(domain, qtype, &proxy_names, &proxy_keys, num_hops).await?;
            let encrypt_timer = init_timer.elapsed();

            session.proxy = proxy_names[first_proxy].clone();
            let response = session.send_request::<USE_PROXIES>(&request).await?;
            let parse_timer = session.parse_response(response).await?;
            let rtt_timer = init_timer.elapsed();
            
            if USE_PROXIES {
                println!("CPT: {:.4?}, RTT: {:.4?}, TPDT: {}", encrypt_timer, rtt_timer, parse_timer);
            } else {
                println!("CPT: {:.4?}, RTT: {:.4?}", encrypt_timer, rtt_timer);
            }
        // }
    // }
    Ok(())
}
