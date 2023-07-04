use std::io;
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use futures::{StreamExt, stream::FuturesUnordered, Future};
use ipnet::{IpNet, Ipv4Net, Ipv6Net, IpAddrRange};
use std::str::FromStr;

async fn check_socks5_proxy(addr: SocketAddr, target: String) -> io::Result<()> {
    let mut stream = TcpStream::connect(addr).await?;

    let mut data = Cursor::new(b"\x05\x01\x00");
    stream.write_buf(&mut data).await?;

    let mut buf = vec![0; 1024];
    let r = stream.read(&mut buf[..]).await?;

    if r == 2 && buf[0] == 0x05 && buf[1] == 0x00 {
        let mut data = b"\x05\x01\x00\x03".to_vec();
        data.push(target.len() as u8);
        data.append(&mut target.as_bytes().to_vec());
        data.push(0x01);
        data.push(0xBB);
        stream.write_buf(&mut data.as_slice()).await?;

        let mut buf = vec![0; 1024];
        let r = stream.read(&mut buf[..]).await?;
        if r >= 7 && buf[1] == 0x00 {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::Other, std::format!("can't connect to {}", addr)))
        }
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "not a socks5 proxy"))
    }
}

async fn check_http_proxy(addr: SocketAddr, target: String) -> io::Result<()> {
    let mut stream = TcpStream::connect(addr).await?;

    let request = 
    std::format!("CONNECT {}:443 HTTP/1.1\r\n", target) +
    std::format!("Host: {}:443\r\n", target).as_str() +
    "User-Agent: curl/7.68.0\r\n" +
    "Proxy-Connection: Keep-Alive\r\n\r\n";
    stream.write_buf(&mut request.as_bytes()).await?;

    let mut buf = vec![0; 1024];
    let r = stream.read(&mut buf[..]).await?;
    if let Ok(msg) = String::from_utf8(buf[0..r].to_vec()) {
        if msg.starts_with("HTTP/1.1 200") {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "rejected by server"))
        }
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "not a http proxy"))
    }
}

#[derive(Debug)]
enum ProxyType {
    Http(String),
    Socks5(String)
}

fn from_error(result: &std::io::Result<()>, proxy_type: ProxyType) -> (ProxyType, Result<(),String>) {
    match result {
        Ok(()) => (proxy_type, Ok(())),
        Err(e) => (proxy_type, Err(e.to_string()))
    }
}

async fn worker(proxy_list: Arc<Mutex<SocketAddrRange>>,
                socks5_proxy_test_result: Arc<Mutex<Vec<(String,Result<(),String>)>>>,
                http_proxy_test_result: Arc<Mutex<Vec<(String,Result<(),String>)>>>,
                target: String, max_await: usize) -> Result<(),String>
{
    let mut future_set: FuturesUnordered<std::pin::Pin<Box<dyn Future<Output = (ProxyType, Result<(), String>)> + Send>>> = FuturesUnordered::new();
    let mut http_result = vec![];
    let mut socks5_result = vec![];
    let mut proxy_list_is_empty = false;
    while !proxy_list_is_empty || future_set.len() > 0 {
        let nn = proxy_list.lock().unwrap().next();
        if nn.is_some() {
            let proxy = nn.unwrap();
            if let Ok(addr) = proxy.parse::<SocketAddr>() {
                let http_test = check_http_proxy(addr, target.clone());
                let socks5_test = check_socks5_proxy(addr, target.clone());
                let p1 = proxy.to_string();
                let p2 = proxy.to_string();
                future_set.push(Box::pin(async move { from_error(&http_test.await, ProxyType::Http(p1)) }));
                future_set.push(Box::pin(async move { from_error(&socks5_test.await, ProxyType::Socks5(p2)) }));
            }
        } else {
            proxy_list_is_empty = true;
        }
        if future_set.len() >= max_await || proxy_list_is_empty {
            let result_opt = future_set.next().await;
            if result_opt.is_some() {
                let result = result_opt.unwrap();
                println!("{:?}", result);
                match result.0 {
                    ProxyType::Http(addr) => http_result.push((addr, result.1)),
                    ProxyType::Socks5(addr) => socks5_result.push((addr, result.1)),
                }
            }
        }
    }
    http_proxy_test_result.lock().unwrap().append(&mut http_result);
    socks5_proxy_test_result.lock().unwrap().append(&mut socks5_result);
    return Ok(());
}

fn edit_distance(str1: &str, str2: &str) -> usize {
    let len1 = str1.chars().count();
    let len2 = str2.chars().count();

    let mut dp = vec![vec![0; len2 + 1]; len1 + 1];

    for i in 0..=len1 {
        dp[i][0] = i;
    }

    for j in 0..=len2 {
        dp[0][j] = j;
    }

    for (i, char1) in str1.chars().enumerate() {
        for (j, char2) in str2.chars().enumerate() {
            let substitution_cost = if char1 == char2 { 0 } else { 1 };
            dp[i + 1][j + 1] = dp[i][j] + substitution_cost;
            dp[i + 1][j + 1] = dp[i + 1][j + 1].min(dp[i + 1][j] + 1);
            dp[i + 1][j + 1] = dp[i + 1][j + 1].min(dp[i][j + 1] + 1);
        }
    }

    dp[len1][len2]
}

#[derive(Debug)]
struct SocketAddrRange {
    nets: Vec<IpNet>,
    ports: Vec<u16>,
    net_idx: usize,
    current_net: Option<IpAddrRange>,
    port_idx: usize,
}

impl From<(Vec<IpNet>, Vec<u16>)> for SocketAddrRange {
    fn from(nets_ports: (Vec<IpNet>, Vec<u16>)) -> Self {
        SocketAddrRange {
            nets: nets_ports.0,
            ports: nets_ports.1,
            net_idx: 0,
            current_net: None,
            port_idx: 0
        }
    }
}

impl Iterator for SocketAddrRange {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.port_idx >= self.ports.len() || self.nets.is_empty() {
            return None;
        }

        if self.current_net.is_none() {
            self.current_net = Some(self.nets[self.net_idx].hosts());
        }

        let ip = self.current_net.as_mut().unwrap().next();
        let ipunwrap = if ip.is_none() {
            if self.net_idx + 1 >= self.nets.len() {
                self.net_idx = 0;
                self.port_idx += 1;
                if self.port_idx >= self.ports.len() {
                    return None;
                }
            } else {
                self.net_idx += 1;
            }
            self.current_net = Some(self.nets[0].hosts());
            self.current_net.unwrap().next().unwrap()
        } else {
            ip.unwrap()
        };

        Some(format!("{}:{}", ipunwrap, self.ports[self.port_idx]))
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let port_start = 256;
    let port_end = 65535;
    let mut ports: Vec<u16> = (port_start..port_end).collect();
    let distances: Vec<usize> = ports.iter().map(|v| {
        let ax = v.to_string();
        edit_distance(ax.as_str(), "7890") * edit_distance(ax.as_str(), "1080") * edit_distance(ax.as_str(), "8080")
    }).collect();
    ports.sort_by(|a, b| {
        let v1 = distances.get((a - port_start) as usize).unwrap();
        let v2 = distances.get((b - port_start) as usize).unwrap();
        v1.partial_cmp(v2).unwrap()
    });
    let ports = ports;

    let mut nets = vec![];
    let addr_vec: Vec<String> = vec!["192.168.100.46/31".to_string()];
    for addr in addr_vec {
        if let Ok(ipv4) = Ipv4Net::from_str(addr.as_str()) {
            nets.push(IpNet::from(ipv4));
        }
        if let Ok(ipv6) = Ipv6Net::from_str(addr.as_str()) {
            nets.push(IpNet::from(ipv6));
        }
    }

    let sarange = Arc::new(Mutex::new(SocketAddrRange::from((nets.clone(), ports.clone()))));
    let socks5_proxy_test_result = Arc::new(Mutex::new(vec![]));
    let http_proxy_test_result   = Arc::new(Mutex::new(vec![]));
    let mut tasks = Vec::new();
    let num_threads: usize = std::thread::available_parallelism().unwrap().into();
    for _ in 0..num_threads {
        tasks.push(tokio::spawn(worker(
                    sarange.clone(),
                    socks5_proxy_test_result.clone(),
                    http_proxy_test_result.clone(), "google.com".to_string(), 100)));
    }

    futures::future::join_all(tasks).await;
    let mm = socks5_proxy_test_result.lock().unwrap();
    for m in &*mm {
        if m.1.is_ok() {
            println!("socks5 proxy: '{}' works", m.0);
        } else {
            println!("socks5 proxy: '{}' doesn't work, {}", m.0, m.1.as_ref().unwrap_err());
        }
    }
    let mm = http_proxy_test_result.lock().unwrap();
    for m in &*mm {
        if m.1.is_ok() {
            println!("http proxy: '{}' works", m.0);
        } else {
            println!("http proxy: '{}' doesn't work, {}", m.0, m.1.as_ref().unwrap_err());
        }
    }
    Ok(())
}
