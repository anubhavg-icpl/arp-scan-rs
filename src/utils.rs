use std::env;
use std::process;
use std::sync::Arc;

use ansi_term::Color::{Blue, Cyan, Green, Purple, Red, Yellow};
use ansi_term::Style;
use ipnetwork::{IpNetwork, NetworkSize};
use pnet_datalink::NetworkInterface;
use serde::Serialize;

use crate::args::ScanOptions;
use crate::network::{ResponseSummary, TargetDetails};

/**
 * Based on the current UNIX environment, find if the process is run as root
 * user. This approach only supports Linux-like systems (Ubuntu, Fedore, ...).
 */
pub fn is_root_user() -> bool {
    env::var("USER").unwrap_or_else(|_| String::from("")) == *"root"
}

/**
 * Prints on stdout a list of all available network interfaces with some
 * technical details. The goal is to present the most useful technical details
 * to pick the right network interface for scans.
 */
pub fn show_interfaces(interfaces: &[NetworkInterface]) {
    let mut interface_count = 0;
    let mut ready_count = 0;

    println!();
    println!(
        "{}",
        Style::new()
            .bold()
            .paint("╔═══════════════════════════════════════════════════════════════════════════╗")
    );
    println!(
        "{}",
        Style::new()
            .bold()
            .paint("║              🌐  Network Interfaces Available for ARP Scan              ║")
    );
    println!(
        "{}",
        Style::new()
            .bold()
            .paint("╚═══════════════════════════════════════════════════════════════════════════╝")
    );
    println!();
    println!(
        "  {} {: <18} {: <18} {: <20} {}",
        Cyan.bold().paint("ID"),
        Cyan.bold().paint("Interface"),
        Cyan.bold().paint("Status"),
        Cyan.bold().paint("MAC Address"),
        Cyan.bold().paint("IP Address")
    );
    println!("  {}", "─".repeat(90));

    for interface in interfaces.iter() {
        let up_text = match interface.is_up() {
            true => format!("{} {}", Green.bold().paint("✔"), Green.paint("UP")),
            false => format!("{} {}", Red.bold().paint("✖"), Red.dimmed().paint("DOWN")),
        };
        let mac_text = match interface.mac {
            Some(mac_address) => Yellow.paint(format!("{}", mac_address)).to_string(),
            None => Red.dimmed().paint("No MAC").to_string(),
        };
        let first_ip = match interface.ips.first() {
            Some(ip_address) => Blue.paint(format!("{}", ip_address)).to_string(),
            None => Red.dimmed().paint("No IP").to_string(),
        };

        let index_text = Purple.bold().paint(format!("[{}]", interface.index));
        println!(
            "  {} {: <18} {: <29} {: <29} {}",
            index_text,
            Style::new().bold().paint(&interface.name),
            up_text,
            mac_text,
            first_ip
        );

        interface_count += 1;
        if interface.is_up() && !interface.is_loopback() && !interface.ips.is_empty() {
            ready_count += 1;
        }
    }

    println!();
    println!(
        "  {} Found {} interfaces, {} ready for scanning",
        Green.bold().paint("►"),
        Yellow.bold().paint(interface_count.to_string()),
        Green.bold().paint(ready_count.to_string())
    );
    if let Some(default_interface) = select_default_interface(interfaces) {
        println!(
            "  {} Default interface: {}",
            Cyan.bold().paint("ℹ"),
            Blue.bold().paint(&default_interface.name)
        );
    }
    println!();
}

pub fn print_ascii_packet() {
    println!();
    println!(" 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 ");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    println!("|         Hardware type         |        Protocol type          |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|");
    println!("|         Hlen  | Plen          |          Operation            |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    println!("|                          Sender HA                            |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    println!("|             Sender HA         |      Sender IP                |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|");
    println!("|             Sender IP         |      Target HA                |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|");
    println!("|                          Target HA                            |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    println!("|                          Target IP                            |");
    println!("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
    println!();
    println!(" - Hardware type (2 bytes), use --hw-type option to change");
    println!(" - Protocol type (2 bytes), use --proto-type option to change");
    println!();
}

/**
 * Find a default network interface for scans, based on the operating system
 * priority and some interface technical details.
 */
pub fn select_default_interface(interfaces: &[NetworkInterface]) -> Option<NetworkInterface> {
    let default_interface = interfaces.iter().find(|interface| {
        if interface.mac.is_none() {
            return false;
        }

        if interface.ips.is_empty() || !interface.is_up() || interface.is_loopback() {
            return false;
        }

        let potential_ipv4 = interface.ips.iter().find(|ip| ip.is_ipv4());
        if potential_ipv4.is_none() {
            return false;
        }

        true
    });

    default_interface.cloned()
}

/**
 * Display scan settings before launching an ARP scan. This includes network
 * details (IP range, interface, ...) and timing informations.
 */
pub fn display_prescan_details(
    ip_networks: &[&IpNetwork],
    selected_interface: &NetworkInterface,
    scan_options: Arc<ScanOptions>,
) {
    let mut network_list = ip_networks
        .iter()
        .take(5)
        .map(|network| network.to_string())
        .collect::<Vec<String>>()
        .join(", ");
    if ip_networks.len() > 5 {
        let more_text = format!(" ({} more)", ip_networks.len() - 5);
        network_list.push_str(&more_text);
    }

    println!();
    println!(
        "{}",
        Style::new()
            .bold()
            .paint("╔═══════════════════════════════════════════════════════════════════════════╗")
    );
    println!(
        "{}",
        Style::new()
            .bold()
            .paint("║                        🎯  Scan Configuration                            ║")
    );
    println!(
        "{}",
        Style::new()
            .bold()
            .paint("╚═══════════════════════════════════════════════════════════════════════════╝")
    );
    println!();
    println!(
        "  {} Interface: {}",
        Cyan.bold().paint("📡"),
        Blue.bold().paint(&selected_interface.name)
    );
    println!(
        "  {} Target Networks: {}",
        Cyan.bold().paint("🌐"),
        Yellow.paint(&network_list)
    );
    if let Some(forced_source_ipv4) = scan_options.source_ipv4 {
        println!(
            "  {} Source IPv4 (forced): {}",
            Cyan.bold().paint("📍"),
            Purple.paint(format!("{}", forced_source_ipv4))
        );
    }
    if let Some(forced_destination_mac) = scan_options.destination_mac {
        println!(
            "  {} Destination MAC (forced): {}",
            Cyan.bold().paint("📌"),
            Purple.paint(format!("{}", forced_destination_mac))
        );
    }
    println!();
}

/**
 * Computes multiple IPv4 networks total size, IPv6 network are not being
 * supported by this function.
 */
pub fn compute_network_size(ip_networks: &[&IpNetwork]) -> u128 {
    ip_networks.iter().fold(0u128, |total_size, ip_network| {
        let network_size: u128 = match ip_network.size() {
            NetworkSize::V4(ipv4_network_size) => ipv4_network_size.into(),
            NetworkSize::V6(_) => {
                eprintln!("IPv6 networks are not supported by the ARP protocol");
                process::exit(1);
            }
        };
        total_size + network_size
    })
}

/**
 * Display the scan results on stdout with a table. The 'final_result' vector
 * contains all items that will be displayed.
 */
pub fn display_scan_results(
    response_summary: ResponseSummary,
    mut target_details: Vec<TargetDetails>,
    options: &ScanOptions,
) {
    target_details.sort_by_key(|item| item.ipv4);

    let mut hostname_len = 15;
    let mut vendor_len = 15;
    for detail in target_details.iter() {
        if let Some(hostname) = &detail.hostname {
            if hostname.len() > hostname_len {
                hostname_len = hostname.len();
            }
        }

        if let Some(vendor) = &detail.vendor {
            if vendor.len() > vendor_len {
                vendor_len = vendor.len();
            }
        }
    }

    if !target_details.is_empty() {
        println!();
        println!(
            "{}",
            Style::new().bold().paint(
                "╔═══════════════════════════════════════════════════════════════════════════╗"
            )
        );
        println!(
            "{}",
            Style::new().bold().paint(
                "║                          🎯  Scan Results                                ║"
            )
        );
        println!(
            "{}",
            Style::new().bold().paint(
                "╚═══════════════════════════════════════════════════════════════════════════╝"
            )
        );
        println!();
        print!("  │ {: <15} ", Cyan.bold().paint("IPv4 Address"));
        print!("│ {: <17} ", Cyan.bold().paint("MAC Address"));
        print!(
            "│ {: <h_max$} ",
            Cyan.bold().paint("Hostname"),
            h_max = hostname_len
        );
        println!(
            "│ {: <v_max$} │",
            Cyan.bold().paint("Vendor"),
            v_max = vendor_len
        );

        println!(
            "  ├─{:─<15}─┼─{:─<17}─┼─{:─<h_max$}─┼─{:─<v_max$}─┤",
            "",
            "",
            "",
            "",
            h_max = hostname_len,
            v_max = vendor_len
        );
    }

    for detail in target_details.iter() {
        let hostname: &str = match &detail.hostname {
            Some(hostname) => hostname,
            None if !options.resolve_hostname => "(disabled)",
            None => "",
        };
        let vendor: &str = match &detail.vendor {
            Some(vendor) => vendor,
            None => "",
        };
        print!("  │ {: <15} ", Blue.paint(format!("{}", detail.ipv4)));
        print!("│ {: <17} ", Yellow.paint(format!("{}", detail.mac)));
        print!(
            "│ {: <h_max$} ",
            Green.paint(hostname),
            h_max = hostname_len
        );
        println!("│ {: <v_max$} │", Purple.paint(vendor), v_max = vendor_len);
    }

    if !target_details.is_empty() {
        println!(
            "  └─{:─<15}─┴─{:─<17}─┴─{:─<h_max$}─┴─{:─<v_max$}─┘",
            "",
            "",
            "",
            "",
            h_max = hostname_len,
            v_max = vendor_len
        );
    }

    println!();
    let seconds_duration = (response_summary.duration_ms as f32) / (1000_f32);
    let target_count = target_details.len();

    println!(
        "{}",
        Style::new()
            .bold()
            .paint("╔═══════════════════════════════════════════════════════════════════════════╗")
    );
    println!(
        "{}",
        Style::new()
            .bold()
            .paint("║                          📊  Scan Summary                                ║")
    );
    println!(
        "{}",
        Style::new()
            .bold()
            .paint("╚═══════════════════════════════════════════════════════════════════════════╝")
    );
    println!();

    match target_count {
        0 => println!(
            "  {} {}",
            Red.bold().paint("✖"),
            Red.bold().paint("No hosts found")
        ),
        1 => println!(
            "  {} {}",
            Green.bold().paint("✔"),
            Green.bold().paint("1 host discovered")
        ),
        _ => println!(
            "  {} {} {}",
            Green.bold().paint("✔"),
            Green.bold().paint(format!("{}", target_count)),
            Green.paint("hosts discovered")
        ),
    }

    println!(
        "  {} Scan duration: {}",
        Cyan.paint("⏱"),
        Yellow.paint(format!("{:.3}s", seconds_duration))
    );

    match response_summary.packet_count {
        0 => println!("  {} No packets received", Red.dimmed().paint("📦")),
        1 => println!("  {} 1 packet received", Blue.paint("📦")),
        _ => println!(
            "  {} {} packets received",
            Blue.paint("📦"),
            Blue.paint(format!("{}", response_summary.packet_count))
        ),
    };

    match response_summary.arp_count {
        0 => println!("  {} No ARP packets filtered", Red.dimmed().paint("🔍")),
        1 => println!("  {} 1 ARP packet filtered", Green.paint("🔍")),
        _ => println!(
            "  {} {} ARP packets filtered",
            Green.paint("🔍"),
            Green.paint(format!("{}", response_summary.arp_count))
        ),
    };

    println!();
}

#[derive(Serialize)]
struct SerializableResultItem {
    ipv4: String,
    mac: String,
    hostname: String,
    vendor: String,
}

#[derive(Serialize)]
struct SerializableGlobalResult {
    packet_count: usize,
    arp_count: usize,
    duration_ms: u128,
    results: Vec<SerializableResultItem>,
}

/**
 * Transforms an ARP scan result (including KPI and target details) to a structure
 * that can be serialized for export (JSON, YAML, CSV, ...)
 */
fn get_serializable_result(
    response_summary: ResponseSummary,
    target_details: Vec<TargetDetails>,
) -> SerializableGlobalResult {
    let exportable_results: Vec<SerializableResultItem> = target_details
        .into_iter()
        .map(|detail| {
            let hostname = match &detail.hostname {
                Some(hostname) => hostname.clone(),
                None => String::from(""),
            };

            let vendor = match &detail.vendor {
                Some(vendor) => vendor.clone(),
                None => String::from(""),
            };

            SerializableResultItem {
                ipv4: format!("{}", detail.ipv4),
                mac: format!("{}", detail.mac),
                hostname,
                vendor,
            }
        })
        .collect();

    SerializableGlobalResult {
        packet_count: response_summary.packet_count,
        arp_count: response_summary.arp_count,
        duration_ms: response_summary.duration_ms,
        results: exportable_results,
    }
}

/**
 * Export the scan results as a JSON string with response details (timings, ...)
 * and ARP results from the local network.
 */
pub fn export_to_json(
    response_summary: ResponseSummary,
    mut target_details: Vec<TargetDetails>,
) -> String {
    target_details.sort_by_key(|item| item.ipv4);

    let global_result = get_serializable_result(response_summary, target_details);

    serde_json::to_string(&global_result).unwrap_or_else(|err| {
        eprintln!("Could not export JSON results ({})", err);
        process::exit(1);
    })
}

/**
 * Export the scan results as a YAML string with response details (timings, ...)
 * and ARP results from the local network.
 */
pub fn export_to_yaml(
    response_summary: ResponseSummary,
    mut target_details: Vec<TargetDetails>,
) -> String {
    target_details.sort_by_key(|item| item.ipv4);

    let global_result = get_serializable_result(response_summary, target_details);

    serde_yaml::to_string(&global_result).unwrap_or_else(|err| {
        eprintln!("Could not export YAML results ({})", err);
        process::exit(1);
    })
}

/**
 * Export the scan results as a CSV string with response details (timings, ...)
 * and ARP results from the local network.
 */
pub fn export_to_csv(
    response_summary: ResponseSummary,
    mut target_details: Vec<TargetDetails>,
) -> String {
    target_details.sort_by_key(|item| item.ipv4);

    let global_result = get_serializable_result(response_summary, target_details);

    let mut wtr = csv::Writer::from_writer(vec![]);

    for result in global_result.results {
        wtr.serialize(result).unwrap_or_else(|err| {
            eprintln!("Could not serialize result to CSV ({})", err);
            process::exit(1);
        });
    }
    wtr.flush().unwrap_or_else(|err| {
        eprintln!("Could not flush CSV writer buffer ({})", err);
        process::exit(1);
    });

    let convert_writer = wtr.into_inner().unwrap_or_else(|err| {
        eprintln!("Could not convert final CSV result ({})", err);
        process::exit(1);
    });
    String::from_utf8(convert_writer).unwrap_or_else(|err| {
        eprintln!("Could not convert final CSV result to text ({})", err);
        process::exit(1);
    })
}
