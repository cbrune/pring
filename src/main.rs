//
// Copyright (C) 2020 Curt Brune <curt@brune.net>
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This program requires extra permission to open a raw socket:
//     sudo setcap cap_net_raw=eip target/debug/pring

use std::cmp;
use std::thread;
use std::time;

use txrx_icmp::*;

use anyhow::{Context, Result};
use dns_lookup;
use log::debug;
use pnet::packet::icmp;
use pnet::packet::icmpv6;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{icmp_packet_iter, icmpv6_packet_iter, transport_channel};
use pnet::transport::{TransportChannelType, TransportProtocol};

use structopt::StructOpt;

fn main() -> Result<()> {
    let arguments = CliArgs::from_args();

    let log_level = if arguments.debug {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    let mut logger = env_logger::Builder::from_default_env();
    logger.filter_level(log_level);
    logger.init();

    let interface = get_interface(arguments.interface)?;
    debug!("Using interface: {:?}", interface);

    let packet_count = arguments.count.unwrap_or(usize::MAX);
    debug!("packet_count: {}", packet_count);

    let packet_interval = time::Duration::from_secs_f32(arguments.interval);
    debug!("packet_interval: {:?}", packet_interval);

    let packet_ttl = arguments.ttl;
    debug!("packet_ttl: {}", packet_ttl);

    let payload_size = arguments.payload_size;
    debug!("payload_size: {}", payload_size);

    let destination_addrs = dns_lookup::lookup_host(&arguments.destination).context(format!(
        "Unable to resolve destination: {}",
        &arguments.destination
    ))?;

    let destination_ip = if arguments.ipv4_only {
        destination_addrs
            .iter()
            .find(|ip| ip.is_ipv4())
            .ok_or(AppError::NoIpv4AddressFound(arguments.destination.clone()))?
            .to_owned()
    } else if arguments.ipv6_only {
        destination_addrs
            .iter()
            .find(|ip| ip.is_ipv6())
            .ok_or(AppError::NoIpv6AddressFound(arguments.destination.clone()))?
            .to_owned()
    } else {
        // take the first one
        destination_addrs[0].to_owned()
    };
    debug!("Using destination_ip: {:?}", destination_ip);

    let transport_protocol = if destination_ip.is_ipv4() {
        TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)
    } else {
        TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6)
    };

    let (mut packet_tx, mut packet_rx) =
        transport_channel(1024, TransportChannelType::Layer4(transport_protocol))
            .context("Error creating ICMP transport channel")?;

    packet_tx
        .set_ttl(packet_ttl)
        .context(format!("Error setting TTL value: {}", packet_ttl))?;

    let destination_str = format!("{} ({})", &arguments.destination, destination_ip);
    println!("PRING {} {} bytes of data.", &destination_str, payload_size);

    let mut tx_count = 0;
    let mut rx_count = 0;
    let mut rtt_usec_min = u128::MAX;
    let mut rtt_usec_max = 0;
    let mut rtt_usec_moving_avg = 0.0;
    let mut rtt_usec_moving_std_dev = 0.0;

    let ping_run = time::Instant::now();

    for i in 0..packet_count {
        debug!("Sending packet: {}", i);

        let (rx_length, sequence_number, ping_rtt) = match transport_protocol {
            TransportProtocol::Ipv4(_) => {
                let _ = send_icmp_v4(
                    &mut packet_tx,
                    &destination_ip,
                    (i % (u16::MAX as usize)) as u16,
                    payload_size,
                )?;
                let ping_tx_time = time::Instant::now();
                tx_count += 1;

                // receive packet
                let mut packet_rx_iter = icmp_packet_iter(&mut packet_rx);
                let (rx_packet, ping_rtt) =
                    match recv_icmp_v4(&mut packet_rx_iter, &packet_interval)? {
                        None => continue,
                        Some((rx_packet, ping_rx_time)) => (
                            rx_packet,
                            ping_rx_time.checked_duration_since(ping_tx_time).unwrap(),
                        ),
                    };

                debug!("received packet: {:?}", rx_packet);

                // check ICMP type
                let rx_buffer = match rx_packet.get_icmp_type() {
                    icmp::IcmpTypes::EchoReply => rx_packet.packet(),
                    _ => {
                        println!(
                            "From {}: {}: {}",
                            &destination_str,
                            icmp_type_to_str(rx_packet.get_icmp_type()),
                            icmp_code_to_string(
                                rx_packet.get_icmp_type(),
                                rx_packet.get_icmp_code()
                            ),
                        );
                        continue;
                    }
                };

                let icmp_echo_reply_packet =
                    icmp::echo_reply::EchoReplyPacket::new(rx_buffer).unwrap();

                (
                    icmp_echo_reply_packet.packet().len(),
                    icmp_echo_reply_packet.get_sequence_number(),
                    ping_rtt,
                )
            }
            TransportProtocol::Ipv6(_) => {
                let _ = send_icmp_v6(
                    &interface,
                    &mut packet_tx,
                    &destination_ip,
                    (i % (u16::MAX as usize)) as u16,
                    payload_size,
                )?;
                let ping_tx_time = time::Instant::now();
                tx_count += 1;

                // receive packet
                let mut packet_rx_iter = icmpv6_packet_iter(&mut packet_rx);
                let (rx_packet, ping_rtt) =
                    match recv_icmp_v6(&mut packet_rx_iter, &packet_interval)? {
                        None => continue,
                        Some((rx_packet, ping_rx_time)) => (
                            rx_packet,
                            ping_rx_time.checked_duration_since(ping_tx_time).unwrap(),
                        ),
                    };

                debug!("received packet: {:?}", rx_packet);

                // check ICMP type
                let rx_buffer = match rx_packet.get_icmpv6_type() {
                    icmpv6::Icmpv6Types::EchoReply => rx_packet.packet(),
                    _ => {
                        println!(
                            "From {}: {}: {}",
                            &destination_str,
                            icmpv6_type_to_str(rx_packet.get_icmpv6_type()),
                            icmpv6_code_to_string(
                                rx_packet.get_icmpv6_type(),
                                rx_packet.get_icmpv6_code()
                            ),
                        );
                        continue;
                    }
                };

                let sequence_number = icmpv6_echo_reply_get_sequence_number(rx_buffer);
                (rx_buffer.len() + 4, sequence_number, ping_rtt)
            }
        };

        println!(
            "{} bytes from {}: icmp_seq={} ttl={}, time={:.2} ms",
            rx_length,
            &destination_str,
            sequence_number,
            packet_ttl,
            (ping_rtt.as_micros() as f32) / 1000.0
        );
        rx_count += 1;

        rtt_usec_min = cmp::min(rtt_usec_min, ping_rtt.as_micros());
        rtt_usec_max = cmp::max(rtt_usec_max, ping_rtt.as_micros());
        rtt_usec_moving_avg = rtt_usec_moving_avg
            + (((ping_rtt.as_micros() as f32) - rtt_usec_moving_avg) / rx_count as f32);
        let std_dev = (rtt_usec_moving_avg - (ping_rtt.as_micros() as f32))
            .powf(2.0)
            .sqrt();
        rtt_usec_moving_std_dev =
            rtt_usec_moving_std_dev + ((std_dev - rtt_usec_moving_std_dev) / rx_count as f32);

        // wait for receive packet
        if i < (packet_count - 1) {
            thread::sleep(packet_interval);
        }
    }

    let ping_duration = ping_run.elapsed();

    println!("\n--- {} pring statistics ---", &arguments.destination);
    println!(
        "{} packets transmitted, {} received, {:.2}% packet loss, time {}ms",
        tx_count,
        rx_count,
        (100.0 * ((tx_count - rx_count) as f32) / (tx_count as f32)),
        ping_duration.as_millis()
    );
    println!(
        "rtt min/avg/max/mdev = {:.3}/{:.3}/{:.3}/{:.3} ms",
        (rtt_usec_min as f32) / 1000.0,
        rtt_usec_moving_avg / 1000.0,
        (rtt_usec_max as f32) / 1000.0,
        rtt_usec_moving_std_dev / 1000.0
    );
    Ok(())
}

#[derive(Debug, structopt::StructOpt)]
#[structopt(name = "pring", author)]
/// Rust based ICMP ping utility
///
struct CliArgs {
    /// Emit debug logging
    #[structopt(short, long)]
    debug: bool,

    /// Use IPv4 only.
    #[structopt(short = "-4", long)]
    ipv4_only: bool,

    /// Use IPv6 only.
    #[structopt(short = "-6", long)]
    ipv6_only: bool,

    /// Time-To-Live count.
    #[structopt(short, long, default_value = "128")]
    ttl: u8,

    /// Number of ECHO_REQUEST packets to send.
    #[structopt(short, long)]
    count: Option<usize>,

    /// Interval in seconds between sending each packet.
    #[structopt(short, long, default_value = "1.0")]
    interval: f32,

    /// Source interface name to use for sending packets.
    #[structopt(short = "-I", long)]
    interface: Option<String>,

    /// Destination host
    destination: String,

    /// Packet paylod size
    #[structopt(short = "-s", long, default_value = "56")]
    payload_size: usize,
}
