//
// Copyright (C) 2020 Curt Brune <curt@brune.net>
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused)]
mod bindgen_wrapper {
    include!(concat!(env!("OUT_DIR"), "/bindgen_wrapper.rs"));
}

mod error;

use std::io::Cursor;
use std::net::IpAddr;
use std::time;

pub use error::AppError;
pub use pnet::datalink::NetworkInterface;

use anyhow::Context;
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use log::debug;
use pnet::datalink;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::{icmp, icmpv6};
use pnet::packet::{Packet, PrimitiveValues};
use pnet::transport::{
    IcmpTransportChannelIterator, Icmpv6TransportChannelIterator, TransportSender,
};

pub fn get_interface(maybe_interface: Option<String>) -> Result<NetworkInterface, AppError> {
    let interfaces = datalink::interfaces();
    match maybe_interface {
        Some(user_interface) => interfaces
            .iter()
            .find(|iface| iface.name == user_interface)
            .map(|iface| iface.to_owned())
            .ok_or(AppError::InterfaceNotFound(user_interface)),
        None => interfaces
            .iter()
            .find(|e| e.is_up() && !e.is_loopback() && e.ips.len() > 0)
            .map(|iface| iface.to_owned())
            .ok_or(AppError::NoDefaultInterfaceFound),
    }
}

// ICMP types
use bindgen_wrapper::{
    ICMP_ADDRESS, ICMP_ADDRESSREPLY, ICMP_DEST_UNREACH, ICMP_ECHO, ICMP_ECHOREPLY, ICMP_INFO_REPLY,
    ICMP_INFO_REQUEST, ICMP_PARAMETERPROB, ICMP_REDIRECT, ICMP_SOURCE_QUENCH, ICMP_TIMESTAMP,
    ICMP_TIMESTAMPREPLY, ICMP_TIME_EXCEEDED,
};

// ICMP unreachable codes
use bindgen_wrapper::{
    ICMP_FRAG_NEEDED, ICMP_HOST_ANO, ICMP_HOST_ISOLATED, ICMP_HOST_UNKNOWN, ICMP_HOST_UNREACH,
    ICMP_HOST_UNR_TOS, ICMP_NET_ANO, ICMP_NET_UNKNOWN, ICMP_NET_UNREACH, ICMP_NET_UNR_TOS,
    ICMP_PKT_FILTERED, ICMP_PORT_UNREACH, ICMP_PREC_CUTOFF, ICMP_PREC_VIOLATION, ICMP_PROT_UNREACH,
    ICMP_SR_FAILED,
};

// ICMP redirect codes
use bindgen_wrapper::{ICMP_REDIR_HOST, ICMP_REDIR_HOSTTOS, ICMP_REDIR_NET, ICMP_REDIR_NETTOS};

// ICMP time exceeded codes
use bindgen_wrapper::{ICMP_EXC_FRAGTIME, ICMP_EXC_TTL};

pub fn icmp_type_to_str(icmp_type: icmp::IcmpType) -> &'static str {
    let (icmp_type,) = icmp_type.to_primitive_values();
    match icmp_type as u32 {
        ICMP_ADDRESS => "AddressMaskRequest",
        ICMP_ADDRESSREPLY => "AddressMaskReply",
        ICMP_DEST_UNREACH => "DestinationUnreachable",
        ICMP_ECHO => "EchoRequest",
        ICMP_ECHOREPLY => "EchoReply",
        ICMP_INFO_REPLY => "InfoReply",
        ICMP_INFO_REQUEST => "InfoRequest",
        ICMP_PARAMETERPROB => "ParameterProblem",
        ICMP_REDIRECT => "Redirect",
        ICMP_SOURCE_QUENCH => "SourceQuench",
        ICMP_TIMESTAMP => "Timestamp",
        ICMP_TIMESTAMPREPLY => "TimestampReply",
        ICMP_TIME_EXCEEDED => "TimeExceeded",
        _ => unreachable!(),
    }
}

pub fn icmp_code_to_string(icmp_type: icmp::IcmpType, icmp_code: icmp::IcmpCode) -> String {
    let (icmp_type,) = icmp_type.to_primitive_values();
    let (icmp_code,) = icmp_code.to_primitive_values();

    match icmp_type as u32 {
        ICMP_ADDRESS | ICMP_ADDRESSREPLY | ICMP_ECHO | ICMP_ECHOREPLY | ICMP_INFO_REPLY
        | ICMP_INFO_REQUEST | ICMP_PARAMETERPROB | ICMP_TIMESTAMP | ICMP_TIMESTAMPREPLY
        | ICMP_SOURCE_QUENCH => format!("IcmpCode({})", icmp_type),
        ICMP_DEST_UNREACH => match icmp_code as u32 {
            ICMP_FRAG_NEEDED => "Fragmentation is needed and Don't Fragment was set",
            ICMP_HOST_ANO => "Communication with destination host is administratively prohibited",
            ICMP_HOST_ISOLATED => "Source host is isolated",
            ICMP_HOST_UNKNOWN => "Destination host is unknown",
            ICMP_HOST_UNREACH => "Host is unreachable",
            ICMP_HOST_UNR_TOS => "Destination host is unreachable for type of service",
            ICMP_NET_ANO => "Communication with destination network is administratively prohibited",
            ICMP_NET_UNKNOWN => "Destination network is unknown",
            ICMP_NET_UNREACH => "Net is unreachable",
            ICMP_NET_UNR_TOS => "Destination network is unreachable for type of service",
            ICMP_PKT_FILTERED => "Communication is administratively prohibited",
            ICMP_PORT_UNREACH => "Port is unreachable",
            ICMP_PREC_CUTOFF => "Precedence cutoff is in effect",
            ICMP_PREC_VIOLATION => "Host precedence violation",
            ICMP_PROT_UNREACH => "Protocol is unreachable",
            ICMP_SR_FAILED => "Source route failed",
            _ => unreachable!(),
        }
        .to_owned(),
        ICMP_REDIRECT => match icmp_code as u32 {
            ICMP_REDIR_HOST => "Redirect datagram for the host",
            ICMP_REDIR_HOSTTOS => "Redirect datagram for the type of service and host",
            ICMP_REDIR_NET => "Redirect datagram for the network",
            ICMP_REDIR_NETTOS => "Redirect datagram for the type of service and network",
            _ => unreachable!(),
        }
        .to_owned(),
        ICMP_TIME_EXCEEDED => match icmp_code as u32 {
            ICMP_EXC_FRAGTIME => "Fragment reassembly time exceeded",
            ICMP_EXC_TTL => "Time to Live exceeded in transit",
            _ => unreachable!(),
        }
        .to_owned(),
        _ => unreachable!(),
    }
}

pub fn send_icmp_v4(
    sender: &mut TransportSender,
    destination: &IpAddr,
    sequence_number: u16,
    payload_size: usize,
) -> Result<(), anyhow::Error> {
    // create packet
    let packet_size =
        icmp::echo_request::MutableEchoRequestPacket::minimum_packet_size() + payload_size;
    let mut payload = vec![0; packet_size];
    let mut packet = icmp::echo_request::MutableEchoRequestPacket::new(&mut payload)
        .ok_or(AppError::Ipv4PacketCreateFailed(packet_size))?;

    packet.set_icmp_type(pnet::packet::icmp::IcmpTypes::EchoRequest);
    packet.set_sequence_number(sequence_number);

    let checksum = {
        let icmp_packet = icmp::IcmpPacket::new(packet.packet()).unwrap();
        icmp::checksum(&icmp_packet)
    };
    packet.set_checksum(checksum);

    debug!("sending packet: {:?}", packet);

    // send packet
    let _ = sender
        .send_to(packet, *destination)
        .with_context(|| format!("Send packet failed for destination: {:?}", destination))?;
    Ok(())
}

pub fn recv_icmp_v4<'a>(
    receive_iter: &'a mut IcmpTransportChannelIterator,
    receive_timeout: &time::Duration,
) -> Result<Option<(IcmpPacket<'a>, time::Instant)>, anyhow::Error> {
    match receive_iter
        .next_with_timeout(*receive_timeout)
        .with_context(|| format!("Error receiving packets"))?
    {
        Some((rx_packet, _)) => return Ok(Some((rx_packet, time::Instant::now()))),
        None => return Ok(None),
    };
}

pub fn send_icmp_v6(
    interface: &NetworkInterface,
    sender: &mut TransportSender,
    destination: &IpAddr,
    sequence_number: u16,
    payload_size: usize,
) -> Result<(), anyhow::Error> {
    // create packet
    let packet_size = icmpv6::MutableIcmpv6Packet::minimum_packet_size() + payload_size;
    let mut payload = vec![0; packet_size];

    let mut packet_sequence_number = Vec::new();
    packet_sequence_number
        .write_u16::<NetworkEndian>(sequence_number)
        .unwrap();
    payload[7..9].clone_from_slice(&packet_sequence_number);

    let mut packet = icmpv6::MutableIcmpv6Packet::new(&mut payload)
        .ok_or(AppError::Ipv6PacketCreateFailed(packet_size))?;

    packet.set_icmpv6_type(pnet::packet::icmpv6::Icmpv6Types::EchoRequest);

    let checksum = {
        let icmpv6_packet = icmpv6::Icmpv6Packet::new(packet.packet()).unwrap();
        let source_ip = interface
            .ips
            .iter()
            .find(|entry| entry.is_ipv6())
            .map(|ip| ip.ip())
            .ok_or(AppError::NoIpv6SourceIpFound(interface.name.to_owned()))?;
        let src_ip = match source_ip {
            IpAddr::V6(src_ip) => src_ip,
            _ => unreachable!(),
        };
        let dest_ip = match destination {
            IpAddr::V6(dest_ip) => dest_ip,
            _ => unreachable!(),
        };
        icmpv6::checksum(&icmpv6_packet, &src_ip, &dest_ip)
    };
    packet.set_checksum(checksum);

    debug!("sending packet: {:?}", packet);

    // send packet
    let _ = sender
        .send_to(packet, *destination)
        .with_context(|| format!("Send packet failed for destination: {:?}", destination))?;
    Ok(())
}

pub fn recv_icmp_v6<'a>(
    receive_iter: &'a mut Icmpv6TransportChannelIterator,
    receive_timeout: &time::Duration,
) -> Result<Option<(Icmpv6Packet<'a>, time::Instant)>, anyhow::Error> {
    match receive_iter
        .next_with_timeout(*receive_timeout)
        .with_context(|| format!("Error receiving packets"))?
    {
        Some((rx_packet, _)) => return Ok(Some((rx_packet, time::Instant::now()))),
        None => return Ok(None),
    };
}

// ICMPv6 types
use bindgen_wrapper::{
    ICMPV6_DEST_UNREACH, ICMPV6_ECHO_REPLY, ICMPV6_ECHO_REQUEST, ICMPV6_PARAMPROB,
    ICMPV6_PKT_TOOBIG, ICMPV6_TIME_EXCEED,
};

// ICMPv6 dest unreachable codes
use bindgen_wrapper::{
    ICMPV6_ADDR_UNREACH, ICMPV6_ADM_PROHIBITED, ICMPV6_NOROUTE, ICMPV6_NOT_NEIGHBOUR,
    ICMPV6_POLICY_FAIL, ICMPV6_PORT_UNREACH, ICMPV6_REJECT_ROUTE,
};

// ICMPv6 parameter problem
use bindgen_wrapper::{ICMPV6_HDR_FIELD, ICMPV6_UNK_NEXTHDR, ICMPV6_UNK_OPTION};

// ICMPv6 time exceeded codes
use bindgen_wrapper::{ICMPV6_EXC_FRAGTIME, ICMPV6_EXC_HOPLIMIT};

pub fn icmpv6_type_to_str(icmp_type: icmpv6::Icmpv6Type) -> String {
    let (icmp_type,) = icmp_type.to_primitive_values();
    match icmp_type as u32 {
        ICMPV6_DEST_UNREACH => "DestinationUnreachable".to_owned(),
        ICMPV6_ECHO_REQUEST => "EchoRequest".to_owned(),
        ICMPV6_ECHO_REPLY => "EchoReply".to_owned(),
        ICMPV6_PARAMPROB => "ParameterProblem".to_owned(),
        ICMPV6_PKT_TOOBIG => "PacketTooBig".to_owned(),
        ICMPV6_TIME_EXCEED => "TimeExceeded".to_owned(),
        _ => format!("Unknown type: {}", icmp_type),
    }
}

pub fn icmpv6_code_to_string(
    icmp_type: icmpv6::Icmpv6Type,
    icmp_code: icmpv6::Icmpv6Code,
) -> String {
    let (icmp_type,) = icmp_type.to_primitive_values();
    let (icmp_code,) = icmp_code.to_primitive_values();

    match icmp_type as u32 {
        ICMPV6_ECHO_REQUEST | ICMPV6_ECHO_REPLY | ICMPV6_PKT_TOOBIG => {
            format!("Icmpv6Code({})", icmp_type)
        }
        ICMPV6_DEST_UNREACH => match icmp_code as u32 {
            ICMPV6_ADDR_UNREACH => "Address is unreachable",
            ICMPV6_ADM_PROHIBITED => "Communication is administratively prohibited",
            ICMPV6_PORT_UNREACH => "Port is unreachable",
            ICMPV6_NOROUTE => "No route to destination",
            ICMPV6_NOT_NEIGHBOUR => "Destination is not a neighbor",
            ICMPV6_POLICY_FAIL => "Policy failed",
            ICMPV6_REJECT_ROUTE => "Route rejected",
            _ => unreachable!(),
        }
        .to_owned(),
        ICMPV6_PARAMPROB => match icmp_code as u32 {
            ICMPV6_HDR_FIELD => "Erroneous header field encountered",
            ICMPV6_UNK_NEXTHDR => "Unrecognized next header type encountered",
            ICMPV6_UNK_OPTION => "Unrecognized IPv6 option encountered",
            _ => unreachable!(),
        }
        .to_owned(),
        ICMPV6_TIME_EXCEED => match icmp_code as u32 {
            ICMPV6_EXC_FRAGTIME => "Exceeded fragment reassembly time",
            ICMPV6_EXC_HOPLIMIT => "Exceeded hop limit",
            _ => unreachable!(),
        }
        .to_owned(),
        _ => format!("Unknown type: {}, code: {}", icmp_type, icmp_code),
    }
}

pub fn icmpv6_echo_reply_get_sequence_number(packet: &[u8]) -> u16 {
    let seq_number = vec![packet[7], packet[8]];
    let mut reader = Cursor::new(seq_number);
    reader.read_u16::<NetworkEndian>().unwrap()
}
