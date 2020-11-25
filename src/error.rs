//
// Copyright (C) 2020 Curt Brune <curt@brune.net>
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::net::IpAddr;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("No default interface found")]
    NoDefaultInterfaceFound,

    #[error("No IPv4 address found for host: {0}")]
    NoIpv4AddressFound(String),

    #[error("No IPv6 address found for host: {0}")]
    NoIpv6AddressFound(String),

    #[error("Unable to create IPv4 packet with size: {0}")]
    Ipv4PacketCreateFailed(usize),

    #[error("Unable to create IPv6 packet with size: {0}")]
    Ipv6PacketCreateFailed(usize),

    #[error("Timeout waiting for packet from : {0}")]
    PingResponseTimeout(IpAddr),

    #[error("No IPv6 source address found for interface: {0}")]
    NoIpv6SourceIpFound(String),
}
