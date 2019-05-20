//! # Networking
//!
//! A library for modeling networking protocols

use std::str;

pub mod types {

  pub struct MacAddress {
    pub address: [u8; 6],
  }

  impl MacAddress {
    /// Produces a new MacAddress
    pub fn new(address: [u8; 6]) -> MacAddress {
      MacAddress { address }
    }

    /// Returns the string representation of a MacAddress
    pub fn as_string(&self) -> String {
      format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        self.address[0],
        self.address[1],
        self.address[2],
        self.address[3],
        self.address[4],
        self.address[5]
      )
    }

    /// Returns a MacAddress's value as a &[u8]
    pub fn as_bytes(&self) -> &[u8] {
      &self.address
    }

    /// Returns a MacAddress's value as a u64
    pub fn as_u64(&self) -> u64 {
      u64::from_be_bytes([
        0,
        0,
        self.address[0],
        self.address[1],
        self.address[2],
        self.address[3],
        self.address[4],
        self.address[5],
      ])
    }
  }

  pub struct IPv4Address {
    pub address: [u8; 4],
  }

  impl IPv4Address {
    /// Produces a new IPv4Address
    pub fn new(address: [u8; 4]) -> IPv4Address {
      IPv4Address { address }
    }

    /// Returns the string representation of an IPv4Address
    pub fn as_string(&self) -> String {
      format!(
        "{}.{}.{}.{}",
        self.address[0], self.address[1], self.address[2], self.address[3]
      )
    }

    /// Returns an IPv4Address's value as a &[u8]
    pub fn as_bytes(&self) -> &[u8] {
      &self.address
    }

    /// Return's an IPv4Address's value as a u32
    pub fn as_u32(&self) -> u32 {
      u32::from_be_bytes([
        self.address[0],
        self.address[1],
        self.address[2],
        self.address[3],
      ])
    }
  }

  pub struct IPv6Address {
    pub address: [u8; 16],
  }

  impl IPv6Address {
    /// Produces a new IPv6Address
    pub fn new(address: [u8; 16]) -> IPv6Address {
      IPv6Address { address }
    }

    /// Returns the string representation of an IPv6Address
    pub fn as_string(&self) -> String {
      format!(
        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        ((self.address[0] as u16) << 8 | self.address[1] as u16),
        ((self.address[2] as u16) << 8 | self.address[3] as u16),
        ((self.address[4] as u16) << 8 | self.address[5] as u16),
        ((self.address[6] as u16) << 8 | self.address[7] as u16),
        ((self.address[8] as u16) << 8 | self.address[9] as u16),
        ((self.address[10] as u16) << 8 | self.address[11] as u16),
        ((self.address[12] as u16) << 8 | self.address[13] as u16),
        ((self.address[14] as u16) << 8 | self.address[15] as u16)
      )
    }

    /// Returns an IPv6Address's value as a &[u8]
    pub fn as_bytes(&self) -> &[u8] {
      &self.address
    }

    /// Returns an IPv6Address's value as a u128
    pub fn as_u128(&self) -> u128 {
      u128::from_be_bytes([
        self.address[0],
        self.address[1],
        self.address[2],
        self.address[3],
        self.address[4],
        self.address[5],
        self.address[6],
        self.address[7],
        self.address[8],
        self.address[9],
        self.address[10],
        self.address[11],
        self.address[12],
        self.address[13],
        self.address[14],
        self.address[15],
      ])
    }
  }

  /// Represents types that may populate the EtherType field in an Ethernet header
  pub struct EtherType {
    pub value: u16,
  }

  impl EtherType {
    /// Produces a new EtherType
    pub fn new(bytes: [u8; 2]) -> EtherType {
      EtherType {
        value: u16::from_be_bytes([bytes[0], bytes[1]]),
      }
    }

    /// Returns the string representation of an EtherType
    pub fn as_string(&self) -> String {
      // if value field is greater than 0x05DC (1500) this
      // is an Ethernet Version 2 frame. If less than 0x05DC,
      // this frame is IEEE 802.3 Ethernet frame.
      let eth2_cutoff = 0x05DC;

      if self.value < eth2_cutoff {
        return String::from("802.3");
      }

      match self.value {
        0x0800 => String::from("IPv4"),
        0x0806 => String::from("ARP"),
        0x8100 => String::from("VLAN"),
        0x86dd => String::from("IPv6"),
        0x8847 => String::from("MPLS"),
        _ => format!("{:02x}", self.value),
      }
    }
  }

  /// Represents a protocol type that may be listed in the protocol/next_header field of
  /// an IPv4/IPv6 header
  pub struct IPProtocolType {
    pub value: u8,
  }

  impl IPProtocolType {
    /// Produces a new IPProtocolType
    pub fn new(bytes: [u8; 1]) -> IPProtocolType {
      IPProtocolType {
        value: u8::from_be_bytes([bytes[0]]),
      }
    }

    /// Returns the string representation of an IPProtocolType
    pub fn as_string(&self) -> String {
      match self.value {
        0x00 => String::from("HOPOPT"),
        0x01 => String::from("ICMP"),
        0x02 => String::from("IGMP"),
        0x06 => String::from("TCP"),
        0x11 => String::from("UDP"),
        0x3A => String::from("IPv6-ICMP"),
        _ => format!("{:02x}", self.value),
      }
    }
  }

  /// Represents a TCP/UDP port
  pub struct TCPUDPPort {
    pub value: u16,
  }

  impl TCPUDPPort {
    /// Produces a new TCPUDPPort
    pub fn new(bytes: [u8; 2]) -> TCPUDPPort {
      TCPUDPPort {
        value: u16::from_be_bytes([bytes[0], bytes[1]]),
      }
    }

    /// Returns the string representation of a TCPUDPPort
    pub fn as_string(&self) -> String {
      match self.value {
        53 => String::from("DNS"),
        137 => String::from("NBT"),
        _ => format!("{:02}", self.value),
      }
    }
  }

  /// Represents a DNS question
  pub struct DNSQuestion<'n> {
    pub q_name_length: u8,
    pub q_name: &'n [u8],
    pub q_type: u16,
    pub q_class: u16
  }

  impl<'n> DNSQuestion<'n> {
    /// Produces a new DNSQuestion
    pub fn new(bytes: &[u8]) -> DNSQuestion {
      let q_name_length = usize::from_be_bytes([0, 0, 0, 0, 0, 0, 0, bytes[0]]);

      DNSQuestion {
        q_name_length: u8::from_be_bytes([bytes[0]]),
        q_name: &bytes[1..1 + q_name_length],
        q_type: u16::from_be_bytes([bytes[2 + q_name_length], bytes[3 + q_name_length]]),
        q_class: u16::from_be_bytes([bytes[4 + q_name_length], bytes[5 + q_name_length]])
      }
    }
  }
}

pub mod frames {
  use super::types::{EtherType, IPProtocolType, IPv4Address, IPv6Address, MacAddress, TCPUDPPort};

  pub struct EthernetFrame<'p> {
    pub dst_mac: MacAddress,
    pub src_mac: MacAddress,
    pub eth_type: EtherType,
    pub payload: &'p [u8],
  }

  impl<'p> EthernetFrame<'p> {
    /// Produces a new EthernetFrame
    pub fn new(bytes: &[u8]) -> EthernetFrame {
      EthernetFrame {
        dst_mac: MacAddress::new([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]),
        src_mac: MacAddress::new([bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11]]),
        eth_type: EtherType::new([bytes[12], bytes[13]]),
        payload: &bytes[14..],
      }
    }

    /// Returns the string representation of an EthernetFrame
    pub fn as_string(&self) -> String {
      format!(
        "ETHERNET: [{}] [{} -> {}]",
        self.eth_type.as_string(),
        self.src_mac.as_string(),
        self.dst_mac.as_string()
      )
    }

    /// Returns the EtherType contained in an EthernetFrame
    pub fn eth_type(&self) -> &EtherType {
      &self.eth_type
    }

    /// Returns the payload contained in an EthernetFrame
    pub fn payload(&self) -> &[u8] {
      self.payload
    }
  }

  pub struct IPv4Frame<'o, 'p> {
    pub version: u8,
    pub header_length: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub time_to_live: u8,
    pub protocol: IPProtocolType,
    pub header_checksum: u16,
    pub src_address: IPv4Address,
    pub dst_address: IPv4Address,
    pub options: &'o [u8],
    pub payload: &'p [u8],
  }

  impl<'o, 'p> IPv4Frame<'o, 'p> {
    /// Produces a new IPv4Frame
    pub fn new(bytes: &[u8]) -> IPv4Frame {
      let options_index = (usize::from_be_bytes([0, 0, 0, 0, 0, 0, 0, bytes[0] & 0x0F]) - 5) * 4;
      let mut payload_index = 20;
      if options_index > 0 {
        payload_index = 21;
      }

      IPv4Frame {
        version: u8::from_be_bytes([bytes[0] & 0xF0]),
        header_length: u8::from_be_bytes([bytes[0] & 0x0F]),
        dscp: u8::from_be_bytes([bytes[1] & 0xFC]),
        ecn: u8::from_be_bytes([bytes[1] & 0x03]),
        total_length: u16::from_be_bytes([bytes[2], bytes[3]]),
        identification: u16::from_be_bytes([bytes[4], bytes[5]]),
        flags: u8::from_be_bytes([bytes[6] & 0xE0]),
        fragment_offset: u16::from_be_bytes([bytes[6] & 0x1F, bytes[7]]),
        time_to_live: u8::from_be_bytes([bytes[8]]),
        protocol: IPProtocolType::new([bytes[9]]),
        header_checksum: u16::from_be_bytes([bytes[10], bytes[11]]),
        src_address: IPv4Address::new([bytes[12], bytes[13], bytes[14], bytes[15]]),
        dst_address: IPv4Address::new([bytes[16], bytes[17], bytes[18], bytes[19]]),
        options: &bytes[20..20 + options_index],
        payload: &bytes[payload_index + options_index..],
      }
    }

    /// Returns the string representation of an IPv4Frame
    pub fn as_string(&self) -> String {
      format!(
        "IPv4: [{}] [{} -> {}]",
        self.protocol.as_string(),
        self.src_address.as_string(),
        self.dst_address.as_string()
      )
    }

    /// Returns the IPProtocolType contained in an IPv4Frame
    pub fn protocol(&self) -> &IPProtocolType {
      &self.protocol
    }

    /// Returns the payload contained in an IPv4Frame
    pub fn payload(&self) -> &[u8] {
      self.payload
    }
  }

  pub struct IPv6Frame<'p> {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: IPProtocolType,
    pub hop_limit: u8,
    pub src_address: IPv6Address,
    pub dst_address: IPv6Address,
    pub payload: &'p [u8],
  }

  impl<'p> IPv6Frame<'p> {
    /// Produces a new IPv6Frame
    pub fn new(bytes: &[u8]) -> IPv6Frame {
      IPv6Frame {
        version: u8::from_be_bytes([bytes[0] & 0xF0]),
        traffic_class: u8::from_be_bytes([(bytes[0] & 0x0F) | (bytes[1] & 0xF0)]),
        flow_label: u32::from_be_bytes([0, (bytes[1] & 0x0f), bytes[2], bytes[3]]),
        payload_length: u16::from_be_bytes([bytes[4], bytes[5]]),
        next_header: IPProtocolType::new([bytes[6]]),
        hop_limit: u8::from_be_bytes([bytes[7]]),
        src_address: IPv6Address::new([
          bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
          bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]),
        dst_address: IPv6Address::new([
          bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
          bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37], bytes[38], bytes[39],
        ]),
        payload: &bytes[40..],
      }
    }

    /// Returns the string representation of an IPv6Frame
    pub fn as_string(&self) -> String {
      format!(
        "IPv6: [{}] [{} -> {}]",
        self.next_header.as_string(),
        self.src_address.as_string(),
        self.dst_address.as_string()
      )
    }

    /// Returns the IPProtocolType contained in an IPv6Frame
    pub fn next_header(&self) -> &IPProtocolType {
      &self.next_header
    }

    /// Returns the payload contained in an IPv6Frame
    pub fn payload(&self) -> &[u8] {
      self.payload
    }
  }

  pub struct UDPFrame<'p> {
    pub src_port: TCPUDPPort,
    pub dst_port: TCPUDPPort,
    pub length: u16,
    pub checksum: u16,
    pub payload: &'p [u8],
  }

  impl<'p> UDPFrame<'p> {
    /// Produces a new UDPFrame
    pub fn new(bytes: &[u8]) -> UDPFrame {
      UDPFrame {
        src_port: TCPUDPPort::new([bytes[0], bytes[1]]),
        dst_port: TCPUDPPort::new([bytes[2], bytes[3]]),
        length: u16::from_be_bytes([bytes[4], bytes[5]]),
        checksum: u16::from_be_bytes([bytes[6], bytes[7]]),
        payload: &bytes[8..],
      }
    }

    /// Returns the string representation of a UDP frame
    pub fn as_string(&self) -> String {
      format!(
        "UDP: [{}] [{} -> {}]",
        self.length,
        self.src_port.as_string(),
        self.dst_port.as_string()
      )
    }
  }

  pub struct DNSFrame {
    pub id: u16,
    pub qr: u8,
    pub opcode: u8,
    pub flags: u8,
    pub zero: u8,
    pub response_code: u8,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_record_count: u16,
    pub additional_record_count: u16,
  }

  impl DNSFrame {
    /// Produces a new DNSFrame
    pub fn new(bytes: &[u8]) -> DNSFrame {
      DNSFrame {
        id: u16::from_be_bytes([bytes[0], bytes[1]]),
        qr: u8::from_be_bytes([bytes[2] & 0x80]),
        opcode: u8::from_be_bytes([bytes[2] & 0x78]),
        flags: u8::from_be_bytes([bytes[2] & 0x07 | bytes[3] & 0x80]),
        zero: u8::from_be_bytes([bytes[3] & 0x70]),
        response_code: u8::from_be_bytes([bytes[3] & 0x0F]),
        question_count: u16::from_be_bytes([bytes[4], bytes[5]]),
        answer_count: u16::from_be_bytes([bytes[6], bytes[7]]),
        authority_record_count: u16::from_be_bytes([bytes[8], bytes[9]]),
        additional_record_count: u16::from_be_bytes([bytes[10], bytes[11]]),
      }
    }

    pub fn as_string(&self) -> String {
      format!(
        "DNS: [id: {}]"
      )
    }
  }
}
