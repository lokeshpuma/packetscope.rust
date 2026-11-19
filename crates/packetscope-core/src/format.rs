use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endianness {
    Big,
    Little,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimestampPrecision {
    Microsecond,
    Nanosecond,
    Other(u8),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureFormat {
    Pcap {
        endianness: Endianness,
        precision: TimestampPrecision,
        major_version: u16,
        minor_version: u16,
        snaplen: u32,
        network: u32,
    },
    PcapNg {
        endianness: Endianness,
        section_count: usize,
        interface_count: usize,
    },
    Unknown,
}

impl CaptureFormat {
    pub fn name(&self) -> &'static str {
        match self {
            CaptureFormat::Pcap { .. } => "PCAP",
            CaptureFormat::PcapNg { .. } => "PCAPNG",
            CaptureFormat::Unknown => "Unknown",
        }
    }

    pub fn is_supported(&self) -> bool {
        !matches!(self, CaptureFormat::Unknown)
    }
}

pub fn detect_format(data: &[u8]) -> CaptureFormat {
    if data.len() < 4 {
        return CaptureFormat::Unknown;
    }

    let magic = [data[0], data[1], data[2], data[3]];

    // Check PCAPNG Section Header Block magic (\n\r\r\n = 0x0A, 0x0D, 0x0D, 0x0A)
    if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
        let endianness = if data.len() >= 12 {
            let bom = [data[8], data[9], data[10], data[11]];
            if bom == [0x1a, 0x2b, 0x3c, 0x4d] {
                Endianness::Little
            } else if bom == [0x4d, 0x3c, 0x2b, 0x1a] {
                Endianness::Big
            } else {
                Endianness::Little
            }
        } else {
            Endianness::Little
        };
        return CaptureFormat::PcapNg {
            endianness,
            section_count: 1,
            interface_count: 1,
        };
    }

    // Check PCAP magic numbers
    let (endianness, precision) = match magic {
        // Microsecond standard
        [0xd4, 0xc3, 0xb2, 0xa1] => (Endianness::Little, TimestampPrecision::Microsecond),
        [0xa1, 0xb2, 0xc3, 0xd4] => (Endianness::Big, TimestampPrecision::Microsecond),
        // Nanosecond standard
        [0x4d, 0x3c, 0xb2, 0xa1] => (Endianness::Little, TimestampPrecision::Nanosecond),
        [0xa1, 0xb2, 0x3c, 0x4d] => (Endianness::Big, TimestampPrecision::Nanosecond),
        _ => return CaptureFormat::Unknown,
    };

    if data.len() >= 24 {
        let read_u16 = |offset: usize| -> u16 {
            if endianness == Endianness::Little {
                u16::from_le_bytes([data[offset], data[offset + 1]])
            } else {
                u16::from_be_bytes([data[offset], data[offset + 1]])
            }
        };

        let read_u32 = |offset: usize| -> u32 {
            if endianness == Endianness::Little {
                u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ])
            } else {
                u32::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ])
            }
        };

        let major_version = read_u16(4);
        let minor_version = read_u16(6);
        let snaplen = read_u32(16);
        let network = read_u32(20);

        CaptureFormat::Pcap {
            endianness,
            precision,
            major_version,
            minor_version,
            snaplen,
            network,
        }
    } else {
        CaptureFormat::Unknown
    }
}
