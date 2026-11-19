use crate::packet::PacketRecord;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineBucket {
    pub bucket_index: usize,
    pub timestamp_sec: f64,
    pub timestamp_iso: String,
    pub packet_count: u32,
    pub byte_count: u64,
    pub tcp_bytes: u64,
    pub udp_bytes: u64,
    pub other_bytes: u64,
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineAnalysis {
    pub bucket_resolution_seconds: f64,
    pub buckets: Vec<TimelineBucket>,
    pub max_pps: f64,
    pub max_bps: f64,
}

pub struct TimelineAggregator {
    // Map of bucket timestamp (as integer seconds or interval) to accumulated data
    buckets: BTreeMap<i64, (u32, u64, u64, u64, String)>, // (pkts, tcp_bytes, udp_bytes, other_bytes, iso)
    min_ts_sec: f64,
    max_ts_sec: f64,
    bucket_size_sec: f64,
}

impl TimelineAggregator {
    pub fn new(bucket_size_sec: f64) -> Self {
        Self {
            buckets: BTreeMap::new(),
            min_ts_sec: f64::MAX,
            max_ts_sec: 0.0,
            bucket_size_sec: if bucket_size_sec <= 0.0 {
                1.0
            } else {
                bucket_size_sec
            },
        }
    }

    pub fn process_packet(&mut self, pkt: &PacketRecord) {
        let ts_sec = if let Some(ns) = pkt.timestamp_ns {
            ns as f64 / 1_000_000_000.0
        } else {
            0.0
        };

        if ts_sec < self.min_ts_sec {
            self.min_ts_sec = ts_sec;
        }
        if ts_sec > self.max_ts_sec {
            self.max_ts_sec = ts_sec;
        }

        let bucket_key = (ts_sec / self.bucket_size_sec).floor() as i64;
        let bytes = pkt.captured_length as u64;

        let entry =
            self.buckets
                .entry(bucket_key)
                .or_insert((0, 0, 0, 0, pkt.timestamp_iso.clone()));
        entry.0 += 1;

        match pkt.transport_protocol.as_deref() {
            Some("TCP") => entry.1 += bytes,
            Some("UDP") => entry.2 += bytes,
            _ => entry.3 += bytes,
        }
    }

    pub fn finalize(self) -> TimelineAnalysis {
        let mut buckets = Vec::new();
        let mut max_pps = 0.0;
        let mut max_bps = 0.0;

        for (idx, (k, (pkts, tcp_b, udp_b, other_b, iso))) in self.buckets.into_iter().enumerate() {
            let total_b = tcp_b + udp_b + other_b;
            let pps = pkts as f64 / self.bucket_size_sec;
            let bps = (total_b as f64 * 8.0) / self.bucket_size_sec;

            if pps > max_pps {
                max_pps = pps;
            }
            if bps > max_bps {
                max_bps = bps;
            }

            buckets.push(TimelineBucket {
                bucket_index: idx,
                timestamp_sec: (k as f64) * self.bucket_size_sec,
                timestamp_iso: iso,
                packet_count: pkts,
                byte_count: total_b,
                tcp_bytes: tcp_b,
                udp_bytes: udp_b,
                other_bytes: other_b,
                packets_per_second: pps,
                bytes_per_second: bps,
            });
        }

        TimelineAnalysis {
            bucket_resolution_seconds: self.bucket_size_sec,
            buckets,
            max_pps,
            max_bps,
        }
    }
}
