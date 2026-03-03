# Phoenix Attacks - HTTP/2 Stress Testing Attack Modules

This crate provides implementations of various HTTP/2 attack vectors for the Phoenix stress testing framework.

## Attack Modules

### 1. Rapid Reset Attack (CVE-2023-44487)
- **File**: `src/rapid_reset.rs`
- **Description**: Sends HEADERS frames followed immediately by RST_STREAM frames to overwhelm servers with minimal client resources.
- **Usage**: `RapidResetAttack::new().with_connections(10).with_rps(Some(10000))`

### 2. CONTINUATION Flood Attack (CVE-2024-27983 family)
- **File**: `src/continuation_flood.rs`
- **Description**: Sends HEADERS frame without END_HEADERS flag followed by many CONTINUATION frames, forcing servers to buffer excessive header data.
- **Usage**: `ContinuationFloodAttack::new().with_frames_per_stream(100_000).with_streams(10)`

### 3. HPACK Bomb Attack
- **File**: `src/hpack_bomb.rs`
- **Description**: Exploits HTTP/2 header compression by adding a large value to the dynamic table and referencing it many times with 1-byte indexes.
- **Usage**: `HpackBombAttack::new().with_header_value_size(4000).with_references(100_000)`

### 4. SETTINGS Flood Attack
- **File**: `src/settings_flood.rs`
- **Description**: Sends thousands of SETTINGS frames without waiting for ACKs, forcing the server to queue and acknowledge each frame.
- **Usage**: `SettingsFloodAttack::new().with_frames_per_second(10_000).with_connections(5)`

### 5. PING Flood Attack
- **File**: `src/ping_flood.rs`
- **Description**: Sends thousands of PING frames, forcing the server to respond with PING ACK frames.
- **Usage**: `PingFloodAttack::new().with_pings_per_second(5_000).with_wait_for_ack(true)`

### 6. Load Test (Legitimate)
- **File**: `src/load_test.rs`
- **Description**: Legitimate HTTP/2 load testing with coordinated omission-aware timing, latency percentiles, and error tracking.
- **Note**: Requires Rust 1.83+ due to dependencies.

## Common Interface

All attacks implement the `Attack` trait:

```rust
#[async_trait]
pub trait Attack: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    async fn run(&self, ctx: AttackContext) -> Result<AttackResult, AttackError>;
}
```

## Dependencies

- **phoenix-core**: Raw HTTP/2 connection handling and frame building
- **phoenix-metrics**: Metrics collection and aggregation
- **tokio**: Async runtime
- **bytes**: Byte buffer manipulation
- **governor**: Rate limiting
- **async-trait**: Async trait support

## Rust Version Compatibility

- **Rust 1.75.0**: All attack modules except `load_test` compile successfully
- **Rust 1.83+**: All modules compile successfully
- **LoadTest module**: Requires Rust 1.83+ due to rustls/webpki dependencies

## Building

```bash
cd phoenix-attacks
cargo build

# For Rust 1.75, disable load_test module:
# 1. Comment out `pub mod load_test;` in src/lib.rs
# 2. Comment out `pub use load_test::LoadTestAttack;` in src/lib.rs
```

## Usage Example

```rust
use phoenix_attacks::RapidResetAttack;
use phoenix_metrics::AttackMetrics;
use std::sync::Arc;
use std::time::Duration;

let attack = RapidResetAttack::new()
    .with_connections(10)
    .with_rps(Some(10000))
    .with_duration(Duration::from_secs(30));

let ctx = AttackContext {
    target: "https://example.com:443".to_string(),
    connections: 10,
    duration: Duration::from_secs(30),
    rps: Some(10000),
    metrics: Arc::new(AttackMetrics::new()),
    extra: std::collections::HashMap::new(),
};

let result = attack.run(ctx).await?;
```

## Security Notes

These attack modules are for:
- Security research and testing
- Load testing your own infrastructure
- Educational purposes

Use responsibly and only against systems you own or have explicit permission to test.