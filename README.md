# hyperoptic_zte_exporter

Prometheus exporter for ZXHN H298A devices.
Only tested with Hyperoptic firmware.

## Running

### Building from source

```shell script
git clone https://github.com/cheahjs/hyperoptic_zte_exporter.git
cd hyperoptic_zte_exporter
go build -o hyperoptic_zte_exporter github.com/cheahjs/hyperoptic_zte_exporter/cmd/hyperoptic_zte_exporter
ROUTER_PASSWORD=password ./hyperoptic_zte_exporter -username=admin -host=http://192.168.1.1 -listen-addr=:23466
```

### Docker

```shell script
docker run -e "ROUTER_PASSWORD=password" -p 23466:23466 deathmax/hyperoptic_zte_exporter -username=admin -host=http://192.168.1.1 -listen-addr=:23466
```

## Exported Metrics

```
# HELP zte_wan_rx_bytes Total bytes received on WAN interface
# TYPE zte_wan_rx_bytes counter
# HELP zte_wan_rx_packets Total packets received on WAN interface
# TYPE zte_wan_rx_packets counter
# HELP zte_wan_tx_bytes Total bytes sent on WAN interface
# TYPE zte_wan_tx_bytes counter
# HELP zte_wan_tx_packets Total packets sent on WAN interface
# TYPE zte_wan_tx_packets counter
# HELP zte_wan_up Shows if the WAN interface is currently up
# TYPE zte_wan_up gauge
# HELP zte_lan_rx_bytes Total bytes received on LAN interfaces
# TYPE zte_lan_rx_bytes counter
# HELP zte_lan_rx_packets Total packets received on LAN interfaces
# TYPE zte_lan_rx_packets counter
# HELP zte_lan_tx_bytes Total bytes sent on LAN interfaces
# TYPE zte_lan_tx_bytes counter
# HELP zte_lan_tx_packets Total packets sent on LAN interfaces
# TYPE zte_lan_tx_packets counter
# HELP zte_lan_link_speed_mbps Current link speed of interface in Mbps
# TYPE zte_lan_link_speed_mbps counter
```
