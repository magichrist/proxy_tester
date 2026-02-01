# Simple Proxy Evaluation
This tools checks availability, reachability and time-quality of proxies or hosts and filters based on \
ping time.

Best for wholesome host selection.

## Config

```

PING_MAX_TIME_MS    // Ping max time tolerance in ms
PING_COUNT          // Number of sent ICMP 
PING_TIMEOUT=1      // Wait time in seconds
PING_THREADS=30     // Number of threads

NC_TIMEOUT=2        // Netcat timeout
NC_JOBS=30          // Netcat number of Jobs

```
### urls.txt
add other endpoints here

### local
add your proxy list files here

---
## Usage
*Easy as F*

Get it:
```
git clone https://github.com/magichrist/proxy_tester.git
cd proxy_tester
```

Run it:
```
chmod +x nc_test.sh
python start.py
```
