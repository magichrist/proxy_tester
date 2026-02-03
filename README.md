# Simple Proxy Evaluation
Proxy Tester checks availability, reachability and time-quality of proxies or hosts and filters based on \
ping time.

Best for wholesome host selection.

## Config

```

PING_MAX_TIME_MS    // Ping max time tolerance in ms
PING_COUNT          // Number of sent ICMP 
PING_TIMEOUT        // Wait time in seconds
PING_THREADS        // Number of threads

NC_TIMEOUT          // Netcat timeout
NC_JOBS             // Netcat number of Jobs

TLS_TIMEOUT         // TLS Timeout
TLS_THREADS         // TLS number of threads

```
### urls.txt
add other endpoints here

### local
**make the directory**
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
```
--no-url // to skip url and test the files in *local* 
```
