import threading

# Save result
results = {
    #Layer 7
    "success": 0, 
    "fail": 0, 
    "details": {},
    #Layer 3/4
    "packets_sent": 0,
    "bytes_sent": 0
}

# Ip found in check-dns
resolved_ip_details = {}

# Save search results
origin_results = {
    "cdn_ips": [],
    "methods": {}
}

results_lock = threading.Lock()
