#!/usr/bin/env python3
# decoy_hunter.py

import asyncio
import sys
import argparse
import logging
import os
from typing import List

from probes import init_probes, test_tcp_port, test_udp_port

logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stderr)
logger = logging.getLogger("decoy-hunter")
logger.propagate = False

LOGO = r"""
         o                                                         o                                   o                             
        <|>                                                       <|>                                 <|>                            
        < \                                                       / >                                 < >                            
   o__ __o/    o__  __o       __o__    o__ __o     o      o       \o__ __o     o       o   \o__ __o    |        o__  __o   \o__ __o  
  /v     |    /v      |>     />  \    /v     v\   <|>    <|>       |     v\   <|>     <|>   |     |>   o__/_   /v      |>   |     |> 
 />     / \  />      //    o/        />       <\  < >    < >      / \     <\  < >     < >  / \   / \   |      />      //   / \   < > 
 \      \o/  \o    o/     <|         \         /   \o    o/       \o/     o/   |       |   \o/   \o/   |      \o    o/     \o/       
  o      |    v\  /v __o   \\         o       o     v\  /v         |     <|    o       o    |     |    o       v\  /v __o   |        
  <\__  / \    <\/> __/>    _\o__</   <\__ __/>      <\/>         / \    / \   <\__ __/>   / \   / \   <\__     <\/> __/>  / \       
                                                      /                                                                              
                                                     o                                                                               
                                                  __/>                                                                               
  Advanced Decoy Detection Toolkit by FL3FT3Z (https://github.com/toxy4ny) versus cool man s0i37 (https://github.com/s0i37/defence)
"""

def print_logo():
    print(LOGO)


async def scan_port(host: str, port: int, proto: str, timeout: int, semaphore, results):
    async with semaphore:
        if proto == "tcp":
            is_real, svc, banner, probe_used = await test_tcp_port(host, port, timeout)
        else:
            is_real, svc, banner, probe_used = await test_udp_port(host, port, timeout)

        status = "[REAL]" if is_real else "[FAKE]"
        banner_str = banner.decode('utf-8', errors='replace').strip().replace('\n', ' \\n ')[:100]
        result_line = f"{status} {port}/{proto} {'open' if is_real or banner else 'closed'} {svc} (via {probe_used}) → {banner_str}"
        
        results.append((is_real, port, proto, result_line))

async def run_scan(host: str, ports: List[int], protocols: List[str], concurrency: int, timeout: int):
    semaphore = asyncio.Semaphore(concurrency)
    results = []
    total_tasks = len(ports) * len(protocols)

    tasks = []
    for port in ports:
        for proto in protocols:
            task = scan_port(host, port, proto, timeout, semaphore, results)
            tasks.append(task)

    desc = f"Scanning {host}"
    for _ in asyncio.as_completed(tasks):
        await _

    print("\n" + "="*80)
    print("RESULTS".center(80))
    print("="*80)
    for is_real, port, proto, line in sorted(results, key=lambda x: (x[2], x[1])):
        print(line)


def parse_ports(port_str: str) -> List[int]:
    if port_str == "full":
        return list(range(1, 65536))
    elif port_str == "top10k":
        return list(range(1, 10001))
    ports = []
    for part in port_str.split(","):
        if "-" in part:
            a, b = map(int, part.split("-"))
            ports.extend(range(a, b + 1))
        else:
            ports.append(int(part))
    return sorted(set(p for p in ports if 1 <= p <= 65535))

def main():
    print_logo()
    
    parser = argparse.ArgumentParser(
        description="Detect fake services behind 'all ports open' deception",
        epilog="Example: ./decoy_hunter.py 192.168.1.10 -p 22,80,443 -sU"
    )
    parser.add_argument("host", help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="top10k",
                        help="Ports: 'top10k', 'full', or custom (e.g. 22,80,1000-2000)")
    parser.add_argument("-sU", "--udp", action="store_true", help="Also scan UDP")
    parser.add_argument("-c", "--concurrency", type=int, default=15, help="Max concurrent connections")
    parser.add_argument("-t", "--timeout", type=int, default=6, help="Timeout per probe (seconds)")
    parser.add_argument("--probe-file", default="nmap-service-probes", help="Path to nmap-service-probes")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not os.path.exists(args.probe_file):
        logger.error(f"[!] nmap-service-probes file not found at: {args.probe_file}")
        logger.error("Download it: wget https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes")
        sys.exit(1)

    init_probes(args.probe_file)

    ports = parse_ports(args.ports)
    protocols = ["tcp"]
    if args.udp:
        protocols.append("udp")

    logger.info(f"[*] Target: {args.host}")
    logger.info(f"[*] Ports: {len(ports)} ({' + UDP' if args.udp else 'TCP only'})")
    logger.info(f"[*] Concurrency: {args.concurrency} | Timeout: {args.timeout}s")
    logger.info("[*] Using full nmap-service-probes with traffic obfuscation\n")

    try:
        asyncio.run(run_scan(args.host, ports, protocols, args.concurrency, args.timeout))
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(1)

if __name__ == "__main__":
    main()
