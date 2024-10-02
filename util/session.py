from scapy.all import Packet


def session_extractor(p: Packet) -> str:
    """Extract sessions from packets"""
    if 'Ether' in p:
        if 'IP' in p or 'IPv6' in p:
            ip_src_fmt = "{IP:%IP.src%}{IPv6:%IPv6.src%}"
            ip_dst_fmt = "{IP:%IP.dst%}{IPv6:%IPv6.dst%}"
            if 'TCP' in p:
                ips = sorted([p.sprintf(f"{ip_src_fmt}:%r,TCP.sport%"),
                              p.sprintf(f"{ip_dst_fmt}:%r,TCP.dport%")])
                return f"TCP-{ips[0]}-{ips[1]}"
            elif 'UDP' in p:
                ips = sorted([p.sprintf(f"{ip_src_fmt}:%r,UDP.sport%"),
                              p.sprintf(f"{ip_dst_fmt}:%r,UDP.dport%")])
                return f"UDP-{ips[0]}-{ips[1]}"
            elif 'HTTP' in p:
                pass
            elif 'ICMP' in p:
                ips = sorted([p.sprintf(f"{ip_src_fmt}"),
                              p.sprintf(f"{ip_dst_fmt}")])
                fmt = f"ICMP-{ips[0]}-{ips[1]} type=%r,ICMP.type% code=%r," \
                      "ICMP.code% id=%ICMP.id%"
                return p.sprintf(fmt)
            elif 'ICMPv6' in p:
                ips = sorted([p.sprintf(f"{ip_src_fmt}"),
                              p.sprintf(f"{ip_dst_fmt}")])
                fmt = f"ICMPv6-{ips[0]} > {ips[1]} type=%r,ICMPv6.type% " \
                      "code=%r,ICMPv6.code%"
                return p.sprintf(fmt)
            elif 'IPv6' in p:
                ips = sorted([p.sprintf(f"{ip_src_fmt}"),
                              p.sprintf(f"{ip_dst_fmt}")])
                fmt = f"IPv6-{ips[0]}-{ips[1]} nh=%IPv6.nh%"
                return p.sprintf(fmt)
            else:
                ips = sorted([p.sprintf(f"{ip_src_fmt}"),
                              p.sprintf(f"{ip_dst_fmt}")])
                fmt = f"IP-{ips[0]}-{ips[1]} proto=%IP.proto%"
                return p.sprintf(fmt)
        elif 'ARP' in p:
            arps = sorted([p.sprintf("%ARP.psrc%"),
                           p.sprintf("%ARP.pdst%")])
            return p.sprintf(f"ARP-{arps[0]}-{arps[1]}")
        else:
            return p.sprintf("Ethernet-type=%04xr,Ether.type%")
    return "Other"
