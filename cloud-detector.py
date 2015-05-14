import pyshark
import collections
import tabulate
import trollius

public_cloud_domains = [
    "dropbox.com",
    "box.com",
    "sugarsync.com",
    "icloud.com",
    "drive.google.com",
    "onedrive.live.com",
]

display_filters = "dns.flags.response eq 0 and " + \
                  " or ".join(["dns.qry.name matches \"" + d + "\"" for d in public_cloud_domains])

dns_capture = pyshark.LiveCapture(
    interface='any',
    display_filter=display_filters)

domain_to_ip_to_count = collections.defaultdict(lambda : collections.defaultdict(int))

def print_callback(packet):
    src = packet.ip.src
    domain = packet.dns.qry_name
    print "DNS Query: %s (src: %s)" % (domain, src)
    domain_to_ip_to_count[domain][src] += 1

try:
    dns_capture.apply_on_packets(print_callback)
except (KeyboardInterrupt, SystemExit, trollius.executor.TimeoutError):
    print
finally:
    print
    print "DNS Query Summary"
    print

    table = []

    for d in sorted(domain_to_ip_to_count.iterkeys()):
        ip_to_count = domain_to_ip_to_count[d]
        table.append([d, len(ip_to_count.keys()), sum(ip_to_count.values())])

    print tabulate.tabulate(table, headers=["Domain", "Uniques", "Total"])
