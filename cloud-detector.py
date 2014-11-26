import pyshark
import sys
import expiringdict
import colorama

# Usage. We need an interface to sniff on.
if len(sys.argv) != 2:
    print "Usage: sudo python %s <interface>" % sys.argv[0]
    sys.exit(1)

# Some large max length, and 20 seconds should be more than enough for the DNS reply.
dns_id_cache = expiringdict.ExpiringDict(max_len=10000, max_age_seconds=20)

# TODO format properly for good search.
PUBLIC_CLOUD_DNS_NAMES = dict([
    ('DROPBOX', 'dropbox.com'),
    ('BOX', 'box.com'),
    ('SUGARSYNC', 'sugarsync.com'),
    ('ICLOUD', 'icloud'),
    ('GOOGLE DRIVE', 'drive.google.com'),
    ('ONE DRIVE', 'onedrive.live.com')
])

capture = pyshark.LiveCapture(interface=sys.argv[1])

for packet in capture.sniff_continuously():
    # Layers.
    layer_eth = packet.layers[0]
    layer_ip  = packet.layers[1]

    # Ethernet src/dst.
    eth_src = layer_eth.get_field_value('eth.src')
    eth_dst = layer_eth.get_field_value('eth.dst')

    # IP src/dst.
    ip_src = layer_ip.get_field_value('ip.src')
    ip_dst = layer_ip.get_field_value('ip.dst')

    if packet.highest_layer == 'DNS':
        # DNS layer.
        layer_dns = packet.layers[-1]

        # DNS query hostname.
        dns_name = layer_dns.get_field_value('dns.qry.name')
        dns_id = layer_dns.get_field_value('dns.id')

        # Ignore DNS packet if the DNS transaction ID is in our expiring cache. This is the DNS
        # reply.
        if dns_id in dns_id_cache:
            continue

        dns_id_cache[dns_id] = dns_name
        print 'DNS QUERY %s (SRC IP=%s MAC=%s)' % (dns_name, ip_src, eth_src)

        # TODO finish this. Yell if it's a bad query.
    else:
        # Check if the query is going to a bad server that we already know about.

        # TODO finish this. Yell if it's a bad packet.
        # TODO potential message rate limiting for the same host. Output needs to be useful.
        pass