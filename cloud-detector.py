import pyshark
import sys
import colorama

if len(sys.argv) != 2:
    print("Usage: python3 %s <interface>" % sys.argv[0])
    sys.exit(1)

# TODO format properly for good search.
PUBLIC_CLOUD_DNS_NAMES = dict([
    ('DROPBOX', 'dropbox.com'),
    ('BOX', 'box.com'),
    ('SUGARSYNC', 'sugarsync.com'),
    ('ICLOUD', 'icloud'),
    ('GOOGLE DRIVE', 'drive.google.com'),
    ('ONE DRIVE', 'onedrive.live.com')
])

dns_capture = pyshark.LiveCapture(
    bpf_filter='port 53', # DNS is on port 53.
    display_filter='dns.flags.response eq 0', # DNS requests only.
    interface=sys.argv[1])

for packet in dns_capture.sniff_continuously():
    print('DNS QUERY %s (IP=%s MAC=%s)' % (packet.dns.qry_name, packet.ip.src, packet.eth.src))
