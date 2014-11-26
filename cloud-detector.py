import pyshark

# TODO format properly for good search. Finish this.
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
    display_filter='eth.type != 0x86dd and dns.flags.response eq 0') # IPv4 only; DNS requests only.

def print_callback(packet):
    print('DNS QUERY %s (IP=%s)' % (packet.dns.qry_name, packet.ip.src))

dns_capture.apply_on_packets(print_callback)
