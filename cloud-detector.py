import pyshark
import re

from trollius.executor import TimeoutError

CNAME_DROPBOX = 'DROPBOX'
CNAME_BOX = 'BOX'
CNAME_SUGARSYNC = 'SUGARSYNC'
CNAME_ICLOUD = 'ICLOUD'
CNAME_GOOGLE = 'GOOGLE DRIVE'
CNAME_ONE = 'ONE DRIVE'

PUBLIC_CLOUD_DNS_NAMES = dict([
    (CNAME_DROPBOX, 'dropbox.com'),
    (CNAME_BOX, 'box.com'),
    (CNAME_SUGARSYNC, 'sugarsync.com'),
    (CNAME_ICLOUD, 'icloud.com'),
    (CNAME_GOOGLE, 'drive.google.com'),
    (CNAME_ONE, 'onedrive.live.com')
])


def init_dict_count():
    return {key: 0 for key in PUBLIC_CLOUD_DNS_NAMES}


'''
Setting Filter Parameters
interface: none
bpf_filter: port 53 for DNS
display_filter: retrieve request lookup, more specifically for dropbox.com namespaces
'''

interfaces = None
# bpf_filters = port 53'
display_filters = 'eth.type != 0x86dd and dns.flags.response eq 0 and dns.qry.name matches "dropbox.com" or dns.qry.name matches "box.com" or dns.qry.name matches "sugarsync.com" or dns.qry.name matches "icloud.com" or dns.qry.name matches "drive.google.com" or dns.qry.name matches "onedrive.live.com"'

#
# filter_string = []
# for key in PUBLIC_CLOUD_DNS_NAMES:
# if filter_string:
# filter_string.append(" || ")
#     filter_string.append('dns matches "(?i)')
#     filter_string.append(PUBLIC_CLOUD_DNS_NAMES[key] + '"')

# filter_s = ''.join(filter_string)
# print filter_s


dns_capture = pyshark.LiveCapture(
    interface=interfaces,
    display_filter=display_filters)

uniq_ips = {}  # dictionary look up for unique ips


def print_callback(packet):
    print('TIME ACCESSED: %s --- DNS QUERY: %s --- (SRC IP: %s)' % (packet.frame_info.time,
                                                                    packet.dns.qry_name,
                                                                    packet.ip.src))

    if packet.ip.src not in uniq_ips:
        uniq_ips[packet.ip.src] = init_dict_count()

    if re.match(".*dropbox.*", packet.dns.qry_name, re.IGNORECASE):
        uniq_ips[packet.ip.src][CNAME_DROPBOX] += 1
    elif re.match(".*box.*", packet.dns.qry_name, re.IGNORECASE):
        uniq_ips[packet.ip.src][CNAME_BOX] += 1
    elif re.match(".*sugarsync.*", packet.dns.qry_name, re.IGNORECASE):
        uniq_ips[packet.ip.src][CNAME_SUGARSYNC] += 1
    elif re.match(".*icloud.*", packet.dns.qry_name, re.IGNORECASE):
        uniq_ips[packet.ip.src][CNAME_ICLOUD] += 1
    elif re.match(".*drive\.google.*", packet.dns.qry_name, re.IGNORECASE):
        uniq_ips[packet.ip.src][CNAME_GOOGLE] += 1
    elif re.match(".*onedrive.*", packet.dns.qry_name, re.IGNORECASE):
        uniq_ips[packet.ip.src][CNAME_ONE] += 1


try:
    dns_capture.apply_on_packets(print_callback)
except (KeyboardInterrupt, SystemExit, TimeoutError):
    print "Exiting..."
finally:
    print "\nSummary Report:"
    print "{:<20} {:<12} {:<8} {:<14} {:<17} {:<11} {:<14}".format('IP Address', 'Dropbox Hits', 'Box HITS',
                                                                   'SugarSync Hits', 'Google Drive Hits', 'ICloud Hits',
                                                                   'One Drive Hits')
    for k, v in uniq_ips.iteritems():
        print "{:<20} {:>12} {:>8} {:>14} {:>17} {:>11} {:>14}".format(k, v[CNAME_DROPBOX], v[CNAME_BOX],
                                                                       v[CNAME_SUGARSYNC], v[CNAME_GOOGLE],
                                                                       v[CNAME_ICLOUD], v[CNAME_ONE])

