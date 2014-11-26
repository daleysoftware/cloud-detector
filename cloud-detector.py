import pyshark

# TODO take this as a param.
capture = pyshark.LiveCapture(interface='en0')

# TODO should we do a lookup on the servers we know about already? Yes.
for packet in capture.sniff_continuously():
    if packet.highest_layer == 'DNS':
        # Layers.
        layer_eth = packet.layers[0]
        layer_ip  = packet.layers[1]
        layer_dns = packet.layers[-1]

        # Ethernet src/dst.
        eth_src = layer_eth.get_field_value('eth.src')
        eth_dst = layer_eth.get_field_value('eth.dst')

        # IP src/dst.
        ip_src = layer_ip.get_field_value('ip.src')
        ip_dst = layer_ip.get_field_value('ip.dst')

        # DNS query host.
        dns_name = layer_dns.get_field_value('dns.qry.name')
        dns_id = layer_dns.get_field_value('dns.id')

        print 'DNS QUERY %s %s (%s @ %s => %s @ %s)' % (dns_id, dns_name, eth_src, ip_src, eth_dst, ip_dst)
        # TODO finish this.
    else:
        # Check if the query is going to a bad server that we already know about.
        # TODO finish this.
        pass