import ipaddress as ip

def divide(network, prefix):
    network = ip.IPv4Network(network)
    return list(network.subnets(new_prefix=prefix))
