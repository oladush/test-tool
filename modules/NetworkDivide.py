import ipaddress as ip

def divide(network, prefix):
    network = ip.IPv4Network(network)
    return list(network.subnets(new_prefix=prefix))


if __name__ == "__main__":
    print(list(divide('192.168.0.0/24', int("32"))))
    # subnet = ip.IPv4Network('192.168.0.0/24')
    #
    # # Split the subnet into smaller subnets with 30 host addresses each
    # new_subnets = list(subnet.subnets(new_prefix=25))
    #
    # # Print the new subnets
    # for new_subnet in new_subnets:
    #     print(new_subnet)
