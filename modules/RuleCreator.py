# def json_rules(data):
#     rules = []
#     for_rule_by_ip = {}
#
#     for item in data:
#         if item['ip'] not in for_rule_by_ip:
#             for_rule_by_ip[item['ip']] = {'proto': set(), 'dport': set(), 'sport': set()}
#         for_rule_by_ip[item['ip']]['proto'].add(item['proto'])
#         for_rule_by_ip[item['ip']]['dport'] |= port_parser(item['dport'])
#         for_rule_by_ip[item['ip']]['sport'] |= port_parser(item['sport'])
#
#     for_rule_by_ip_proto = {}
#
#     for item in data:
#         if item['ip'] + '_' + item['proto'] not in for_rule_by_ip_proto:
#             for_rule_by_ip_proto[item['ip'] + '_' + item['proto']] = {'dport': set(), 'sport': set()}
#         for_rule_by_ip_proto[item['ip'] + '_' + item['proto']]['dport'] |= port_parser(item['dport'])
#         for_rule_by_ip_proto[item['ip'] + '_' + item['proto']]['sport'] |= port_parser(item['sport'])
#
#     print(for_rule_by_ip_proto)
#     print(for_rule_by_ip)
#
#     for ip_proto in for_rule_by_ip_proto:
#         rules.append(rule_by_ip_protocol(for_rule_by_ip_proto[ip_proto], ip_proto.split('_')[0], ip_proto.split('_')[1]))
#
#     for ip in for_rule_by_ip:
#         rules.append(rule_by_ip(for_rule_by_ip[ip], ip))
#
#
#
#     return rules
#
# def rule_by_ip(item, ip):
#     return [
#         f"drop dst host {ip} and not proto {', '.join(list(item['proto']))}",
#         f"drop dst host {ip} and not src port {', '.join(list(item['sport']))}",
#         f"drop dst host {ip} and not dst port {', '.join(list(item['dport']))}"
#     ]
#
# # drop dst host 8.8.8.8 and not proto udp, tcp
# # drop dst host 8.8.8.8 and not proto udp and not src port 1027..65535
# # drop dst host 8.8.8.8 and not proto udp and not dst port 80, 443, 1024..65535
# # drop dst host 8.8.8.8 and not proto tcp and not src port 1024..65535
# # drop dst host 8.8.8.8 and not proto tcp and not dst port 6666
# # drop dst host 8.8.8.8 and not src port 1027..65535, 1024..65535
# # drop dst host 8.8.8.8 and not src port 1027..65535 and not dst port 6666
# # drop dst host 8.8.8.8 and not src port 1024..65535 and not dst port 80, 443, 1024..65535
# # drop dst host 8.8.8.8 and not dst port 80, 6666, 443, 1024..65535
#
# def rule_by_ip_protocol(item, ip, proto):
#     return [
#         f"drop dst host {ip} and not proto {proto} and not src port {', '.join(list(item['sport']))}",
#         f"drop dst host {ip} and not proto {proto} and not dst port {', '.join(list(item['dport']))}",
#     ]
#
# def port_parser(ports):
#     if ports.isdigit():
#         return set([ports])
#     if '..' in ports and len(ports.split('..')) == 2:
#         return set([ports])
#
#     parsed = []
#     for port in ports.split(','):
#         port = port.strip()
#         parsed += port_parser(port)
#
#     return set(parsed)

import json

# def json_rules(data):
#     rules = []
#     for_rule_by_ip = {}
#
#     for item in data:
#         if item['ip'] not in for_rule_by_ip:
#             for_rule_by_ip[item['ip']] = {'proto': set(), 'dport': set(), 'sport': set()}
#         for_rule_by_ip[item['ip']]['proto'].add(item['proto'])
#         for_rule_by_ip[item['ip']]['dport'] |= port_parser(item['dport'])
#         for_rule_by_ip[item['ip']]['sport'] |= port_parser(item['sport'])
#
#     for_rule_by_ip_proto = {}
#
#     for item in data:
#         if item['ip'] + '_' + item['proto'] not in for_rule_by_ip_proto:
#             for_rule_by_ip_proto[item['ip'] + '_' + item['proto']] = {'dport': set(), 'sport': set()}
#         for_rule_by_ip_proto[item['ip'] + '_' + item['proto']]['dport'] |= port_parser(item['dport'])
#         for_rule_by_ip_proto[item['ip'] + '_' + item['proto']]['sport'] |= port_parser(item['sport'])
#
#     print(for_rule_by_ip_proto)
#     print(for_rule_by_ip)
#
#     for ip_proto in for_rule_by_ip_proto:
#         rules.append(rule_by_ip_protocol(for_rule_by_ip_proto[ip_proto], ip_proto.split('_')[0], ip_proto.split('_')[1]))
#
#     for ip in for_rule_by_ip:
#         rules.append(rule_by_ip(for_rule_by_ip[ip], ip))
#
#     return rules






def rule_by_ip(item, ip):
    return [
        f"drop dst host {ip} and not proto {', '.join(list(item['proto']))}",
        f"drop dst host {ip} and not src port {', '.join(list(item['sport']))}",
        f"drop dst host {ip} and not dst port {', '.join(list(item['dport']))}"
    ]

# drop dst host 8.8.8.8 and not proto udp, tcp
# drop dst host 8.8.8.8 and not proto udp and not src port 1027..65535
# drop dst host 8.8.8.8 and not proto udp and not dst port 80, 443, 1024..65535
# drop dst host 8.8.8.8 and not proto tcp and not src port 1024..65535
# drop dst host 8.8.8.8 and not proto tcp and not dst port 6666
# drop dst host 8.8.8.8 and not src port 1027..65535, 1024..65535
# drop dst host 8.8.8.8 and not src port 1027..65535 and not dst port 6666
# drop dst host 8.8.8.8 and not src port 1024..65535 and not dst port 80, 443, 1024..65535
# drop dst host 8.8.8.8 and not dst port 80, 6666, 443, 1024..65535

def rule_by_ip_protocol(item, ip, proto):
    return [
        f"drop dst host {ip} and not proto {proto} and not src port {', '.join(list(item['sport']))}",
        f"drop dst host {ip} and not proto {proto} and not dst port {', '.join(list(item['dport']))}",
    ]


TEMPLATE_DROP_SRC = 'drop dst host {} and not src port {}'
TEMPLATE_DROP_DST = 'drop dst host {} and not dst port {}'
TEMPLATE_DROP_PROTO = 'drop dst host {} and not proto {}'
TEMPLATE_DROP_SRC_DST = 'drop dst host {} and not src port {} and not dst port {}'
TEMPLATE_DROP_PROTO_SRC = 'drop dst host {} and not proto {} and not src port {}'
TEMPLATE_DROP_PROTO_DST = 'drop dst host {} and not proto {} and not dst port {}'


def json_rules(data):
    pre_rule = {}

    for item in data:
        key = item['ip']
        if key not in pre_rule:
            pre_rule[key] = {}
            pre_rule[key]['by_ip_proto'] = {}
            pre_rule[key]['by_ip'] = {'proto': set(), 'dport': set(), 'sport': set()}

        pre_rule[key]['by_ip']['proto'].add(item['proto'])
        pre_rule[key]['by_ip']['dport'] |= port_parser(item['dport'])
        pre_rule[key]['by_ip']['sport'] |= port_parser(item['sport'])


    for item in data:
        key_ip = item['ip']
        key_proto = item['proto']

        if key_proto not in pre_rule[key_ip]['by_ip_proto']:

            print(key_proto)
            pre_rule[key_ip]['by_ip_proto'][key_proto] = {'dport': set(), 'sport': set()}

        pre_rule[key_ip]['by_ip_proto'][key_proto]['dport'] |= port_parser(item['dport'])
        pre_rule[key_ip]['by_ip_proto'][key_proto]['sport'] |= port_parser(item['sport'])

    rules = []
    for ip in pre_rule:
        rules.append(
            rules_by_ip_new(ip, pre_rule[ip])
        )

    print(rules)
    return rules


def rules_by_ip_new(ip, item):
    rules = [
        TEMPLATE_DROP_PROTO.format(ip, ', '.join(list(item['by_ip']['proto']))),
        TEMPLATE_DROP_SRC.format(ip, ', '.join(list(item['by_ip']['sport']))),
        TEMPLATE_DROP_DST.format(ip, ', '.join(list(item['by_ip']['dport'])))
    ]

    if not equals_ports(item):
        rules.append(
            TEMPLATE_DROP_SRC_DST.format(ip, ', '.join(list(item['by_ip']['sport'])), ', '.join(list(item['by_ip']['dport']))))

    if len(item['by_ip']['proto']) < 2:
        return rules

    for proto in item['by_ip_proto']:
        rules.append(
            TEMPLATE_DROP_PROTO_SRC.format(ip, proto, ', '.join(list(item['by_ip_proto'][proto]['sport']))))

        rules.append(
            TEMPLATE_DROP_PROTO_DST.format(ip, proto, ', '.join(list(item['by_ip_proto'][proto]['dport']))))
    return rules

def equals_ports(item):
    s_ip = item['by_ip']['sport']
    d_ip = item['by_ip']['sport']

    for proto in item['by_ip_proto']:
        if item['by_ip_proto'][proto]['sport'] != s_ip or item['by_ip_proto'][proto]['sport'] != d_ip:
            return False

    return True

def port_parser(ports):
    if ports.isdigit():
        return set([ports])
    if '..' in ports and len(ports.split('..')) == 2:
        return set([ports])

    parsed = []
    for port in ports.split(','):
        port = port.strip()
        parsed += port_parser(port)

    return set(parsed)

