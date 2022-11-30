# !/usr/bin/env python3
import logging
import lxml.etree as ET
import lxml.objectify as objectify
from json2xml import json2xml
import ipaddress


# from bs4 import BeautifulSoup


# logger = logging.getLogger("Extractor")
# handler = logging.FileHandler('./system_plugin.log')
# formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
# handler.setFormatter(formatter)
# logger.addHandler(handler)
# logger.setLevel(logging.ERROR)

# dep_namespace:
def run(xml_object, dep_class, dep_name, dep_namespace, test_run, rule_name, rule_namespace):
    result_list = []
    utf8_parser = ET.XMLParser(encoding='utf-8', recover=True)
    root = ET.fromstring(xml_object.encode('utf-8'), parser=utf8_parser)

    # #### To remove the namespace if its present
    for elem in root.iter():
        if not hasattr(elem.tag, 'find'): continue  # (1)
        i = elem.tag.find('}')
        if i >= 0:
            elem.tag = elem.tag[i + 1:]
    objectify.deannotate(root, cleanup_namespaces=True)

    try:
        if dep_class == "subservice.interface.health" and dep_name == "vpn-if-health-list" and \
                dep_namespace == "system" and \
                rule_name == "Rule-L3VPN-Demo" and rule_namespace == "custom":
            return extract_subservice_vpn_interfaces_payload(root, test_run)
        elif rule_name == "Rule-L3VPN-Demo" and rule_namespace == "custom" and \
                dep_class == "subservice.ebgp.nbr.health":
            return extract_subservice_ebgp_nbr_health_payload(root, test_run)
        elif rule_name == "Rule-L3VPN-Demo" and rule_namespace == "custom" and \
                dep_class == "subservice.vrf.plain.lsp.reachability":
            return extract_subservice_vrf_plain_lsp_reachability_payload(root, test_run)
        else:
            return result_list
    except Exception as exception:
        return "exception in running the plugin(Iter9). Error {error}".format(error=exception)


# Payload Extraction logic for subservice.vrf.plain.lsp.reachability
def extract_subservice_vrf_plain_lsp_reachability_payload(root, test_run):
    result_list = []
    if test_run:
        result_list = ["device", "vrf", "peer-vpn-addr-list"]
        return result_list

    devices = get_pe_devices(root)

    for device in devices:
        # Each result is a dictionary that can be used to instantiate one Subservice instance
        result = {}
        result["device"] = device

        device_vrf_path = ".//devices/device[key='{device}']/config/vrf/vrf-list/key".format(device=device)
        device_vrf_records = root.findall(device_vrf_path)
        result["vrf"] = device_vrf_records[0].text

        # IP address on this PE side

        self_vpn_ip_path = ".//devices/device[key='{device}']/config/router/bgp/*/*/neighbor/key".format(device=device)
        self_vpn_ip_records = root.findall(self_vpn_ip_path)
        self_vpn_ip = self_vpn_ip_records[0].text

        # PE configs have vrf in it, but CE dont, so the following should work.

        all_vpn_ip_records_path = ".//devices/device/config/router/bgp/*/vrf/neighbor/key"
        all_vpn_ip_records = root.findall(all_vpn_ip_records_path)

        # Fetch all IP addresses except for self one
        peer_ntw_list = []
        for ip_record in all_vpn_ip_records:
            if ip_record.text != self_vpn_ip:
                version = ipaddress.ip_interface(ip_record.text).version
                if version == 4:
                    ip_intf = ipaddress.IPv4Interface(ip_record.text)
                else:
                    ip_intf = ipaddress.IPv6Interface(ip_record.text)
                peer_ntw_str_32 = "%s" % (ip_intf.network)
                # hardcode mask to /24
                peer_ntw_str_24 =str(ipaddress.ip_network(peer_ntw_str_32).supernet(new_prefix=24))

                peer_ntw_list.append(peer_ntw_str_24)

        result["peer-vpn-addr-list"] = peer_ntw_list
        result_xml = json2xml.Json2xml(result, wrapper="plugin-output", pretty=True, attr_type=False).to_xml()
        result_list.append(result_xml)

    return result_list


def extract_subservice_vpn_interfaces_payload(root, test_run):
    result_list = []

    if test_run:
        result_list = ["device", "ifId"]
        return result_list

    for device in get_pe_devices(root):
        # Each result is a dictionary that can be used to instantiate one Subservice instance
        result = {}
        result["device"] = device

        # Assumes exactly one PE-CE interface on this vrf/vpn
        interfacename_path=".//devices/device[key='{device}']/config/interface/*".format(device=device)
        interfaceid_path=".//devices/device[key='{device}']/config/interface/*/key".format(device=device)

        device_interfacename_record = root.xpath(interfacename_path)
        device_interfaceid_record = root.xpath(interfaceid_path)
        result["ifId"] = device_interfacename_record[0].tag + device_interfaceid_record[0].text
        result_xml = json2xml.Json2xml(result, wrapper="plugin-output", pretty=True, attr_type=False).to_xml()
        result_list.append(result_xml)
    return result_list

# Payload Extraction logic for subservice.ebgp.nbr.health
def extract_subservice_ebgp_nbr_health_payload(root, test_run):
    result_list = []
    if test_run:
        result_list = ["device", "bgp_nbr_type", "vrf", "bgp_nbr_ipaddrs"]
        return result_list

    #device_records = root.findall('.//devices/device/name')
    #devices = [device_record.text for device_record in device_records]

    for device in get_pe_devices(root):
        # Each result is a dictionary that can be used to instantiate one Subservice instance
        result = {}
        result["device"] = device

        device_vrf_path = ".//devices/device[key='{device}']/config/vrf/vrf-list/key".format(device=device)
        device_vrf_records = root.findall(device_vrf_path)
        result["vrf"] = device_vrf_records[0].text

        # Assumes exactly one eBGP peering

        ebgp_address_family_path = ".//devices/device[key='{device}']/config/router/bgp/*/*/neighbor/address-family/*".format(device=device)
        ebgp_address_family_records = root.findall(ebgp_address_family_path)

        #ebgp_config_path = ".//flat-L3vpn/endpoint[access-pe='{device}']/ce-pe-prot/e-bgp".format(device=device)
        #ebgp_config_records = root.findall(ebgp_config_path)
        #if len(ebgp_config_records) == 0:
        #continue

        # Not sure this is used currently, hardcode to address family
        result["bgp_nbr_type"] = ebgp_address_family_records[0].tag

        bgp_nbr_ipaddrs_path = ".//devices/device[key='{device}']/config/router/bgp/*/*/neighbor/key".format(
            device=device)
        bgp_nbr_ipaddrs_records = root.findall(bgp_nbr_ipaddrs_path)
        if len(bgp_nbr_ipaddrs_records) == 0:
            continue
        bgp_nbr_ipaddrs = [bgp_ipaddr_record.text for bgp_ipaddr_record in bgp_nbr_ipaddrs_records]
        result["bgp_nbr_ipaddrs"] = bgp_nbr_ipaddrs

        result_xml = json2xml.Json2xml(result, wrapper="plugin-output", pretty=True, attr_type=False).to_xml()
        result_list.append(result_xml)


    #print(result_list)
    return result_list



def get_pe_devices(root):
    xpathquery = ".//endpoint/pe-device"
    pe_device_records = root.findall(xpathquery)
    pe_devices = [pe_device_record.text for pe_device_record in pe_device_records]
    return pe_devices


