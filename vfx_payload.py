#!/usr/bin/env python

"""
This module contains helper functions to create xml payload
data for vxlan configuration within Brocade VCS fabrics.
NOS 5.0 or above is required and fabrics must be configured
for logical chassis mode
"""

from xml.etree import ElementTree
from xml.etree.ElementTree import Element

def overlay_gateway(gateway_name):
    """build xml payload for create overlay request"""
    gw_element = Element('overlay-gateway')
    name_element = ElementTree.SubElement(gw_element, 'name')
    name_element.text = gateway_name
    return ElementTree.tostring(gw_element)

def set_overlay_type(type='layer2-extension'):
    """configure overlay gateway type.  it should be layer2-extension or nsx"""
    type_element = Element('type')
    type_element.text = type
    return ElementTree.tostring(type_element)

def create_vtep(loopback):
    """ build xml payload for create vtep.  it should be the loopback id """
    loopback_element = Element('loopback')
    loopbackid_element = ElementTree.SubElement(loopback_element, 'loopback-id')
    loopbackid_element.text = str(loopback)
    return ElementTree.tostring(loopback_element)

def attach_rbridge(rbridge_id):
    """ xml payload for tunnel rbridge attachment. it should be an rbridge id"""
    attach_elem = Element('attach')
    rbridgeid_elem = ElementTree.SubElement(attach_elem, 'rbridge-id')
    add_elem = ElementTree.SubElement(rbridgeid_elem, 'add')
    add_elem.text = str(rbridge_id)
    return ElementTree.tostring(attach_elem)

def vlan_to_vni_mapping(vlan, vni):
    """xml payload for vlan to vni mapping"""
    mapping_elem = Element('vlan-vni-mapping')
    vlan_elem = ElementTree.SubElement(mapping_elem, 'vlan')
    vlan_elem.text = str(vlan)
    vni_elem = ElementTree.SubElement(mapping_elem, 'vni')
    vni_elem.text = str(vni)
    return ElementTree.tostring(mapping_elem)

def activate_gw(activate_bool='true'):
    """xml payload to activate/diable gateway via true/false"""
    activate_elem = Element('activate')
    activate_elem.text = activate_bool
    return ElementTree.tostring(activate_elem)

def define_remote_site(name):
    """xml payload to define remote site name"""
    site_elem = Element('site')
    name_elem = ElementTree.SubElement(site_elem, 'name')
    name_elem.text = name
    return ElementTree.tostring(site_elem)

def add_remote_ip(ipaddr):
    """xml payload for define remote site ip address"""
    ip_elem = Element('ip')
    addr_elem = ElementTree.SubElement(ip_elem, 'address')
    addr_elem.text = ipaddr
    return ElementTree.tostring(ip_elem)

def extend_vlan(vlan):
    """xml payload for adding local vlan to extend"""
    extend_elem = Element('extend')
    vlan_elem = ElementTree.SubElement(extend_elem, 'vlan')
    add_elem = ElementTree.SubElement(vlan_elem, 'add')
    add_elem.text = str(vlan)
    return ElementTree.tostring(extend_elem)






