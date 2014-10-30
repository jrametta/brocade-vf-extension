#!/usr/bin/env python

"""
Required steps per fabric to create a vxlan overlay gateway

   * Define an overlay-gateway name
   * Set the gateway type to l2 extension
   * Specify a loopback id to use for the VTEP
   * Attach an RBridge ID
   * Map a VLAN to a VNI
   * Activate the overlay gateway
   * Define a name for the remote site
   * Specify remote site's IP address of VTEP
   * Specify which vlans to extend


Example usage:
    $ ./vfx.py  create  --hostname 10.254.11.17  --gw foo --loopback 100  \
            --rbridge 100 --vlan 100 --vni 1600000 --remote_site site2    \
            --remote_ip 200.200.200.200

    $ ./vfx.py  show  --hostname 10.254.11.17 --gw sko_gateway

"""

import requests
import vfx_payload as PF
import sys
from xml.dom.minidom import parseString
import argparse

import logging

class overlay_gw(object):
    """class to manage vxlan overlay gateways"""
    def __init__(self, name, hostname, username, password):
        self.gateway_name  = name
        self.username = username
        self.password = password
        self.ext_type = 'layer2-extension'

        self.config_url = "http://{}/rest/config/running".format(hostname)
        self.headers = {'Accept': 'application/vnd.configuration.resource+xml'}

    def vfextension_create(self, loopback, rbridge):
        """docstring for vfextensionn_create"""
        self.tunnel_create()
        self.overlay_type_set()
        self.vtep_create(loopback)
        self.rbridge_attach(rbridge)

    def tunnel_create(self):
        """docstring for tunnel_create"""
        payload = PF.overlay_gateway(self.gateway_name)
        req = requests.post(self.config_url, data=payload,
                            headers=self.headers,
                            auth=(self.username, self.password))
        self.check_response(req)
        return req

    def tunnel_delete(self):
        """docstring for _tunnel_del"""
        url = self.config_url + "/overlay-gateway/{}".format(self.gateway_name)
        logging.info("url: %s", url)
        payload = PF.overlay_gateway(self.gateway_name)
        req = requests.delete(url, data=payload, headers=self.headers,
                              auth=(self.username, self.password))
        self.check_response(req)
        return req

    def check_response(self, rsp):
        """docstring for check_response"""
        logging.info("rsp code: %d: %s", rsp.status_code, rsp.reason)
        if rsp.status_code not in (200, 201, 204):
            logging.error("http request failed: %s" % rsp.reason)
            logging.error("rc: %d\n%s", rsp.status_code, rsp.content)
            raise Exception('Request Failed')

    def overlay_type_set(self):
        """docstring for overlay_type_set"""
        url = self.config_url + "/overlay-gateway/{}/type".format(
                self.gateway_name)
        logging.info("url: %s", url)
        payload = PF.set_overlay_type(self.ext_type)
        req = requests.put(url, data=payload, headers=self.headers,
                           auth=(self.username, self.password))
        self.check_response(req)
        return req

    def vtep_create(self, loopback):
        """docstring for vtep_create"""
        url = self.config_url + "/overlay-gateway/{}/type".format(
                self.gateway_name)
        url += "/ip/interface/Loopback"
        logging.info("url: %s", url)
        payload = PF.create_vtep(loopback)
        req = requests.put(url, data=payload, headers=self.headers,
                           auth=(self.username, self.password))
        self.check_response(req)
        return req

    def rbridge_attach(self, rbridge):
        """docstring for _rbridge_attach"""
        url = self.config_url + "/overlay-gateway/{}/attach".format(
                self.gateway_name)
        logging.info("url: %s", url)
        payload = PF.attach_rbridge(rbridge)
        req = requests.put(url, data=payload, headers=self.headers,
                           auth=(self.username, self.password))
        self.check_response(req)
        return req

    def vlan_to_vni_map(self, vlan, vni):
        """docstring for vlan_to_vni_map"""
        url = self.config_url + "/overlay-gateway/{}/map".format(
                self.gateway_name)
        logging.info("url: %s", url)
        payload = PF.vlan_to_vni_mapping(vlan, vni)
        req = requests.post(url, data=payload, headers=self.headers,
                           auth=(self.username, self.password))
        self.check_response(req)
        return req

    def gateway_activate(self):
        """docstring for gateway_activate"""
        url = self.config_url + "/overlay-gateway/{}".format(self.gateway_name)
        logging.info("url: %s", url)
        payload = PF.activate_gw()
        req = requests.post(url, data=payload, headers=self.headers,
                           auth=(self.username, self.password))
        self.check_response(req)
        return req

    def remote_site_create(self, name, ipaddr):
        """docstring for remote_site_create"""
        url = self.config_url + "/overlay-gateway/{}".format(self.gateway_name)
        logging.info("url: %s", url)
        payload = PF.define_remote_site(name)
        req = requests.post(url, data=payload, headers=self.headers,
                           auth=(self.username, self.password))
        self.check_response(req)

        logging.info("rsp code: %d: %s", req.status_code, req.reason)

        url += "/site/{}".format(name)
        logging.info("url: %s", url)
        payload = PF.add_remote_ip(ipaddr)
        req = requests.post(url, data=payload, headers=self.headers,
                           auth=(self.username, self.password))
        self.check_response(req)
        return req

    def vlan_extend(self, name, vlan):
        """docstring for vlan_extend"""
        url = self.config_url + "/overlay-gateway/{}".format(self.gateway_name)
        url += "/site/{}/extend".format(name)
        logging.info("url: %s", url)
        payload = PF.extend_vlan(vlan)
        req = requests.put(url, data=payload, headers=self.headers,
                           auth=(self.username, self.password))
        self.check_response(req)
        return req

    def tunnel_show(self, gw=None):
        """diplay information about tunnel name"""
        url = self.config_url + "/overlay-gateway/"
        if gw is not None:
            url += self.gateway_name

        logging.info("url: %s", url)
        req = requests.get(url, headers=self.headers,
                           auth=(self.username, self.password))
        self.check_response(req)

        #NOTE overlay gateway details are not complete

        data = "<xml>\n" +  req.content + "</xml>\r\n"
        dom = parseString(data)
        gateway = dom.getElementsByTagName('overlay-gateway')[0]
        print "GW Name:   " + gateway.getElementsByTagName(
                                                'name')[0].firstChild.nodeValue
        if gw is not None:
            print "Active:    " + gateway.getElementsByTagName(
                                                'activate')[0].firstChild.nodeValue
            print "Type:      " + gateway.getElementsByTagName(
                                                    'type')[0].firstChild.nodeValue
            print "RBridge_ID " + gateway.getElementsByTagName(
                                                     'add')[0].firstChild.nodeValue
            print "VLAN:      " + gateway.getElementsByTagName(
                                                    'vlan')[0].firstChild.nodeValue


def main():
    parser = argparse.ArgumentParser(
            description='Brocade VCS Overlay Gateway Builder')

    parser.add_argument('action', choices=['create', 'delete', 'update', 'show'])
    parser.add_argument("--hostname", required=True, help="VCS Managment IP")
    parser.add_argument("--username", default='admin', help="login username")
    parser.add_argument("--password", default='password', help="login password")
    parser.add_argument("--gw", help="tunnel gateway name")
    parser.add_argument('--loopback', help='loopback id to create vtep')
    parser.add_argument('--vlan', help='vlan to extend')
    parser.add_argument('--vni', help='map vlan to this vni')
    parser.add_argument('--rbridge', help='rbridge id  to carry gateway')
    parser.add_argument('--remote_site', help='remote site name')
    parser.add_argument('--remote_ip', help='ip addr of remote site vtep')
    parser.add_argument('--verbose', action='store_true',
                        help='display debug output')

    args = parser.parse_args()

    if args.verbose == True:
        logging.basicConfig(level=logging.INFO)

    gw = overlay_gw(args.gw, args.hostname, args.username, args.password)

    if args.action == 'create':
        try:
            gw.vfextension_create(args.loopback, args.rbridge)
            gw.vlan_to_vni_map(args.vlan, args.vni)
            gw.gateway_activate()
            gw.remote_site_create(args.remote_site, args.remote_ip)
            gw.vlan_extend(args.remote_site, args.vlan)
        except:
            print 'something went wrong :('

    elif args.action == 'update':
        #TODO: update gw supports
        print 'not implemented'

    elif args.action == 'delete':
        gw.tunnel_delete()

    elif args.action == 'show':
        gw.tunnel_show(gw=args.gw)


if __name__ == '__main__':
    main()

