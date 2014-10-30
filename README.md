brocade-vf-extension
====================

Manage VXLAN overlay-gateway functionality on Brocade VDX switches using REST API

   * vfx.py: manage gw functions
   * vfx_payload: helper functions to create xml payloads
   * postman_vcs_vf_extension.json: google postman client rest call examples

Example Usage:

```
$ ./vfx.py  create  --hostname 10.254.11.17  --gw sko_gateway --loopback 100 --rbridge 100 \
   --vlan 100 --vni 1600000 --remote_site site2 --remote_ip 200.200.200.200

$ ./vfx.py  show  --hostname 10.254.11.17 --gw sko_gateway
    GW Name:   sko_gateway
    Active:    true
    Type:      layer2-extension
    RBridge_ID 100
    VLAN:      100

$ ./vfx.py  delete    --hostname 10.254.11.17  --gw sko_gateway
```

