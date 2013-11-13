# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (C) 2012-2013 Red Hat, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Configuration for libvirt objects.

Classes to represent the configuration of various libvirt objects
and support conversion to/from XML. These classes are solely concerned
by providing direct Object <-> XML document conversions. No policy or
operational decisions should be made by code in these classes. Such
policy belongs in the 'designer.py' module which provides simplified
helpers for populating up config object instances.
"""

from manila import exception
from manila.openstack.common.gettextutils import _
from manila.openstack.common import log as logging

from lxml import etree


LOG = logging.getLogger(__name__)


class LibvirtConfigObject(object):

    def __init__(self, **kwargs):
        super(LibvirtConfigObject, self).__init__()

        self.root_name = kwargs.get("root_name")
        self.ns_prefix = kwargs.get('ns_prefix')
        self.ns_uri = kwargs.get('ns_uri')

    def _text_node(self, name, value):
        child = etree.Element(name)
        child.text = str(value)
        return child

    def format_dom(self):
        if self.ns_uri is None:
            return etree.Element(self.root_name)
        else:
            return etree.Element("{" + self.ns_uri + "}" + self.root_name,
                                 nsmap={self.ns_prefix: self.ns_uri})

    def parse_str(self, xmlstr):
        self.parse_dom(etree.fromstring(xmlstr))

    def parse_dom(self, xmldoc):
        if self.root_name != xmldoc.tag:
            raise exception.InvalidInput(
                "Root element name should be '%s' not '%s'"
                % (self.root_name, xmldoc.tag))

    def to_xml(self, pretty_print=True):
        root = self.format_dom()
        xml_str = etree.tostring(root, pretty_print=pretty_print)
        return xml_str


class LibvirtConfigGuestDevice(LibvirtConfigObject):

    def __init__(self, **kwargs):
        super(LibvirtConfigGuestDevice, self).__init__(**kwargs)


class LibvirtConfigGuestFilesys(LibvirtConfigGuestDevice):

    def __init__(self, **kwargs):
        super(LibvirtConfigGuestFilesys, self).__init__(root_name="filesystem",
                                                        **kwargs)

        self.source_type = "mount"
        self.source_dir = None
        self.target_dir = "/"
        self.driver = "path"

    def format_dom(self):
        dev = super(LibvirtConfigGuestFilesys, self).format_dom()

        dev.set("type", self.source_type)

        dev.append(etree.Element("driver", driver=self.driver))
        if self.source_type == "mount":
            dev.append(etree.Element("source", dir=self.source_dir))
        elif self.source_type == "file":
            dev.append(etree.Element("source", file=self.source_dir))
        dev.append(etree.Element("target", dir=self.target_dir))

        return dev

    def parse_dom(self, xmldoc):
        super(LibvirtConfigGuestFilesys, self).parse_dom(xmldoc)

        self.source_type = xmldoc.get('type')
        for child in xmldoc.getchildren():
            if child.tag == 'source':
                if self.source_type == "mount":
                    self.source_dir = child.get('dir')
                elif self.source_type == "file":
                    self.source_dir = child.get('file')
            if child.tag == 'target':
                self.target_dir = child.get('dir')
            if child.tag == 'driver':
                self.driver = child.get('type')

class LibvirtConfigGuestInterface(LibvirtConfigGuestDevice):

    def __init__(self, **kwargs):
        super(LibvirtConfigGuestInterface, self).__init__(
            root_name="interface",
            **kwargs)

        self.net_type = None
        self.target_dev = None
        self.model = None
        self.mac_addr = None
        self.script = None
        self.source_dev = None
        self.source_mode = "private"
        self.vporttype = None
        self.vportparams = []
        self.filtername = None
        self.filterparams = []
        self.driver_name = None
        self.vif_inbound_peak = None
        self.vif_inbound_burst = None
        self.vif_inbound_average = None
        self.vif_outbound_peak = None
        self.vif_outbound_burst = None
        self.vif_outbound_average = None

    def format_dom(self):
        dev = super(LibvirtConfigGuestInterface, self).format_dom()

        dev.set("type", self.net_type)
        if self.mac_addr:
            dev.append(etree.Element("mac", address=self.mac_addr))
        if self.model:
            dev.append(etree.Element("model", type=self.model))

        if self.driver_name:
            dev.append(etree.Element("driver", name=self.driver_name))

        if self.net_type == "ethernet":
            if self.script is not None:
                dev.append(etree.Element("script", path=self.script))
        elif self.net_type == "direct":
            dev.append(etree.Element("source", dev=self.source_dev,
                                     mode=self.source_mode))
        elif self.net_type == "network":
            dev.append(etree.Element("source", network=self.source_dev))
        else:
            dev.append(etree.Element("source", bridge=self.source_dev))

        if self.target_dev is not None:
            dev.append(etree.Element("target", dev=self.target_dev))

        if self.vporttype is not None:
            vport = etree.Element("virtualport", type=self.vporttype)
            for p in self.vportparams:
                param = etree.Element("parameters")
                param.set(p['key'], p['value'])
                vport.append(param)
            dev.append(vport)

        if self.filtername is not None:
            filter = etree.Element("filterref", filter=self.filtername)
            for p in self.filterparams:
                filter.append(etree.Element("parameter",
                                            name=p['key'],
                                            value=p['value']))
            dev.append(filter)

        if self.vif_inbound_average or self.vif_outbound_average:
            bandwidth = etree.Element("bandwidth")
            if self.vif_inbound_average is not None:
                vif_inbound = etree.Element("inbound",
                average=str(self.vif_inbound_average))
                if self.vif_inbound_peak is not None:
                    vif_inbound.set("peak", str(self.vif_inbound_peak))
                if self.vif_inbound_burst is not None:
                    vif_inbound.set("burst", str(self.vif_inbound_burst))
                bandwidth.append(vif_inbound)

            if self.vif_outbound_average is not None:
                vif_outbound = etree.Element("outbound",
                average=str(self.vif_outbound_average))
                if self.vif_outbound_peak is not None:
                    vif_outbound.set("peak", str(self.vif_outbound_peak))
                if self.vif_outbound_burst is not None:
                    vif_outbound.set("burst", str(self.vif_outbound_burst))
                bandwidth.append(vif_outbound)
            dev.append(bandwidth)

        return dev

    def parse_dom(self, xmldoc):
        self.net_type = xmldoc.get('type')
        for c in xmldoc.getchildren():
            if c.tag == 'source':
                if self.net_type == 'network':
                    self.source_dev = c.get('network')
            if c.tag == 'mac':
                self.mac_addr = c.get('address')
            if c.tag == 'target':
                self.target_dev = c.get('dev')


    def add_filter_param(self, key, value):
        self.filterparams.append({'key': key, 'value': value})

    def add_vport_param(self, key, value):
        self.vportparams.append({'key': key, 'value': value})


class LibvirtConfigGuestCharBase(LibvirtConfigGuestDevice):

    def __init__(self, **kwargs):
        super(LibvirtConfigGuestCharBase, self).__init__(**kwargs)

        self.type = "pty"

    def format_dom(self):
        dev = super(LibvirtConfigGuestCharBase, self).format_dom()
        dev.set("type", self.type)
        return dev

    def parse_dom(self, xmldoc):
        super(LibvirtConfigGuestCharBase, self).parse_dom(xmldoc)
        self.type = xmldoc.get('type')



class LibvirtConfigGuestChar(LibvirtConfigGuestCharBase):

    def __init__(self, **kwargs):
        super(LibvirtConfigGuestChar, self).__init__(**kwargs)

    def format_dom(self):
        dev = super(LibvirtConfigGuestChar, self).format_dom()
        return dev


class LibvirtConfigGuestConsole(LibvirtConfigGuestChar):

    def __init__(self, **kwargs):
        super(LibvirtConfigGuestConsole, self).__init__(root_name="console",
                                                        **kwargs)


class LibvirtConfigGuest(LibvirtConfigObject):

    def __init__(self, **kwargs):
        super(LibvirtConfigGuest, self).__init__(root_name="domain",
                                                 **kwargs)

        self.virt_type = None
        self.uuid = None
        self.name = None
        self.memory = 1024 * 1024 * 500
        self.vcpus = 1
        self.os_type = None
        self.os_init_path = None
        self.devices = []

    def _format_basic_props(self, root):
        if self.uuid:
            root.append(self._text_node("uuid", self.uuid))
        root.append(self._text_node("name", self.name))
        root.append(self._text_node("memory", self.memory))
        root.append(self._text_node("vcpu", self.vcpus))

    def _format_os(self, root):
        os = etree.Element("os")
        os.append(self._text_node("type", self.os_type))
        if self.os_init_path is not None:
            os.append(self._text_node("init", self.os_init_path))

        root.append(os)

    def _format_devices(self, root):
        if len(self.devices) == 0:
            return
        devices = etree.Element("devices")
        for dev in self.devices:
            devices.append(dev.format_dom())
        root.append(devices)

    def format_dom(self):
        root = super(LibvirtConfigGuest, self).format_dom()
        root.set("type", self.virt_type)
        self._format_basic_props(root)
        self._format_os(root)
        self._format_devices(root)
        return root

    def parse_dom(self, xmldoc):
        self.virt_type = xmldoc.get('type')
        for c in xmldoc.getchildren():
            if c.tag in ('uuid', 'name', 'memory', 'vcpu'):
                setattr(self, c.tag, c.text)
            if c.tag == 'devices':
                for d in c.getchildren():
                    if d.tag == 'filesystem':
                        obj = LibvirtConfigGuestFilesys()
                        obj.parse_dom(d)
                        self.devices.append(obj)
                    elif d.tag == 'interface':
                        obj = LibvirtConfigGuestInterface()
                        obj.parse_dom(d)
                        self.devices.append(obj)
                    elif d.tag == 'console':
                        obj = LibvirtConfigGuestConsole()
                        obj.parse_dom(d)
                        self.devices.append(obj)
            if c.tag == 'os':
                for o in c.getchildren():
                    if o.tag == 'type':
                        self.os_type = o.text
                    if o.tag == 'init':
                        self.os_init_path = o.text

    def add_device(self, dev):
        self.devices.append(dev)
