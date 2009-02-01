# Copyright (c) 2009, Takashi Ito
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the authors nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import os
import socket
import time
from cStringIO import StringIO
from xml.etree import ElementTree as ET
from httplib import HTTPMessage
from random import random

from twisted.internet import error
from twisted.internet.udp import MulticastPort
from twisted.internet.protocol import DatagramProtocol
from twisted.internet.threads import blockingCallFromThread
from twisted.python.threadpool import ThreadPool
from twisted.python.threadable import isInIOThread
from twisted.web import server
from twisted.web import resource
from twisted.web import wsgi

from routes import Mapper
from routes.middleware import RoutesMiddleware


__all__ = [
    'UpnpNamespace',
    'UpnpDevice',
    'UpnpBase',
    'SoapMessage',
    'xml_tostring',
    'make_gmt',
    'not_found',
    'ns',
]


class UpnpNamespace(object):
    device = 'urn:schemas-upnp-org:device-1-0'
    service = 'urn:schemas-upnp-org:service-1-0'
    dlna = 'urn:schemas-dlna-org:device-1-0'
    s = 'http://schemas.xmlsoap.org/soap/envelope/'
    dc = 'http://purl.org/dc/elements/1.1/'
    upnp = 'urn:schemas-upnp-org:metadata-1-0/upnp/'
    didl = 'urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/'

ns = UpnpNamespace

def is_new_etree(et):
    ver = et.VERSION.split('.')
    if int(ver[0]) > 1:
        return True
    return int(ver[1]) > 2

def register_namespace(et, prefix, uri):
    if is_new_etree(ET):
        et.register_namespace(prefix, uri)
    else:
        et._namespace_map[uri] = prefix

# register upnp/dlna namespaces
register_namespace(ET, 's', ns.s)
register_namespace(ET, 'dc', ns.dc)
register_namespace(ET, 'upnp', ns.upnp)
register_namespace(ET, 'dlna', ns.dlna)


def find(elem, nodes, ns):
    return elem.find('/'.join(['{%s}' % ns + x for x in nodes]))

def findtext(elem, nodes, ns, default=None):
    return elem.findtext('/'.join(['{%s}' % ns + x for x in nodes]), default)

def get_outip(remote_host):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((remote_host, 80))
    return sock.getsockname()[0]

def make_gmt():
    return time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())

def not_found(environ, start_response):
    headers = [
        ('DATE', make_gmt()),
        ('Content-type', 'text/plain'),
        ('Connection', 'close'),
    ]
    start_response('404 Not Found', headers)
    return ['Not Found']

def build_packet(first_line, packet):
    buff = first_line + '\r\n'
    buff += '\r\n'.join([k + ': ' + v for k, v in packet])
    buff += '\r\n\r\n'
    return buff

def xml_tostring(elem, encoding='utf-8', xml_decl=None, default_ns=None):
    class dummy(object):
        pass
    data = []
    fileobj = dummy()

    if is_new_etree(ET):
        fileobj.write = data.append
        ET.ElementTree(elem).write(fileobj, encoding, xml_decl, default_ns)
    else:
        def _write(o):
            # workaround
            l = (o, ('<tmp:', '<'), ('</tmp:', '</'), (' tmp:', ' '), ('xmlns:tmp=', 'xmlns='))
            o = reduce(lambda s, (f, t): s.replace(f, t), l)
            data.append(o)
        fileobj.write = _write
        if xml_decl or encoding not in ('utf-8', 'us-ascii'):
            fileobj.write('<?xml version="1.0" encoding="%s"?>\n' % encoding)
        register_namespace(ET, 'tmp', default_ns)
        ET.ElementTree(elem).write(fileobj, encoding)

    return "".join(data)


class SoapMessage(object):
    """
    >>> r = SoapMessage('type', 'action')
    >>> r.set_args([('a1', 'v1'), ('a2', 'v2')])
    >>> r.get_arg('a1')
    'v1'
    >>> r.get_arg('a2')
    'v2'
    >>> r.get_args()
    [('a1', 'v1'), ('a2', 'v2')]
    >>> r.set_arg('a1', 'new one')
    >>> r.get_arg('a1')
    'new one'
    >>> r.del_arg('a1')
    >>> r.get_arg('a1', None)
    >>> r.get_arg('a1')
    ''
    """

    TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope
    xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
    s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:%s xmlns:u="%s"/>
  </s:Body>
</s:Envelope>
"""

    def __init__(self, serviceType, name, doc=None):
        if doc == None:
            xml = self.TEMPLATE % (name, serviceType)
            doc = ET.parse(StringIO(xml))

        self.doc = doc.getroot()
        body = self.doc.find('{%s}Body' % ns.s)

        if name == None or serviceType == None:
            tag = body[0].tag
            if tag[0] == '{':
                serviceType, name = tag[1:].split('}', 1)
            else:
                serviceType, name = '', tag

        self.u = serviceType
        self.action = body.find('{%s}%s' % (self.u, name))

    @classmethod
    def parse(cls, fileobj, serviceType=None, name=None):
        return cls(serviceType, name, ET.parse(fileobj))

    def set_arg(self, name, value):
        elem = self.action.find(name)
        if elem == None:
            elem = ET.SubElement(self.action, name)
        elem.text = value

    def set_args(self, args):
        for name, value in args:
            self.set_arg(name, value)

    def get_arg(self, name, default=''):
        return self.action.findtext(name, default)

    def get_args(self):
        args = []
        for elem in self.action:
            args.append((elem.tag, elem.text))
        return args

    def del_arg(self, name):
        elem = self.action.find(name)
        if elem != None:
            self.action.remove(elem)

    def tostring(self, encoding='utf-8', xml_decl=True):
        register_namespace(ET, 'u', self.u)
        return xml_tostring(self.doc, encoding, xml_decl)


class SoapMiddleware(object):
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        soapaction = (environ['HTTP_SOAPACTION'] or '').strip('"').split('#', 1)
        if len(soapaction) == 2:
            environ['upnp.soap.serviceType'] = soapaction[0]
            environ['upnp.soap.action'] = soapaction[1]
        return self.app(environ, start_response)


class SSDPServer(DatagramProtocol):
    def __init__(self, owner):
        self.owner = owner;

    def datagramReceived(self, data, addr):
        self.owner.datagramReceived(data, addr, get_outip(addr[0]))


class UpnpDevice(object):

    SERVER_NAME = 'OS/x.x UPnP/1.0 py/1.0'
    OK = ('200 OK', 'text/xml; charset="utf-8"')
    NOT_FOUND = ('404 Not Found', 'text/plain')
    SERVER_ERROR = ('500 Internal Server Error', 'text/plain')

    def __init__(self, udn, dd, soap_app, server_name=SERVER_NAME):
        self.udn = udn
        self.ssdp = None
        self.http = None
        self.port = 0
        self.server_name = server_name
        self.soap_app = SoapMiddleware(soap_app) if soap_app else None

        # load DD
        self.dd = ET.parse(dd)
        xml_dir = os.path.dirname(dd)

        # set UDN
        find(self.dd, ['device', 'UDN'], ns.device).text = udn

        # get deviceType
        self.deviceType = findtext(self.dd, ['device', 'deviceType'], ns.device)

        self.services = {}
        self.serviceTypes = []
        for service in find(self.dd, ['device', 'serviceList'], ns.device):
            sid = findtext(service, ['serviceId'], ns.device, '')

            # SCPDURL
            scpdurl = find(service, ['SCPDURL'], ns.device)
            self.services[sid] = ET.parse(os.path.join(xml_dir, scpdurl.text))
            scpdurl.text = '/' + self.udn + '/' + sid

            # controlURL
            find(service, ['controlURL'], ns.device).text = scpdurl.text + '/soap'

            # eventSubURL
            find(service, ['eventSubURL'], ns.device).text = scpdurl.text + '/sub'

            # append serviceType
            serviceType = findtext(service, ['serviceType'], ns.device, '')
            self.serviceTypes.append(serviceType)

    def make_notify_packets(self, host, ip, port_num, nts):
        types = ['upnp:rootdevice', self.udn, self.deviceType]
        types += self.services.keys()
        packets = []

        for nt in types:
            packet = [
                ('HOST', host),
                ('CACHE-CONTROL', 'max-age=1800'),
                ('LOCATION', 'http://%s:%d/%s' % (ip, port_num, self.udn)),
                ('NT', nt),
                ('NTS', nts),
                ('SERVER', self.server_name),
                ('USN', self.udn + ('' if nt == self.udn else '::' + nt)),
            ]
            packets.append(packet)

        return packets

    def make_msearch_response(self, headers, (addr, port), dest):
        # get ST
        st = headers.getheader('ST')
        sts = ['ssdp:all', 'upnp:rootdevice', self.udn, self.deviceType]
        sts += self.serviceTypes
        if st not in sts:
            return []

        if st == self.udn:
            usns = ['']
        elif st == 'ssdp:all':
            usns = ['upnp:rootdevice', '', self.deviceType] + self.services.keys()
        else:
            usns = [st]

        packets = []
        for usn in usns:
            if usn != '':
                usn = '::' + usn
            packet = [
                ('CACHE-CONTROL', 'max-age=1800'),
                ('DATE', make_gmt()),
                ('EXT', ''),
                ('LOCATION', 'http://%s:%s/%s' % (addr, port, self.udn)),
                ('SERVER', self.server_name),
                ('ST', st),
                ('USN', self.udn + usn)
            ]
            packets.append(packet)

        return packets

    def __call__(self, environ, start_response):
        rargs = environ['wsgiorg.routing_args'][1]
        udn = rargs['udn']
        action = rargs['action']
        sid = rargs['sid']
        method = environ['REQUEST_METHOD']

        body = 'Not Found'
        code = self.NOT_FOUND

        if method == 'GET' and action == 'desc':
            if sid == None:
                # DD
                body = xml_tostring(self.dd.getroot(), 'utf-8', True, ns.device)
                code = self.OK
            elif sid in self.services:
                # SCPD
                body = xml_tostring(self.services[sid].getroot(), 'utf-8', True, ns.service)
                code = self.OK

        elif method == 'POST' and action == 'soap':
            if self.soap_app:
                return self.soap_app(environ, start_response)

        elif method == 'SUBSCRIBE' or method == 'UNSUBSCRIBE':
            # TODO: impl
            pass

        headers = [
            ('DATE', make_gmt()),
            ('Content-type', code[1]),
            ('Connection', 'close'),
        ]

        start_response(code[0], headers)
        return [body]


class _WSGIResponse(wsgi._WSGIResponse):
    def __init__(self, reactor, threadpool, application, request):
        wsgi._WSGIResponse.__init__(self, reactor, threadpool, application, request)
        self.environ['REMOTE_ADDR'] = request.getClientIP()
        self.request.responseHeaders.removeHeader('content-type')


class WSGIResource(wsgi.WSGIResource):
    def render(self, request):
        response = _WSGIResponse(self._reactor, self._threadpool, self._application, request)
        response.start()
        return server.NOT_DONE_YET


class UpnpBase(object):

    SSDP_ADDR = '239.255.255.250'
    SSDP_PORT = 1900
    INADDR_ANY = '0.0.0.0'
    SOAP_BODY_MAX = 200 * 1024
    _addr = (SSDP_ADDR, SSDP_PORT)

    def __init__(self):
        self.started = False
        self.reactor = None
        self.interfaces = []
        self.tpool = ThreadPool(name=self.__class__.__name__)
        self.devices = {}

        # setup route map
        self.map = self._make_map()
        self.app = RoutesMiddleware(self, self.map)

    def _make_map(self):
        m = Mapper()
        m.connect(':udn/:sid/:action', controller='upnp', action='desc', sid=None)
        return m

    def append_device(self, devices):
        for device in devices:
            if device.udn in self.devices:
                self.remove_device(device.udn)
            self.devices[device.udn] = device
            self._notify(device, 'ssdp:alive')

    def remove_device(self, udn):
        try:
            device = self.devices[udn]
            self._notify(device, 'ssdp:byebye')
            del self.devices[udn]
        except KeyError:
            pass

    def _notify_all(self, nts):
        if not self.started:
            return
        for udn in self.devices:
            self._notify(self.devices[udn], nts)

    def _notify(self, device, nts):
        if not self.started:
            return
        for ip in self.interfaces:
            # create send port
            port = MulticastPort(0, None, interface=ip, reactor=self.reactor)
            try:
                port._bindSocket()
            except error.CannnotListenError, e:
                # in case the ip address changes
                continue

            # get real ip
            if ip == self.INADDR_ANY:
                ip = get_outip(self.SSDP_ADDR)

            # send notify packets
            delay = 0
            host = self.SSDP_ADDR + ':' + str(self.SSDP_PORT)
            for packet in device.make_notify_packets(host, ip, self.port, nts):
                buff = build_packet('NOTIFY * HTTP/1.1', packet)
                self.reactor.callLater(delay, self._send_packet, port, buff, self._addr)
                delay += 0.020

    def _send_packet(self, port, buff, addr):
        if self.started:
            port.write(buff, addr)

    def datagramReceived(self, data, addr, outip):
        if outip not in self.interfaces:
            if self.INADDR_ANY not in self.interfaces:
                return

        req_line, data = data.split('\r\n', 1)
        method, path, version = req_line.split(None, 3)

        # check method
        if method != 'M-SEARCH' or path != '*':
            return

        # parse header
        headers = HTTPMessage(StringIO(data))
        mx = int(headers.getheader('MX'))

        # send M-SEARCH response
        for udn in self.devices:
            device = self.devices[udn]
            delay = random() * mx
            for packet in device.make_msearch_response(headers, (outip, self.port), addr):
                buff = build_packet('HTTP/1.1 200 OK', packet)
                self.reactor.callLater(delay, self._send_packet, self.ssdp, buff, addr)
                delay += 0.020

    def __call__(self, environ, start_response):
        """
        This function have to be called in a worker thread, not the IO thread.
        """
        rargs = environ['wsgiorg.routing_args'][1]
        try:
            if isInIOThread():
                # TODO: read request body
                return self.devices[rargs['udn']](environ, start_response)
            else:
                # read request body
                input = environ['wsgi.input']
                environ['upnp.body'] = input.read(self.SOAP_BODY_MAX)
                # call the app in IO thread
                args = [rargs['udn'], environ, start_response]
                blockingCallFromThread(self.reactor, self._call_handler, args)
                return args[3]
        except Exception, e:
            #print e
            #print 'Unknown access: ' + environ['PATH_INFO'] 
            return not_found(environ, start_response)

    def _call_handler(self, args):
        ret = self.devices[args[0]](args[1], args[2])
        args.append(ret)

    def start(self, reactor, interfaces=[INADDR_ANY]):
        if self.started:
            return

        self.reactor = reactor
        self.interfaces = interfaces
        if len(self.interfaces) == 0:
            self.interfaces.append(self.INADDR_ANY)

        # http server address
        if len(self.interfaces) == 1:
            interface = self.interfaces[0]
        else:
            interface = self.INADDR_ANY

        # start http server
        self.tpool.start()
        resource = WSGIResource(self.reactor, self.tpool, self.app)
        self.http = self.reactor.listenTCP(0, server.Site(resource))
        self.port = self.http.socket.getsockname()[1]

        # start ssdp server
        self.ssdp = self.reactor.listenMulticast(self.SSDP_PORT,
                                                 SSDPServer(self),
                                                 interface=interface,
                                                 listenMultiple=True)
        self.ssdp.setLoopbackMode(1)
        for ip in self.interfaces:
            self.ssdp.joinGroup(self.SSDP_ADDR, interface=ip)

        self.started = True
        self._notify_all('ssdp:alive')

    def stop(self):
        if not self.started:
            return

        self._notify_all('ssdp:byebye')

        # stop ssdp server
        for ip in self.interfaces:
            self.ssdp.leaveGroup(self.SSDP_ADDR, interface=ip)
        self.ssdp.stopListening()

        # stop http server
        self.tpool.stop()
        self.http.stopListening()

        self.started = False
        self.interfaces = []


class _dp(DatagramProtocol):
    def __init__(self, owner):
        self.owner = owner

    def datagramReceived(self, datagram, address):
        self.owner(datagram, address)


class MSearchRequest(object):

    SSDP_ADDR = '239.255.255.250'
    SSDP_PORT = 1900
    INADDR_ANY = '0.0.0.0'
    _addr = (SSDP_ADDR, SSDP_PORT)
    WAIT_MARGIN = 0.5

    def __init__(self, owner=None):
        self.ports = []
        if owner == None:
            owner = self.datagramReceived
        self.owner = owner

    def __del__(self):
        for port in self.ports:
            port.stopListening()

    def datagramReceived(self, datagram, address):
        pass

    def send(self, reactor, st, mx=2, interfaces=[]):
        if len(interfaces) == 0 or self.INADDR_ANY in interfaces:
            outip = get_outip(self.SSDP_ADDR)
            if outip not in interfaces:
                interfaces.append(outip)
            while self.INADDR_ANY in interfaces:
                interfaces.remove(self.INADDR_ANY)

        packet = [
            ('HOST', self.SSDP_ADDR + ':' + str(self.SSDP_PORT)),
            ('MAN', '"ssdp:discover"'),
            ('MX', str(mx)),
            ('ST', st),
        ]
        buff = build_packet('M-SEARCH * HTTP/1.1', packet)

        new_ports = []
        for ip in interfaces:
            port = reactor.listenUDP(0, _dp(self.owner), interface=ip)
            new_ports.append(port)
            port.write(buff, self._addr)
        self.ports += new_ports

        return reactor.callLater(mx + self.WAIT_MARGIN, self._stop, new_ports)

    def _stop(self, ports):
        for port in ports:
            port.stopListening()
            self.ports.remove(port)


def _test():
    import doctest
    doctest.testmod()


if __name__ == '__main__':
    _test()

    from twisted.internet import reactor

    def soap_app(environ, start_response):
        sid = environ['wsgiorg.routing_args'][1]['sid']
        serviceType = environ['upnp.soap.serviceType']
        action = environ['upnp.soap.action']
        req = SoapMessage.parse(StringIO(environ['upnp.body']), serviceType, action)

        print action + ' from ' + environ['REMOTE_ADDR']
        print '\t' + sid
        print '\t' + serviceType
        print '\t' + str(req.get_args())

        return not_found(environ, start_response)

    device = UpnpDevice('uuid:00000000-0000-0000-001122334455', 'xml/ms.xml', soap_app)
    base = UpnpBase()
    base.append_device([device])
    base.start(reactor)
    
    def stop():
        base.remove_device(device.udn)
        base.stop()
        reactor.stop()

    reactor.callLater(15, stop)
    reactor.run()

