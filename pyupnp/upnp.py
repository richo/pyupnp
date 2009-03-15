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

from zope.interface import Interface
from zope.interface import implements

from routes import Mapper
from routes.middleware import RoutesMiddleware


__all__ = [
    'UpnpNamespace',
    'UpnpDevice',
    'UpnpBase',
    'SoapMessage',
    'SoapError',
    'IContent',
    'FileContent',
    'xml_tostring',
    'make_gmt',
    'to_gmt',
    'not_found',
    'ns',
    'nsmap',
    'toxpath',
    'mkxp',
    'StreamingServer',
    'MSearchRequest',
]


nsmap = {
    'device': 'urn:schemas-upnp-org:device-1-0',
    'service': 'urn:schemas-upnp-org:service-1-0',
    'control': 'urn:schemas-upnp-org:control-1-0',
    'dlna': 'urn:schemas-dlna-org:device-1-0',
    's': 'http://schemas.xmlsoap.org/soap/envelope/',
    'dc': 'http://purl.org/dc/elements/1.1/',
    'upnp': 'urn:schemas-upnp-org:metadata-1-0/upnp/',
    'didl': 'urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/',
}

class UpnpNamespaceMeta(type):
    def __new__(cls, name, bases, d):
        for prefix, uri in nsmap.items():
            d[prefix] = uri
        return type.__new__(cls, name, bases, d)

class UpnpNamespace(object):
    __metaclass__ = UpnpNamespaceMeta

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

def toxpath(path, default_ns=None, nsmap=nsmap):
    nodes = []
    pref = '{%s}' % default_ns if default_ns else ''
    for node in [x.split(':', 1) for x in path.split('/')]:
        if len(node) == 1:
            nodes.append(pref + node[0])
        else:
            if node[0] in nsmap:
                nodes.append('{%s}%s' % (nsmap[node[0]], node[1]))
            else:
                nodes.append(':'.join(node))
    return '/'.join(nodes)

def mkxp(default_ns=None, nsmap=nsmap):
    def _mkxp(path, default_ns=default_ns, nsmap=nsmap):
        return toxpath(path, default_ns, nsmap)
    return _mkxp

def get_outip(remote_host):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((remote_host, 80))
    return sock.getsockname()[0]

def make_gmt():
    return to_gmt(time.gmtime())

def to_gmt(t):
    return time.strftime('%a, %d %b %Y %H:%M:%S GMT', t)

def not_found(environ, start_response):
    headers = [
        ('Content-type', 'text/plain'),
        ('Connection', 'close'),
    ]
    start_response('404 Not Found', headers)
    return ['Not Found']

def build_packet(first_line, packet):
    lines = [first_line]
    lines += [': '.join(t) for t in packet]
    lines += ['', '']
    return '\r\n'.join(lines)

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

    def get_name(self):
        return self.action.tag.split('}')[1][1:]

    def get_header(self):
        return '"%s#%s"' % (self.u, self.get_name)

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


class SoapError(object):

    TEMPLATE = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
    s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <s:Fault>
      <faultcode>s:Client</faultcode>
      <faultstring>UPnPError</faultstring>
      <detail>
        <UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
          <errorCode>%s</errorCode>
          <errorDescription>%s</errorDescription>
        </UPnPError>
      </detail>
    </s:Fault>
  </s:Body>
</s:Envelope>
"""

    def __init__(self, code=501, desc='Action Failed'):
        self.code = str(code)
        self.desc = desc

    def tostring(self):
        return self.TEMPLATE % (self.code, self.desc)

    @classmethod
    def parse(cls, text):
        doc = ET.XML(text)
        elem = toxpath('s:Body/s:Fault/detail/control:UPnPError')
        code = int(elem.findtext(toxpath('control:errorCode')))
        desc = elem.findtext(toxpath('control:errorDescription'), '')
        return SoapError(code, desc)


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


xp = mkxp(ns.device)


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
        self.dd.find(xp('device/UDN')).text = udn

        # get deviceType
        self.deviceType = self.dd.findtext(xp('device/deviceType'))

        self.services = {}
        self.serviceTypes = []
        for service in self.dd.find(xp('device/serviceList')):
            sid = service.findtext(xp('serviceId'), '')

            # SCPDURL
            scpdurl = service.find(xp('SCPDURL'))
            self.services[sid] = ET.parse(os.path.join(xml_dir, scpdurl.text))
            scpdurl.text = '/'.join(('', self.udn, sid))

            # controlURL
            service.find(xp('controlURL')).text = scpdurl.text + '/soap'

            # eventSubURL
            service.find(xp('eventSubURL')).text = scpdurl.text + '/sub'

            # append serviceType
            serviceType = service.findtext('{%s}serviceType' % ns.device, '')
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
    SSDP_INTERVAL = 0.020

    def __init__(self):
        self.started = False
        self.reactor = None
        self.interfaces = []
        self.tpool = ThreadPool(name=self.__class__.__name__)
        self.devices = {}
        self.mts = {}

        # setup route map
        self.map = self._make_map()
        self.app = RoutesMiddleware(self, self.map)

    def _make_map(self):
        m = Mapper()
        m.connect('mt/:name/*id', controller='mt', action='get')
        m.connect(':udn/:sid/:action', controller='upnp', action='desc', sid=None)
        return m

    def append_device(self, devices, interval=SSDP_INTERVAL):
        for device in devices:
            delay = 0
            if device.udn in self.devices:
                self.remove_device(device.udn)
                if interval:
                    delay = 0.3
            self.devices[device.udn] = device
            self._notify(device, 'ssdp:alive', delay, interval)

    def remove_device(self, udn, interval=SSDP_INTERVAL):
        try:
            device = self.devices[udn]
            self._notify(device, 'ssdp:byebye', interval=interval)
            del self.devices[udn]
        except KeyError:
            pass

    def append_mt(self, mt):
        if mt.name in self.mts:
            remove_mt(mt.name)
        self.mts[mt.name] = mt

    def remove_mt(self, name):
        del self.mts[name]

    def _notify_all(self, nts, interval=SSDP_INTERVAL):
        if not self.started:
            return
        for udn in self.devices:
            self._notify(self.devices[udn], nts, interval=interval)

    def _notify(self, device, nts, delay=0, interval=SSDP_INTERVAL):
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
            host = self.SSDP_ADDR + ':' + str(self.SSDP_PORT)
            for packet in device.make_notify_packets(host, ip, self.port, nts):
                buff = build_packet('NOTIFY * HTTP/1.1', packet)
                if interval:
                    self.reactor.callLater(delay, self._send_packet, port, buff, self._addr)
                    delay += interval
                else:
                    self._send_packet(port, buff, self._addr)

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
                delay += self.SSDP_INTERVAL

    def __call__(self, environ, start_response):
        """
        This function have to be called in a worker thread, not the IO thread.
        """
        rargs = environ['wsgiorg.routing_args'][1]
        controller = rargs['controller']

        # Media Transport
        if controller == 'mt':
            name = rargs['name']
            if name in self.mts:
                return self.mts[name](environ, start_response)
            else:
                return not_found(environ, start_response)

        if controller != 'upnp':
            return not_found(environ, start_response)

        try:
            udn = rargs['udn']
            if isInIOThread():
                # TODO: read request body
                return self.devices[udn](environ, start_response)
            else:
                # read request body
                input = environ['wsgi.input']
                environ['upnp.body'] = input.read(self.SOAP_BODY_MAX)
                # call the app in IO thread
                args = [udn, environ, start_response]
                blockingCallFromThread(self.reactor, self._call_handler, args)
                return args[3]
        except Exception, e:
            #print e
            #print 'Unknown access: ' + environ['PATH_INFO'] 
            return not_found(environ, start_response)

    def _call_handler(self, args):
        ret = self.devices[args[0]](args[1], args[2])
        args.append(ret)

    def start(self, reactor, interfaces=[INADDR_ANY], http_port=0):
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
        self.http = self.reactor.listenTCP(http_port, server.Site(resource))
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


class IContent(Interface):

    def __iter__():
        """Returns the content stream"""

    def length(whence=1):
        """Returns the content length."""

    def set_range(first, last=-1):
        """Sets content range in byte."""

    def get_type():
        """Returns Content-Type header value."""

    def get_features():
        """Returns contentFeatures.dlna.org header value."""


class FileContent(object):

    implements(IContent)
    readsize = 32 * 1024

    def __init__(self, filename):
        self.filename = filename
        self.f = open(filename, 'rb')
        self.last = -1
        self.pos = 0

    def __del__(self):
        self.f.close()

    def __iter__(self):
        while True:
            size = self.readsize
            if self.last >= 0:
                remain = self.last - self.pos + 1
                if remain < size:
                    size = remain
                if size == 0:
                    break
            buff = self.f.read(size)
            x = len(buff)
            if x <= 0:
                break
            self.pos += x
            yield buff
        raise StopIteration()

    def seek(self, pos, whence=0):
        self.f.seek(pos, whence)
        self.pos = pos

    def length(self, whence=1):
        pos = start = self.f.tell()
        if whence == 0:
            start = 0
        self.f.seek(0, 2)
        ret = self.f.tell()
        self.f.seek(pos)
        return ret - start

    def set_range(self, first, last=-1):
        length = self.length(0)
        if first < 0:
            raise ValueError('invalid range: first(%d) < 0' % first)
        if last >= 0 and first > last:
            raise ValueError('invalid range: first(%d) > last(%d)' % (first, last))
        if last < 0 or length <= last:
            last = length - 1
        self.seek(first)
        self.last = last
        return '%d-%d/%d' % (first, last, length)

    def get_type(self):
        return 'application/octet-stream'

    def get_features(self):
        return None

    def get_mtime(self):
        return to_gmt(time.gmtime(os.path.getmtime(self.filename)))


class StreamingServer(object):
    def __init__(self, name):
        self.name = name

    def __call__(self, environ, start_response):
        # response values
        code = '405 Method Not Allowed'
        headers = []
        body = []

        # params
        method = environ['REQUEST_METHOD']
        id = environ['wsgiorg.routing_args'][1]['id']

        if method == 'HEAD' or method == 'GET':
            # check if the file exists
            content = self.get_content(id, environ)
            if content != None:
                code = '200 OK'
                headers.append(('Content-type', content.get_type()))

            headers.append(('contentFeatures.dlna.org', content.get_features()))

            # get content body
            if method == 'GET':
                body = content

                # Byte seek
                if 'HTTP_RANGE' in environ:
                    code = '206 Partial Content'
                    try:
                        fbp, lbp = environ['HTTP_RANGE'].split()[0].split('=')[1].split('-')
                        lbp = -1 if lbp == '' else int(lbp)
                        content_range = 'bytes ' + content.set_range(int(fbp), lbp)
                        headers.append(('Content-Range', content_range))
                    except (IOError, ValueError):
                        code = '416 Requested Range Not Satisfiable'
                        body = []

        start_response(code, headers)
        return body

    def get_content(self, id, environ):
        return Content(id)


def _test():
    import doctest
    doctest.testmod()


if __name__ == '__main__':
    _test()

    from sys import argv
    from uuid import uuid1
    from optparse import OptionParser
    from twisted.internet import reactor
    from pkg_resources import resource_filename

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

    resource_filename(__name__, 'xml/cds.xml')
    resource_filename(__name__, 'xml/cms.xml')

    # parse options
    parser = OptionParser(usage='%prog [options]')
    default_udn = 'uuid:00000000-0000-0000-001122334455'
    #default_udn = 'uuid:' + str(uuid1())
    parser.add_option('-u', '--udn', dest='udn', default=default_udn)
    parser.add_option('-d', '--desc', dest='desc', default='xml/ms.xml')
    options, args = parser.parse_args(argv)

    dd = resource_filename(__name__, options.desc)
    device = UpnpDevice(options.udn, dd, soap_app)
    base = UpnpBase()
    base.append_device([device])
    base.start(reactor)
    
    def stop():
        base.remove_device(device.udn)
        base.stop()
        reactor.stop()

    reactor.callLater(15, stop)
    reactor.run()

