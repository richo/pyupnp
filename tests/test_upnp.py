# -*- coding: utf-8 -*-

from StringIO import StringIO
from httplib import HTTPMessage
from xml.etree import ElementTree as ET
from pkg_resources import resource_filename
from zope.interface import implements
from twisted.internet import reactor
from twisted.python.threadpool import ThreadPool
from twisted.web import server, resource, wsgi, static
from routes import Mapper
from routes.middleware import RoutesMiddleware

from pyupnp import upnp
from pyupnp.upnp import *


def test_toxpath():
    xpath = toxpath('x:b/y:d/f/g:h/:i', 'e', {'x': 'a', 'y': 'c'})
    assert '{a}b/{c}d/{e}f/g:h/:i' == xpath

    xpath = toxpath('a:b/c')
    assert 'a:b/c' == xpath


def test_mkxp():
    xp = mkxp('e', {'x': 'a', 'y': 'c'})
    xpath = xp('x:b/y:d/f/g:h/:i')
    assert '{a}b/{c}d/{e}f/g:h/:i' == xpath


def test_build_packet():
    first_line = 'NOTIFY * HTTP/1.1'
    packet = [
        ('HOST', '127.0.0.1:80'),
        ('Connection', 'close'),
    ]
    expected = 'NOTIFY * HTTP/1.1\r\n'
    expected += 'HOST: 127.0.0.1:80\r\n'
    expected += 'Connection: close\r\n\r\n'
    actual = upnp.build_packet(first_line, packet)
    assert expected == actual


def test_SoapMessage():
    soap = SoapMessage('type', 'action')

    # get_name
    assert 'action' == soap.get_name()

    # get_header
    assert '"type#action"' == soap.get_header()

    # get_arg
    assert '' == soap.get_arg('a1', '')
    assert None == soap.get_arg('a1', None)
    assert 'abc' == soap.get_arg('a1', 'abc')

    # set_args
    soap.set_args([('a1', 'v1'), ('a2', 'v2')])

    # get_arg
    assert 'v1' == soap.get_arg('a1')
    assert 'v1' == soap.get_arg('a1', 'abc')
    assert 'v2' == soap.get_arg('a2')
    assert '' == soap.get_arg('a3')
    assert 'abc' == soap.get_arg('a3', 'abc')

    # get_args
    assert [('a1', 'v1'), ('a2', 'v2')] == soap.get_args()

    # set_arg (add)
    soap.set_arg('a3', 'v3')
    assert 'v3' == soap.get_arg('a3')

    # set_arg (update)
    soap.set_arg('a1', 'new one')
    assert 'new one' == soap.get_arg('a1')

    # del_arg
    soap.del_arg('a1')
    assert '' == soap.get_arg('a1')
    assert None == soap.get_arg('a1', None)
    assert 'abc' == soap.get_arg('a1', 'abc')

    # parse
    text = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope
    xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
    s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:ActionName xmlns:u="ActionNamespace">
      <arg0>value0</arg0>
      <arg1>value1</arg1>
    </u:ActionName>
  </s:Body>
</s:Envelope>
"""
    msg = SoapMessage.parse(StringIO(text))
    assert 'ActionName' == msg.get_name()
    assert 'ActionNamespace' == msg.u
    assert '"ActionNamespace#ActionName"' == msg.get_header()

    # tostring
    def _check_elem(elem0, elem1):
        # check element name and value
        assert elem0.tag == elem1.tag
        assert elem0.text == elem1.text

        # check all attributes
        assert set(elem0.attrib.items()) == set(elem1.attrib.items())

        # check all children
        children0 = elem0.getchildren()
        children1 = elem1.getchildren()
        assert len(children0) == len(children1)
        for child0, child1 in zip(children0, children1):
            _check_elem(child0, child1)

    _check_elem(msg.doc, ET.XML(msg.tostring()))

    # encoding check
    msg.set_arg('mbarg', '日本語')
    _check_elem(msg.doc, ET.XML(msg.tostring()))


def test_SoapError():
    code = 123
    desc = 'desc'
    soap = SoapError(code, desc)

    # tostring, parse
    clone = SoapError.parse(soap.tostring())
    assert str(code) == clone.code
    assert desc == clone.desc


def test_SoapMiddleware():
    SoapMiddleware = upnp.SoapMiddleware

    pair = [None, None]
    def app(environ, start_response):
         assert pair[0] == environ.get('upnp.soap.serviceType', None)
         assert pair[1] == environ.get('upnp.soap.action', None)

    for x in ('a', ''):
        for y in ('b', '', '#', 'c#', '#c', 'c#c', 'd e f'):
            pair = (x, y)
            SoapMiddleware(app)({'HTTP_SOAPACTION': '"%s#%s"' % (x, y)}, None)
            SoapMiddleware(app)({'HTTP_SOAPACTION': '%s#%s' % (x, y)}, None)

    pair = (None, None)
    SoapMiddleware(app)({'HTTP_SOAPACTION': 'xxx'}, None)
    SoapMiddleware(app)({}, None)


def test_UpnpBase():
    # __init__
    base = UpnpBase()

    # make_mt_path
    assert '/mt/name/id' == base.make_mt_path('name', 'id')


def test_UpnpDevice():
    xp = mkxp(ns.device)
    udn = 'uuid:00000000-0000-0000-001122334455'
    server_name = 'OS/1.0 UPnP/1.0 pyupnp/1.0'

    dd = resource_filename(upnp.__name__, 'xml/ms.xml')
    resource_filename(upnp.__name__, 'xml/cds.xml')
    resource_filename(upnp.__name__, 'xml/cms.xml')

    def soap_app(environ, start_response):
        pass

    # __init__
    device = UpnpDevice(udn, dd, None)
    assert udn == device.udn
    assert UpnpDevice.SERVER_NAME == device.server_name
    assert None == device.soap_app
    assert udn == device.dd.findtext(xp('device/UDN'))

    device = UpnpDevice(udn, dd, soap_app, server_name)
    assert udn == device.udn
    assert server_name == device.server_name
    assert soap_app == device.soap_app.app
    assert udn == device.dd.findtext(xp('device/UDN'))

    # make_notify_packets
    host = '127.0.0.1:1900'
    ip = '192.168.0.100'
    port = 19000
    addr = (ip, port)
    dest = '192.168.0.101'
    location = device.make_location(ip, port)

    sa = device.make_notify_packets(host, ip, port, 'ssdp:alive')
    sb = device.make_notify_packets(host, ip, port, 'ssdp:byebye')

    for packets in (sa, sb):
        for packet in packets:
            d = dict(packet)
            assert host == d.get('HOST')
            assert d.get('USN').startswith(udn)
            if d.get('NTS') == 'ssdp:alive':
                assert location == d.get('LOCATION')
                assert device.server_name == d.get('SERVER')

    # make_msearch_response
    # ssdp:all
    headers = HTTPMessage(StringIO('ST: ssdp:all'))
    packets = device.make_msearch_response(headers, addr, dest)
    assert 3 + 2 * 0 + len(device.services) == len(packets)
    for packet in packets:
        d = dict(packet)
        assert '' == d.get('EXT')
        assert location == d.get('LOCATION')
        assert device.server_name == d.get('SERVER')
        assert d.get('USN').startswith(device.udn)

    # invalid ST
    headers = HTTPMessage(StringIO('ST: xxxx'))
    packets = device.make_msearch_response(headers, addr, dest)
    assert [] == packets

    # UDN
    headers = HTTPMessage(StringIO('ST: ' + device.udn))
    packets = device.make_msearch_response(headers, addr, dest)
    assert 1 == len(packets)
    d = dict(packets[0])
    assert '' == d.get('EXT')
    assert location == d.get('LOCATION')
    assert device.server_name == d.get('SERVER')
    assert device.udn == d.get('ST') == d.get('USN')

    # serviceType
    for serviceType in device.serviceTypes + ['upnp:rootdevice']:
        headers = HTTPMessage(StringIO('ST: ' + serviceType))
        packets = device.make_msearch_response(headers, addr, dest)
        assert 1 == len(packets)
        d = dict(packets[0])
        assert '' == d.get('EXT')
        assert location == d.get('LOCATION')
        assert device.server_name == d.get('SERVER')
        assert serviceType == d.get('ST')
        assert '%s::%s' % (device.udn, serviceType) == d.get('USN')

    # __call__
    try:
        from webtest import TestApp
        from routes.middleware import RoutesMiddleware
        sid = 'urn:upnp-org:serviceId:ConnectionManager'
        base = UpnpBase()
        app = TestApp(RoutesMiddleware(device, base.mapper))
        # DD
        res = app.get('/upnp/' + udn)
        # SCPD
        res = app.get('/upnp/%s/%s' % (udn, sid))
        # SOAP
        #res = app.get('/%s/%s/%s' % (udn, sid, 'soap'))
    except ImportError:
        pass


def test_parse_npt():
    testcase = [
        # S+
        (('0'), 0.000, None),
        (('1'), 1.000, None),
        (('59'), 59.000, None),
        (('60'), 60.000, None),
        (('100'), 100.000, None),
        (('1000'), 1000.000, None),
        (('10000'), 10000.000, None),
        (('100000'), 100000.000, None),
        (('1000000'), 1000000.000, None),
        (('10000000'), 10000000.000, None),
        (('100000000'), 100000000.000, None),
        (('1000000000'), 1000000000.000, None),
        (('10000000000'), 10000000000.000, None),
        (('100000000000'), 100000000000.000, None),
        (('1000000000000'), 1000000000000.000, None),
        (('10000000000000'), 10000000000000.000, None),
        (('100000000000000'), 100000000000000.000, None),
        # S+.sss
        (('0.0'), 0.0, None),
        (('0.1'), 0.1, None),
        (('0.00'), 0.0, None),
        (('0.01'), 0.01, None),
        (('0.10'), 0.10, None),
        (('0.000'), 0.000, None),
        (('0.001'), 0.001, None),
        (('0.010'), 0.010, None),
        (('0.100'), 0.100, None),
        (('0.999'), 0.999, None),
        (('1.000'), 1.000, None),
        (('1.001'), 1.001, None),
        (('1.999'), 1.999, None),
        (('01.999'), 1.999, None),
        (('10.000'), 10.000, None),
        (('10.001'), 10.001, None),
        (('10.999'), 10.999, None),
        (('59.999'), 59.999, None),
        (('60.000'), 60.000, None),
        (('100.000'), 100.000, None),
        (('0.0000'), None, ValueError),
        # H+:MM:SS(.sss)
        (('0:00:00'), 0.000, None),
        (('0:00:01'), 1.000, None),
        (('0:00:59'), 59.000, None),
        (('0:00:60'), None, ValueError),
        (('0:01:00'), 1 *60 * 1.0, None),
        (('0:59:00'), 59 * 60 * 1.0, None),
        (('0:60:00'), None, ValueError),
        (('00:00:00'), 0.000, None),
        (('01:00:00'), 1 * 60 * 60 * 1.0, None),
        (('59:00:00'), 59 * 60 * 60 * 1.0, None),
        (('60:00:00'), 60 * 60 * 60 * 1.0, None),
        (('0:01:01'), 61.0, None),
        (('0:01:59'), 60.0 + 59.0, None),
        (('0:01:60'), None, ValueError),
        (('1:01:01'), 3600.0 + 61.0, None),
        (('1:01:59'), 3600.0 + 60.0 + 59.0, None),
        (('1:01:60'), None, ValueError),
        (('0:59:59'), 59.0 * 60.0 + 59.0, None),
        (('1:59:59'), 3600.0 + 59.0 * 60.0 + 59.0, None),
        (('0:01:60'), None, ValueError),
        (('0:60:60'), None, ValueError),
        (('1:01:60'), None, ValueError),
        (('1:60:60'), None, ValueError),
        (('00:00'), None, ValueError),
        ((':00:00'), None, ValueError),
        (('0:00'), None, ValueError),
        (('0:00:'), None, ValueError),
        (('0::00'), None, ValueError),
        (('0:0:00'), None, ValueError),
        (('0:00:0'), None, ValueError),
        (('0:00:000'), None, ValueError),
        (('0:000:00'), None, ValueError),
        # H+:MM:SS.sss
        (('0:00:00.0'), 0.0, None),
        (('0:00:00.1'), 0.1, None),
        (('0:00:00.9'), 0.9, None),
        (('0:00:00.00'), 0.0, None),
        (('0:00:00.01'), 0.01, None),
        (('0:00:00.10'), 0.10, None),
        (('0:00:00.99'), 0.99, None),
        (('0:00:00.000'), 0.000, None),
        (('0:00:00.001'), 0.001, None),
        (('0:00:00.010'), 0.010, None),
        (('0:00:00.100'), 0.100, None),
        (('0:00:00.999'), 0.999, None),
        (('0:00:01.000'), 1.000, None),
        (('0:00:01.001'), 1.001, None),
        (('0:00:01.010'), 1.010, None),
        (('0:00:01.100'), 1.100, None),
        (('0:00:01.999'), 1.999, None),
        (('0:01:01.000'), 60.0 + 1.000, None),
        (('0:01:01.001'), 60.0 + 1.001, None),
        (('0:01:01.010'), 60.0 + 1.010, None),
        (('0:01:01.100'), 60.0 + 1.100, None),
        (('0:01:01.999'), 60.0 + 1.999, None),
        (('1:01:01.000'), 3600.0 + 60.0 + 1.000, None),
        (('1:01:01.001'), 3600.0 + 60.0 + 1.001, None),
        (('1:01:01.010'), 3600.0 + 60.0 + 1.010, None),
        (('1:01:01.100'), 3600.0 + 60.0 + 1.100, None),
        (('1:01:01.999'), 3600.0 + 60.0 + 1.999, None),
        (('0:00:00.'), None, ValueError),
        (('0:00:00.0000'), None, ValueError),
        # Errors
        (('x'), None, ValueError),
        (('x.xxx'), None, ValueError),
        (('x:xx:xx'), None, ValueError),
        (('x:xx:xx.xxx'), None, ValueError),
        (('x0'), None, ValueError),
        (('0x'), None, ValueError),
        (('0x0'), None, ValueError),
        (('0.xxx'), None, ValueError),
        (('0.0x0'), None, ValueError),
        (('x:00:00'), None, ValueError),
        (('0:xx:00'), None, ValueError),
        (('0:00:xx'), None, ValueError),
        (('x:00:00.000'), None, ValueError),
        (('0:xx:00.000'), None, ValueError),
        (('0:00:xx.000'), None, ValueError),
        (('0:00:00.xxx'), None, ValueError),
        (('0x:00:00.000'), None, ValueError),
        (('0:0x:00.000'), None, ValueError),
        (('0:00:0x.000'), None, ValueError),
        (('0:00:00.00x'), None, ValueError),
    ]

    for npt_time, expected, exc in testcase:
        try:
            result = parse_npt(npt_time)
            assert expected == result
            tmp = to_npt(result)
            print result, tmp
            assert expected == parse_npt(tmp)
        except Exception, e:
            #print npt_time, e
            assert exc == e.__class__


class ContentStub(object):
    implements(IContent)
    chunk_size = 8 * 1024

    def __init__(self, size, content_type, content_features):
        self.first = 0
        self.last = size - 1
        self.size = size
        self.content_type = content_type
        self.content_features = content_features

    def __iter__(self):
        datalen = self.last - self.first + 1
        extra = datalen % self.chunk_size
        n = self.first % 10
        for i in xrange(int(datalen / self.chunk_size)):
            yield "".join(['%i' % ((x + n) % 10) for x in xrange(self.chunk_size)])
            n = (n + self.chunk_size) % 10
        yield "".join(['%i' % ((x + n) % 10) for x in xrange(extra)])
    
    def length(self, whence=1):
        if whence == 0:
            return self.size
        if whence == 1:
            return self.size - self.first
        raise ValueError('invalid parameter: whence=%d' % whence)

    def set_range(self, first, last=-1):
        length = self.length(0)
        if first >= self.size:
            raise ValueError('invalid range: first(%s)' % first)
        if last < 0:
            last = length - 1
        elif first > last:
            raise ValueError('invalid range: first(%s) > last(%s)' % (first, last))
        elif length <= last:
            last = length - 1
        self.first = first
        self.last = last
        return '%i-%i/%i' % (self.first, self.last, length)

    def get_type(self):
        return self.content_type

    def get_features(self):
        return self.content_features


def _test_StreamingServer():
    expected_id = 'test'
    headers = {
        #'TimeSeekRange.dlna.org': 'npt=30.000-',
        'TimeSeekRange.dlna.org': 'npt=20.000-50.000',
        #'Range': 'bytes=5-',
        'Connection': 'close',
    }
    duration = '00:01:00'
    content_length = 64 * 1024
    interface = '192.168.0.103'

    class StreamingServerStub(ByteSeekMixin, TimeSeekMixin, StreamingServer):
        def get_content(self, id, environ):
            assert expected_id == id
            #raise ValueError(repr(environ))
            for k in headers:
                assert headers[k] == environ['HTTP_' + k.upper()]
            return ContentStub(content_length,
                               'video/mpeg',
                               'DLNA.ORG_PN=MPEG_PS_NTSC;DLNA.ORG_OP=11')

    from twisted.web import client

    class HTTPPageGetter(client.HTTPPageGetter):
        handleStatus_206 = lambda self: self.handleStatus_200()

    class HTTPClientFactory(client.HTTPClientFactory):
        protocol = HTTPPageGetter

    def getPageFactory(url, *args, **kwargs):
        scheme, host, port, path = client._parse(url)
        factory = HTTPClientFactory(url, *args, **kwargs)
        reactor.connectTCP(host, port, factory)
        return factory

    app = StreamingServerStub('test')

    mapper = Mapper()
    mapper.connect(':id', controller='mt', action='get')
    app = RoutesMiddleware(app, mapper)

    tpool = ThreadPool()
    tpool.start()
    resource = upnp.WSGIResource(reactor, tpool, app)
    port = reactor.listenTCP(0, server.Site(resource), interface=interface)

    port_num = port.socket.getsockname()[1]
    url = 'http://%s:%i/%s?duration=%s' % (interface, port_num, expected_id, duration)
    factory = getPageFactory(url, headers=headers)
    def check_result(contents):
        raise ValueError('expected: %d, actual: %d' % (content_length, len(contents)))
        #raise ValueError(repr(factory.response_headers))
        assert content_length == len(contents)
    factory.deferred.addCallback(check_result)

    reactor.callLater(5, reactor.stop)
    reactor.run()

