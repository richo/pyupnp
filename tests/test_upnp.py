from StringIO import StringIO
from httplib import HTTPMessage
from xml.etree import ElementTree as ET
from pkg_resources import resource_filename
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

    # make_desc_path
    assert '/udn' == base.make_desc_path('udn')
    assert '/udn/sid' == base.make_desc_path('udn', 'sid')


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
    location = 'http://%s:%d/%s' % (ip, port, udn)

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
        app = TestApp(RoutesMiddleware(device, base.map))
        # DD
        res = app.get('/' + udn)
        # SCPD
        res = app.get('/%s/%s' % (udn, sid))
        # SOAP
        #res = app.get('/%s/%s/%s' % (udn, sid, 'soap'))
    except ImportError:
        pass

