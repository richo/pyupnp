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
import dircache
from cStringIO import StringIO
from xml.etree import ElementTree as ET
from routes import url_for
import upnp


class wrapper(object):
    def __init__(self, callable):
        self.callable = callable

    def __call__(self, environ, start_response):
        if 0:
            print '------'
            for key in sorted(environ.keys()):
                print key, environ[key]
    
        try:
            return self.callable(environ, start_response)
        except Exception, e:
            print e
            raise


formats = {
    '.jpg' : ('object.item.imageItem', 'image/jpeg', 'DLNA.ORG_OP=01'),
    '.png' : ('object.item.imageItem', 'image/png', 'DLNA.ORG_OP=01'),
    '.mp3' : ('object.item.audioItem', 'audio/mpeg', 'DLNA.ORG_OP=01'),
    '.mpg' : ('object.item.videoItem', 'video/mpeg', 'DLNA.ORG_OP=01'),
}

nsmap = {
    'xmlns:dc'   : upnp.ns.dc,
    'xmlns:upnp' : upnp.ns.upnp,
    'xmlns'      : upnp.ns.didl
}


class MediaServer(object):
    def __init__(self, content_dir=os.path.curdir):
        self.content_dir = unicode(content_dir)

    def toresult(self, objs, parent, environ):
        root = ET.Element('DIDL-Lite', nsmap)
        base_url = 'http://' + environ['SERVER_NAME'] + ':' + environ['SERVER_PORT']
        for name, ext in objs:
            tag = 'item'
            resources = []
            id = name[len(self.content_dir):]
            if os.path.isdir(name):
                tag = 'container'
                upnpclass = 'object.container'
            else:
                upnpclass = formats[ext][0]
                url = base_url + url_for(controller='mt', action='get', name='ms', id=id)
                protocolInfo = 'http-get:*:%s:%s' % formats[ext][1:]
                resources.append((protocolInfo, url))
            props = [
                ('upnp:class', upnpclass),
                ('dc:title', os.path.basename(name)),
            ]
            atts = {
                'id' : id.encode('utf-8'),
                'restricted' : '1',
                'parentID' : parent.encode('utf-8'),
            }
            elem = ET.SubElement(root, tag, atts)
            for prop in props:
                ET.SubElement(elem, prop[0]).text = prop[1]
            for res in resources:
                ET.SubElement(elem, 'res', {'protocolInfo' : res[0]}).text = res[1]
        return upnp.xml_tostring(root, xml_decl=True)

    def make_browse_response(self, req, environ):
        serviceType = environ['upnp.soap.serviceType']
        action = environ['upnp.soap.action']

        # inargs
        id = req.get_arg('ObjectID')
        flag = req.get_arg('BrowseFlag')
        start = int(req.get_arg('StartingIndex'))
        count = int(req.get_arg('RequestedCount'))
        order = req.get_arg('SortCriteria')
    
        parent = id
        if id == '0':
            id = self.content_dir
        else:
            id = os.path.normpath(os.path.join(self.content_dir, id))

        if not os.path.exists(id) or not id.startswith(self.content_dir):
            return upnp.SoapError(701, 'No such object')

        # out args
        objs = []
        matched = 0

        if flag == 'BrowseMetadata':
            ext = os.path.splitext(id)[1]
            objs.append((id, ext))
            matched = 1
            parent = os.path.dirname(parent)[len(self.content_dir):]
            if parent == '':
                parent = '0'
        elif flag == 'BrowseDirectChildren':
            for name in dircache.listdir(id):
                if name.startswith('.'):
                    continue
                ext = os.path.splitext(name)[1]
                name = os.path.normpath(os.path.join(id, name))
                if os.path.isfile(name) and ext in formats:
                    pass
                elif os.path.isdir(name):
                    pass
                else:
                    continue
                matched += 1
                if matched <= start:
                    continue
                if len(objs) < count:
                    objs.append((name, ext))
        else:
            return upnp.SoapError(402, 'Invalid args')

        resp = upnp.SoapMessage(serviceType, action + 'Response')
        resp.set_arg('Result', self.toresult(objs, parent, environ))
        resp.set_arg('NumberReturned', str(len(objs)))
        resp.set_arg('TotalMatches', str(matched))
        resp.set_arg('UpdateID', '0')
        return resp

    def __call__(self, environ, start_response):
    
        code = '200 OK'
        headers = [
            ('Content-type', 'text/xml; charset="utf-8"'),
        ]
    
        #sid = environ['wsgiorg.routing_args'][1]['sid']
        serviceType = environ['upnp.soap.serviceType']
        action = environ['upnp.soap.action']
        req = upnp.SoapMessage.parse(StringIO(environ['upnp.body']),
                                     serviceType, action)
    
        if action == 'Browse':
            resp = self.make_browse_response(req, environ)
    
        elif action == 'GetSortCapabilities':
            resp = upnp.SoapMessage(serviceType, action + 'Response')
            resp.set_arg('SortCaps', '')
    
        elif action == 'GetProtocolInfo':
            resp = upnp.SoapMessage(serviceType, action + 'Response')
            sources = []
            for ext in formats:
                sources.append('http:*:%s:%s' % formats[ext][1:])
            resp.set_args([('Source', ",".join(sources)), ('Sink', '')])
    
        else:
            return upnp.not_found(environ, start_response)
    
        # Content-Length
        buff = resp.tostring()
        if environ['SERVER_PROTOCOL'] == 'HTTP/1.0':
            headers.append(('Content-Length', str(len(buff))))
    
        start_response('200 OK', headers)
        return [buff]


class File(upnp.FileContent):
    def __init__(self, filename):
        upnp.FileContent.__init__(self, filename)
        self.ext = os.path.splitext(os.path.basename(self.filename))[1]

    def get_type(self):
        if self.ext in formats:
            return formats[self.ext][1]
        return upnp.FileContent.get_type(self)

    def get_features(self):
        if self.ext in formats:
            return formats[self.ext][2]
        return upnp.FileContent.get_features(self)


class StreamingServer(upnp.ByteSeekMixin, upnp.TimeSeekMixin, upnp.StreamingServer):
    def __init__(self, name, content_dir=os.path.curdir):
        upnp.StreamingServer.__init__(self, name)
        self.content_dir = unicode(content_dir)

    def get_content(self, id, environ):
        return File(os.path.join(self.content_dir, id))


if __name__ == '__main__':
    import sys
    from uuid import uuid1
    from getopt import gnu_getopt
    from twisted.internet import reactor

    if hasattr(sys, "setdefaultencoding"):
        sys.setdefaultencoding("utf-8")

    def is_frozen():
        import imp
        return (hasattr(sys, "frozen")
            or hasattr(sys, "importers")
            or imp.is_frozen("__main__"))

    def get_main_dir():
        if is_frozen():
            return os.path.abspath(os.path.dirname(sys.executable))
        return os.path.abspath(os.path.dirname(sys.argv[0]))

    # settings
    content_dir = 'content_dir'
    http_port = 0
    udn = 'uuid:00000000-0000-0000-001122334455'
    #udn = 'uuid:' + str(uuid1())
    dd = os.path.join(get_main_dir(), 'xml/ms.xml')

    # parse arguments
    long_opts = ['port=', 'content-dir=', 'udn=']
    optlist, args = gnu_getopt(sys.argv[1:], 'p:c:u:', long_opts)
    for name, value in optlist:
        if name in ('-p', '--port'):
            if 0 <= int(value) <= 65535:
                http_port = int(value)
        if name in ('-c', '--content-dir'):
            content_dir = value
        if name in ('-u', '--udn'):
            udn = value

    # prepare device
    device = upnp.UpnpDevice(udn, dd, wrapper(MediaServer(content_dir)))
    base = upnp.UpnpBase()
    base.append_device([device])
    base.append_mt(StreamingServer('ms', content_dir))

    # start working
    base.start(reactor, http_port=http_port)
    
    def stop():
        base.remove_device(udn, interval=0)
        base.stop()
        reactor.stop()

    reactor.callLater(30 * 6, stop)
    reactor.run()

