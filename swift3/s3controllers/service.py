#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: Kun Huang <academicgareth@gmail.com>
# Created Time: 05/28/13 15:30:51 (CST)
# Modified Time: 05/28/13 16:14:14 (CST)


from urllib import unquote, quote
from simplejson import loads
from xml.sax.saxutils import escape as xml_escape
from swift3.s3controllers.base import BaseController

from swift.common.wsgi import WSGIContext
from swift.common.http import HTTP_OK, HTTP_CREATED, HTTP_ACCEPTED, \
    HTTP_NO_CONTENT, HTTP_BAD_REQUEST, HTTP_UNAUTHORIZED, HTTP_FORBIDDEN, \
    HTTP_NOT_FOUND, HTTP_CONFLICT, HTTP_UNPROCESSABLE_ENTITY, is_success, \
    HTTP_NOT_IMPLEMENTED, HTTP_LENGTH_REQUIRED, HTTP_SERVICE_UNAVAILABLE
from swift.common.swob import Request, Response

class ServiceController(BaseController):
    """
    Handles account level requests.
    """
    def __init__(self, env, app, account_name, token, **kwargs):
        WSGIContext.__init__(self, app)
        self.account = unquote(account_name)
        env['HTTP_X_AUTH_TOKEN'] = token
        env['PATH_INFO'] = '/v1/AUTH_%s' % account_name

    def GET(self, env, start_response):
        """
        Handle GET Service request
        """
        env['QUERY_STRING'] = 'format=json'
        body_iter = self._app_call(env)
        status = self._get_status_int()

        if not is_success(status):
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return self.get_err_response('AccessDenied')
            else:
                return self.get_err_response('InvalidURI')

        if status == HTTP_OK:
            containers = loads(''.join(list(body_iter)))
            # we don't keep the creation time of a backet (s3cmd doesn't
            # work without that) so we use something bogus.
            body = '<?xml version="1.0" encoding="UTF-8"?>' \
                   '<ListAllMyBucketsResult ' \
                   'xmlns="http://doc.s3.amazonaws.com/2006-03-01">' \
                   '<Buckets>%s</Buckets>' \
                   '</ListAllMyBucketsResult>' \
                   % ("".join(['<Bucket><Name>%s</Name><CreationDate>'
                               '2009-02-03T16:45:09.000Z</CreationDate></Bucket>'
                               % xml_escape(i['name']) for i in containers]))
            resp = Response(status=HTTP_OK, content_type='application/xml',
                            body=body)
            return resp
        elif status == HTTP_NO_CONTENT:
            data = {'ListAllMyBucketsResult':{'Owner':{'ID':self.account,'DisplayName':self.account},'Buckets':''}}
            body = self.dict2xmlbody(data)
            return Response(status=HTTP_OK, content_type='application/xml', body=body)
        else:
            raise ValueError('service.GET:unknown swift proxy response status')
