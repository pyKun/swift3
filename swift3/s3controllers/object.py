#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: Kun Huang <academicgareth@gmail.com>
# Created Time: 05/28/13 15:31:10 (CST)
# Modified Time: 05/28/13 16:33:05 (CST)

import urlparse
from urllib import unquote, quote
from lxml import etree

from swift3.s3controllers.base import BaseController
from swift.common.wsgi import WSGIContext
from swift.proxy.controllers.base import get_container_info
from swift.common.http import HTTP_OK, HTTP_CREATED, HTTP_ACCEPTED, \
    HTTP_NO_CONTENT, HTTP_BAD_REQUEST, HTTP_UNAUTHORIZED, HTTP_FORBIDDEN, \
    HTTP_NOT_FOUND, HTTP_CONFLICT, HTTP_UNPROCESSABLE_ENTITY, is_success, \
    HTTP_NOT_IMPLEMENTED, HTTP_LENGTH_REQUIRED, HTTP_SERVICE_UNAVAILABLE
from swift.common.swob import Request, Response

class ObjectController(BaseController):
    """
    Handles requests on objects
    """
    def __init__(self, env, app, account_name, token, container_name,
                 object_name, **kwargs):
        WSGIContext.__init__(self, app)
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)
        env['HTTP_X_AUTH_TOKEN'] = token
        env['PATH_INFO'] = '/v1/AUTH_%s/%s/%s' % (account_name, container_name,
                                                  object_name)

    def GETorHEAD(self, env, start_response):
        if 'QUERY_STRING' in env:
            args = dict(urlparse.parse_qsl(env['QUERY_STRING'], 1))
        else:
            args = {}

        # Let s3multi handle it.
        if 'uploadId' in args:
            return self.app(env, start_response)

        if 'acl' in args:
            # ACL requests need to make a HEAD call rather than GET
            env['REQUEST_METHOD'] = 'HEAD'
            env['SCRIPT_NAME'] = ''
            env['QUERY_STRING'] = ''

        app_iter = self._app_call(env)
        status = self._get_status_int()
        headers = dict(self._response_headers)

        if env['REQUEST_METHOD'] == 'HEAD':
            app_iter = None

        if is_success(status):
            if 'acl' in args:
                # Method must be GET or the body wont be returned to the caller
                env['REQUEST_METHOD'] = 'GET'
                return self.get_acl(self.account_name, headers)

            new_hdrs = {}
            for key, val in headers.iteritems():
                _key = key.lower()
                if _key.startswith('x-object-meta-'):
                    new_hdrs['x-amz-meta-' + key[14:]] = val
                elif _key in ('content-length', 'content-type',
                              'content-range', 'content-encoding',
                              'etag', 'last-modified'):
                    new_hdrs[key] = val
            return Response(status=status, headers=new_hdrs, app_iter=app_iter)
        elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
            return self.get_err_response('AccessDenied')
        elif status == HTTP_NOT_FOUND:
            return self.get_err_response('NoSuchKey')
        else:
            return self.get_err_response('InvalidURI')

    def HEAD(self, env, start_response):
        """
        Handle HEAD Object request
        """
        return self.GETorHEAD(env, start_response)

    def GET(self, env, start_response):
        """
        Handle GET Object request
        """
        return self.GETorHEAD(env, start_response)

    def PUT(self, env, start_response):
        """
        Handle PUT Object and PUT Object (Copy) request
        """
        for key, value in env.items():
            if key.startswith('HTTP_X_AMZ_META_'):
                del env[key]
                env['HTTP_X_OBJECT_META_' + key[16:]] = value
            elif key == 'HTTP_CONTENT_MD5':
                if value == '':
                    return self.get_err_response('InvalidDigest')
                try:
                    env['HTTP_ETAG'] = value.decode('base64').encode('hex')
                except:
                    return self.get_err_response('InvalidDigest')
                if env['HTTP_ETAG'] == '':
                    return self.get_err_response('SignatureDoesNotMatch')
            elif key == 'HTTP_X_AMZ_COPY_SOURCE':
                env['HTTP_X_COPY_FROM'] = value

        body_iter = self._app_call(env)
        status = self._get_status_int()

        if status != HTTP_CREATED:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return self.get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return self.get_err_response('NoSuchBucket')
            elif status == HTTP_UNPROCESSABLE_ENTITY:
                return self.get_err_response('InvalidDigest')
            else:
                return self.get_err_response('InvalidURI')

        if 'HTTP_X_COPY_FROM' in env:
            body = '<CopyObjectResult>' \
                   '<ETag>"%s"</ETag>' \
                   '</CopyObjectResult>' % self._response_header_value('etag')
            return Response(status=HTTP_OK, body=body)

        return Response(status=200, etag=self._response_header_value('etag'))

    def POST(self, env, start_response):
        return self.get_err_response('AccessDenied')

    def DELETE(self, env, start_response):
        """
        Handle DELETE Object request
        """
        body_iter = self._app_call(env)
        status = self._get_status_int()

        if status != HTTP_NO_CONTENT:
            if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return self.get_err_response('AccessDenied')
            elif status == HTTP_NOT_FOUND:
                return self.get_err_response('NoSuchKey')
            else:
                return self.get_err_response('InvalidURI')

        resp = Response()
        resp.status = HTTP_NO_CONTENT
        return resp
