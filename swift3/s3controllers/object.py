#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: Kun Huang <academicgareth@gmail.com>

import urlparse
from urllib import unquote, quote
from lxml import etree

from swift3.s3controllers.base import BaseController
from swift.common.wsgi import WSGIContext
from swift.common.wsgi import make_pre_authed_env as copyenv
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
        self.object_name = unquote(object_name)
        env['HTTP_X_AUTH_TOKEN'] = token
        env['PATH_INFO'] = '/v1/AUTH_%s/%s/%s' % (account_name, container_name,
                                                  object_name)

    def GETorHEAD(self, env, start_response):
        qs = env.get('QUERY_STRING', '')
        args = urlparse.parse_qs(qs, 1)

        if args.get('versionID') or env.get('HTTP_X_AMZ_VERSION_ID'):
            version_id = args.get('versionID') or env.get('HTTP_X_AMZ_VERSION_ID')
            location = self.version_name(self.container_name)
            path = '/v1/AUTH_%s/%s/%s' % (self.account_name, location, version_id)
            # md5 the versioned object and return the match one
            #env2 = copyenv(env, method='GET', path=path, query_string='')
            #app_iter = self._app_call(env2)
            #status = self._get_status_int()
            env['PATH_INFO'] = path
            env['QUERY_STRING'] = ''

        app_iter = self._app_call(env)
        status = self._get_status_int()
        headers = dict(self._response_headers)

        if env['REQUEST_METHOD'] == 'HEAD':
            app_iter = None

        if is_success(status):
            return Response(status=status, headers=self.obj_headers_to_amz(headers), app_iter=app_iter)
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
