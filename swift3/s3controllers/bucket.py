#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: Kun Huang <academicgareth@gmail.com>


import urlparse
from urllib import unquote, quote
from simplejson import loads
from xml.sax.saxutils import escape as xml_escape
from lxml import etree
from copy import copy
from xml.dom.minidom import parseString

from swift3.s3controllers import BaseController, ObjectController
from swift.common.wsgi import WSGIContext
from swift.common.wsgi import make_pre_authed_env as copyenv
from swift.proxy.controllers.base import get_container_info
from swift.common.http import HTTP_OK, HTTP_CREATED, HTTP_ACCEPTED, \
    HTTP_NO_CONTENT, HTTP_BAD_REQUEST, HTTP_UNAUTHORIZED, HTTP_FORBIDDEN, \
    HTTP_NOT_FOUND, HTTP_CONFLICT, HTTP_UNPROCESSABLE_ENTITY, is_success, \
    HTTP_NOT_IMPLEMENTED, HTTP_LENGTH_REQUIRED, HTTP_SERVICE_UNAVAILABLE
from swift.common.swob import Request, Response

class BucketController(BaseController):
    """
    Handles bucket request.
    """
    def __init__(self, env, app, account_name, token, container_name,
                 **kwargs):
        self.MAX_BUCKET_LISTING = 1000
        WSGIContext.__init__(self, app)
        self.container_name = unquote(container_name)
        self.account_name = unquote(account_name)
        env['HTTP_X_AUTH_TOKEN'] = token
        env['PATH_INFO'] = '/v1/AUTH_%s/%s' % (account_name, container_name)
        conf = kwargs.get('conf', {})
        self.location = conf.get('location', 'US')

    def GET(self, env, start_response):
        """
        Handle GET Bucket (List Objects) request
        """
        qs = env.get('QUERY_STRING', '')
        args = urlparse.parse_qs(qs, 1)

        key_args = set(['cors','lifecycle', 'policy', 'logging', 'notification',
                        'tagging', 'requestPayment', 'versioning', 'versions',
                        'website', 'location'])

        if not key_args & set(args):
            # GET bucket to list objects
            max_keys = self.MAX_BUCKET_LISTING
            if 'max-keys' in args:
                if args.get('max-keys')[0].isdigit() is False:
                    return self.get_err_response('InvalidArgument')
                max_keys = min(int(args.get('max-keys')[0]), self.MAX_BUCKET_LISTING)


            if 'acl' not in args:
                #acl request sent with format=json etc confuses swift
                env['QUERY_STRING'] = 'format=json&limit=%s' % (max_keys + 1)
            if 'marker' in args:
                env['QUERY_STRING'] += '&marker=%s' % quote(args['marker'])
            if 'prefix' in args:
                env['QUERY_STRING'] += '&prefix=%s' % quote(args['prefix'])
            if 'delimiter' in args:
                env['QUERY_STRING'] += '&delimiter=%s' % quote(args['delimiter'])
            body_iter = self._app_call(env)
            status = self._get_status_int()
            headers = dict(self._response_headers)

            if is_success(status) and 'acl' in args:
                return self.get_acl(self.account_name, headers)

            if 'versioning' in args:
                # Just report there is no versioning configured here.
                body = ('<VersioningConfiguration '
                        'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>')
                return Response(body=body, content_type="text/plain")

            if status != HTTP_OK:
                if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return self.get_err_response('AccessDenied')
                elif status == HTTP_NOT_FOUND:
                    return self.get_err_response('NoSuchBucket')
                else:
                    return self.get_err_response('InvalidURI')

            if 'location' in args:
                body = ('<?xml version="1.0" encoding="UTF-8"?>'
                        '<LocationConstraint '
                        'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"')
                if self.location == 'US':
                    body += '/>'
                else:
                    body += ('>%s</LocationConstraint>' % self.location)
                return Response(body=body, content_type='application/xml')

            if 'logging' in args:
                # logging disabled
                body = ('<?xml version="1.0" encoding="UTF-8"?>'
                        '<BucketLoggingStatus '
                        'xmlns="http://doc.s3.amazonaws.com/2006-03-01" />')
                return Response(body=body, content_type='application/xml')

            objects = loads(''.join(list(body_iter)))
            body = ('<?xml version="1.0" encoding="UTF-8"?>'
                    '<ListBucketResult '
                    'xmlns="http://s3.amazonaws.com/doc/2006-03-01">'
                    '<Prefix>%s</Prefix>'
                    '<Marker>%s</Marker>'
                    '<Delimiter>%s</Delimiter>'
                    '<IsTruncated>%s</IsTruncated>'
                    '<MaxKeys>%s</MaxKeys>'
                    '<Name>%s</Name>'
                    '%s'
                    '%s'
                    '</ListBucketResult>' %
                    (
                    xml_escape(args.get('prefix', '')),
                    xml_escape(args.get('marker', '')),
                    xml_escape(args.get('delimiter', '')),
                    'true' if max_keys > 0 and len(objects) == (max_keys + 1) else
                    'false',
                    max_keys,
                    xml_escape(self.container_name),
                    "".join(['<Contents><Key>%s</Key><LastModified>%sZ</LastModif'
                            'ied><ETag>%s</ETag><Size>%s</Size><StorageClass>STA'
                            'NDARD</StorageClass><Owner><ID>%s</ID><DisplayName>'
                            '%s</DisplayName></Owner></Contents>' %
                            (xml_escape(unquote(i['name'])), i['last_modified'],
                             i['hash'],
                             i['bytes'], self.account_name, self.account_name)
                             for i in objects[:max_keys] if 'subdir' not in i]),
                    "".join(['<CommonPrefixes><Prefix>%s</Prefix></CommonPrefixes>'
                             % xml_escape(i['subdir'])
                             for i in objects[:max_keys] if 'subdir' in i])))
            return Response(body=body, content_type='application/xml')
        else:
            # GET specified data
            #env['REQUEST_METHOD'] = 'HEAD'
            body_iter = self._app_call(env)
            status = self._get_status_int()
            headers = dict(self._response_headers)

            action = args.keys().pop()
            if action == 'acl':
                # get acl
                # get policy
                acl = headers.get('X-Container-Meta-Policy') or ''

                if is_success(status):
                    if acl:
                        return Response(status=HTTP_OK, content_type='application/xml', body=unquote(acl))
                    else:
                        return self.get_err_response('NotSuchPolicy')

                elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return self.get_err_response('AccessDenied')
                else:
                    return self.get_err_response('InvalidURI')
            elif action == 'cors':
                # get cors
                _headers = set(['X-Container-Meta-Access-Control-Expose-Headers',
                                'X-Container-Meta-Access-Control-Allow-Origin',
                                'X-Container-Meta-Access-Control-Max-Age',
                                'X-Container-Meta-Access-Control-Allow-Method'])
                bodye = etree.Element('CORSConfiguration')
                if _headers & set(headers):
                    rule = etree.Element('CORSRule')
                    if 'X-Container-Meta-Access-Control-Expose-Headers' in headers:
                        valuel = headers['X-Container-Meta-Access-Control-Expose-Headers'].split(',')
                        for i in valuel:
                            eh = self.create_elem('ExposeHeader', i)
                            rule.append(eh)
                    if 'X-Container-Meta-Access-Control-Allow-Origin' in headers:
                        valuel = headers['X-Container-Meta-Access-Control-Allow-Origin'].split(',')
                        for i in valuel:
                            ao = self.create_elem('AllowedOrigin', i)
                            rule.append(ao)
                    if 'X-Container-Meta-Access-Control-Max-Age' in headers:
                        valuel = headers['X-Container-Meta-Access-Control-Max-Age'].split(',')
                        for i in valuel:
                            ma = self.create_elem('MaxAgeSeconds', i)
                            rule.append(ma)
                    if 'X-Container-Meta-Access-Control-Allow-Method' in headers:
                        valuel = headers['X-Container-Meta-Access-Control-Allow-Method'].split(',')
                        for i in valuel:
                            al = self.create_elem('AllowedMethod', i)
                            rule.append(al)
                    rule.append(self.create_elem('ID', 'unique_rule'))
                    bodye.append(rule)
                else:
                    bodye.text = ''

                if is_success(status):
                    return Response(status=HTTP_OK, content_type='application/xml', body=self.elem2xmlbody(bodye))
                elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return self.get_err_response('AccessDenied')
                else:
                    return self.get_err_response('InvalidURI')

            elif action == 'lifecycle':
                # get lifecycle
                bodye = etree.Element('LifecycleConfiguration')
                if 'X-Container-Meta-Expiration-Status' in headers:
                    rule = etree.Element('Rule')
                    rule.append(self.create_elem('Status', headers['X-Container-Meta-Expiration-Status']))
                    rule.append(self.create_elem('ID', 'unique_rule'))
                    if 'X-Container-Meta-Expiration-Prefix' in headers:
                        rule.append(self.create_elem('Prefix', headers['X-Container-Meta-Expiration-Prefix']))
                    if 'X-Container-Meta-Expiration-At' in headers or \
                       'X-Container-Meta-Expiration-After' in headers:
                        expir = etree.Element('Expiration')
                        if 'X-Container-Meta-Expiration-At' in headers:
                            expir.append(self.create_elem('Date', headers['X-Container-Meta-Expiration-At']))
                        if 'X-Container-Meta-Expiration-After' in headers:
                            expir.append(self.create_elem('Days', headers['X-Container-Meta-Expiration-After']))
                        rule.append(expir)
                    if 'X-Container-Meta-Trans-Class' in headers:
                        trans = etree.Element('Transition')
                        cls = self.create_elem('StorageClass', headers['X-Container-Meta-Trans-Class'])
                        trans.append(cls)
                        if 'X-Container-Meta-Trans-At' in headers:
                            trans.append(self.create_elem('Date', headers['X-Container-Meta-Trans-At']))
                        if 'X-Container-Meta-Trans-After' in headers:
                            trans.append(self.create_elem('Days', headers['X-Container-Meta-Trans-After']))
                        rule.append(trans)
                    bodye.append(rule)
                else:
                    bodye.text = ''

                if is_success(status):
                    return Response(status=HTTP_OK, content_type='application/xml', body=self.elem2xmlbody(bodye))
                elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return self.get_err_response('AccessDenied')
                else:
                    return self.get_err_response('InvalidURI')

            elif action == 'policy':
                # get policy
                json = headers.get('X-Container-Meta-Policy') or ''

                if is_success(status):
                    if json:
                        return Response(status=HTTP_OK, content_type='application/json', body=unquote(json))
                    else:
                        return self.get_err_response('NotSuchPolicy')

                elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return self.get_err_response('AccessDenied')
                else:
                    return self.get_err_response('InvalidURI')
            elif action == 'logging':
                # get logging
                target = headers.get('X-Container-Meta-Logging-Target') or ''
                prefix = headers.get('X-Container-Meta-Logging-Prefix') or ''
                statuse = etree.Element('BucketLoggingStatus')
                if target:
                    enabled = etree.Element('LoggingEnabled')
                    target_bucket = self.create_elem('TargetBucket', target)
                    if prefix:
                        target_prefix = self.create_elem('TargetPrefix', prefix)
                    enabled.append(target_bucket)
                    enabled.append(target_prefix)
                    statuse.append(enabled)
                else:
                    pass # set text None

                if is_success(status):
                    return Response(status=HTTP_OK, content_type='application/xml', body=self.elem2xmlbody(statuse))
                elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return self.get_err_response('AccessDenied')
                else:
                    return self.get_err_response('InvalidURI')
            elif action == 'notification':
                # get it
                noti = headers.get('X-Container-Meta-Noti')
                if is_success(status):
                    if noti:
                        return Response(status=HTTP_OK, content_type='application/xml', body=unquote(noti))
                    else:
                        return self.get_err_response('NotSuchWebsite')

                elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return self.get_err_response('AccessDenied')
                else:
                    return self.get_err_response('InvalidURI')
            elif action == 'tagging':
                # get tagging
                Tagging = etree.Element('Tagging')
                TagSet = etree.Element('TagSet')
                meta_keys = [header[21:] for header in headers if header.startswith('X-Container-Meta-Tag-')]
                for key in meta_keys:
                    Tag = etree.Element('Tag')
                    keyvalues = headers['X-Container-Meta-Tag-' + key]
                    _key = keyvalues[:len(key)]
                    _value = keyvalues[len(key):]
                    Tag.append(self.create_elem('Key', _key))
                    Tag.append(self.create_elem('Value', _value))
                    TagSet.append(Tag)
                Tagging.append(TagSet)
                if is_success(status):
                    return Response(status=HTTP_OK, content_type='application/xml', body=self.elem2xmlbody(Tagging))
                elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return self.get_err_response('AccessDenied')
                else:
                    return self.get_err_response('InvalidURI')

            elif action == 'requestPayment':
                # get it
                pay = headers.get('X-Container-Meta-Payment')
                if is_success(status):
                    if pay:
                        return Response(status=HTTP_OK, content_type='application/xml', body=unquote(pay))
                    else:
                        return self.get_err_response('NotSuchWebsite')

                elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return self.get_err_response('AccessDenied')
                else:
                    return self.get_err_response('InvalidURI')
            elif action == 'versioning':
                versioning = 'Enabled' if 'X-Versions-Location' in headers else 'Suspended'
                bodye = etree.Element('VersioningConfiguration')
                stat = self.create_elem('Status', versioning)
                bodye.append(stat)
                if is_success(status):
                    return Response(status=HTTP_OK, content_type='application/xml', body=self.elem2xmlbody(bodye))
                elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return self.get_err_response('AccessDenied')
                else:
                    return self.get_err_response('InvalidURI')
            elif action == 'website':
                # get website
                website = headers.get('X-Container-Meta-Website')
                if is_success(status):
                    if website:
                        return Response(status=HTTP_OK, content_type='application/xml', body=unquote(website))
                    else:
                        return self.get_err_response('NotSuchWebsite')

                elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return self.get_err_response('AccessDenied')
                else:
                    return self.get_err_response('InvalidURI')
            elif action == 'location':
                bodye = self.create_elem('LocationConstraint', 'CN')
                return Response(status=HTTP_OK, content_type='application/xml', body=self.elem2xmlbody(bodye))
            elif action == 'versions':
                # get versions container
                path = '/v1/AUTH_%s/%s' % (self.account_name, self.container_name)
                env = copyenv(env, method='GET', path=path, query_string='')
                body_iter = self._app_call(env)
                status = self._get_status_int()

                # get origin container
                path = '/v1/AUTH_%s/%s' % (quote(self.account_name), quote(self.version_name(self.container_name)))
                env2 = copyenv(env, method='GET', path=path, query_string='')
                body_iter2 = self._app_call(env2)
                status2 = self._get_status_int()

                last = list(body_iter)
                history = list(body_iter2)
                res = etree.Element('ListVersionsResult')
                bucket = self.create_elem('Name', self.container_name)
                res.append(bucket)
                if last:
                    last = [i for i in last[0].split('\n') if i]
                    for i in last:
                        ver = etree.Element('Version')
                        ver.append(self.create_elem('Key', i))
                        ver.append(self.create_elem('VersionId', 'lastest'))
                        ver.append(self.create_elem('IsLastest', 'true'))
                        res.append(ver)

                if history:
                    history = [i for i in history[0].split('\n') if i]
                    for i in history:
                        ver = etree.Element('Version')
                        ver.append(self.create_elem('Key', i.split('/')[0][3:]))
                        ver.append(self.create_elem('VersionId', i.split('/')[1]))
                        ver.append(self.create_elem('IsLastest', 'false'))
                        res.append(ver)

                if is_success(status) and is_success(status2):
                    return Response(status=HTTP_OK, content_type='application/xml', body=self.elem2xmlbody(res))
                elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return self.get_err_response('AccessDenied')
                else:
                    return self.get_err_response('InvalidURI')
            else:
                return self.get_err_response('InvalidURI')


    def PUT(self, env, start_response):
        """
        Handle PUT Bucket request
        """
        # checking params available
        AMZ_ACL = set(['HTTP_X_AMZ_GRANT_READ',
                       'HTTP_X_AMZ_GRANT_WRITE',
                       'HTTP_X_AMZ_GRANT_READ_ACP',
                       'HTTP_X_AMZ_GRANT_WRITE_ACP',
                       'HTTP_X_AMZ_GRANT_FULL_CONTROL'])
        qs = env.get('QUERY_STRING', '')
        args = urlparse.parse_qs(qs, 1)
        if not args:
            if not self.validate_bucket_name(self.container_name):
                return self.get_err_response('InvalidBucketName')

            if not self.is_unique(self.container_name):
                return self.get_err_response('BucketAlreadyExists')

            # to create a new one
            if 'HTTP_X_AMZ_ACL' in env:
                amz_acl = env['HTTP_X_AMZ_ACL']
                translated_acl = self.swift_acl_translate(canned=amz_acl)
                for header, value in translated_acl:
                    env[header] = value
            elif AMZ_ACL & set(env.keys()):
                acld = dict()
                if 'HTTP_X_AMZ_GRANT_READ' in env.keys():
                    acld['read'] = self.keyvalue2dict(env['HTTP_X_AMZ_GRANT_READ'])
                if 'HTTP_X_AMZ_GRANT_WRITE' in env.keys():
                    acld['write'] = self.keyvalue2dict(env['HTTP_X_AMZ_GRANT_WRITE'])
                if 'HTTP_X_AMZ_GRANT_FULL_CONTROL' in env.keys():
                    acld['full'] = self.keyvalue2dict(env['HTTP_X_AMZ_GRANT_FULL_CONTROL'])
                translated_acl = self.swift_acl_translate(acl=acld)
                for header, value in translated_acl:
                    env[header] = value

            # modify env put to swift
            body_iter = self._app_call(env)
            status = self._get_status_int()

            if status != HTTP_CREATED:
                if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return self.get_err_response('AccessDenied')
                elif status == HTTP_ACCEPTED:
                    return self.get_err_response('BucketAlreadyExists')
                else:
                    return self.get_err_response('InvalidURI')

            resp = Response()
            resp.headers['Location'] = self.container_name
            resp.status = HTTP_OK
            return resp

        if len(args) > 1:
            return self.get_err_response('InvalidURI')

        # now args only 1
        action = args.keys().pop()
        if action == 'acl':
            # put acl
            acl = env['wsgi.input'].read()
            env['REQUEST_METHOD'] = 'POST'
            env['QUERY_STRING'] = ''
            env['HTTP_X_CONTAINER_META_ACL'] = quote(acl)
            body_iter = self._app_call(env)
            status = self._get_status_int()
            if is_success(status):
                resp = Response()
                resp.status = HTTP_OK
                return resp
            elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return self.get_err_response('AccessDenied')
            else:
                return self.get_err_response('InvalidURI')
        elif action == 'cors':
            # put cors
            bodye = self.xmlbody2elem(env['wsgi.input'].read())
            env['HTTP_X_CONTAINER_META_ACCESS_CONTROL_ALLOW_ORIGIN'] = ','.join([i.text for i in bodye.xpath('/CORSConfiguration/CORSRule/AllowedOrigin')])
            env['HTTP_X_CONTAINER_META_ACCESS_CONTROL_MAX_AGE'] = ','.join([i.text for i in bodye.xpath('/CORSConfiguration/CORSRule/MaxAgeSeconds')])
            env['HTTP_X_CONTAINER_META_ACCESS_CONTROL_EXPOSE_HEADERS'] = ','.join([i.text for i in bodye.xpath('/CORSConfiguration/CORSRule/ExposeHeader')])
            env['HTTP_X_CONTAINER_META_ACCESS_CONTROL_ALLOW_METHOD'] = ','.join(i.text for i in bodye.xpath('/CORSConfiguration/CORSRule/AllowedMethod'))
            env['QUERY_STRING'] = ''
            env['REQUEST_METHOD'] = 'POST'

            body_iter = self._app_call(env)
            status = self._get_status_int()

            if is_success(status):
                resp = Response()
                resp.headers['Location'] = self.container_name
                resp.status = HTTP_OK
                return resp
            elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return self.get_err_response('AccessDenied')
            else:
                return self.get_err_response('InvalidURI')

        elif action == 'lifecycle':
            # put lifecycle
            container_info = get_container_info(env, self.app)
            if container_info['versions']:
                return self.get_err_response('AccessDenied')

            bodye = self.xmlbody2elem(env['wsgi.input'].read())

            tat = bodye.xpath('/LifecycleConfiguration/Rule/Transition/Date')
            env['HTTP_X_CONTAINER_META_TRANS_AT'] = tat[0].text if tat else ''
            tafter = bodye.xpath('/LifecycleConfiguration/Rule/Transition/Days')
            env['HTTP_X_CONTAINER_META_TRANS_AFTER'] = tafter[0].text if tafter else ''
            trans = bodye.xpath('/LifecycleConfiguration/Rule/Transition/StorageClass')
            env['HTTP_X_CONTAINER_META_TRANS_CLASS'] = trans[0].text if trans else ''

            at = bodye.xpath('/LifecycleConfiguration/Rule/Expiration/Date')
            env['HTTP_X_CONTAINER_META_EXPIRATION_AT'] = at[0].text if at else ''
            after = bodye.xpath('/LifecycleConfiguration/Rule/Expiration/Days')
            env['HTTP_X_CONTAINER_META_EXPIRATION_AFTER'] = after[0].text if after else ''
            prefix = bodye.xpath('/LifecycleConfiguration/Rule/Prefix')
            env['HTTP_X_CONTAINER_META_EXPIRATION_PREFIX'] = prefix[0].text if prefix else ''
            stat = bodye.xpath('/LifecycleConfiguration/Rule/Status')
            env['HTTP_X_CONTAINER_META_EXPIRATION_STATUS'] = stat[0].text if stat else ''

            env['REQUEST_METHOD'] = 'POST'
            env['QUERY_STRING'] = ''
            body_iter = self._app_call(env)
            status = self._get_status_int()
            if is_success(status):
                resp = Response()
                resp.status = HTTP_OK
                return resp
            elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return self.get_err_response('AccessDenied')
            else:
                return self.get_err_response('InvalidURI')
        elif action == 'policy':
            # put policy
            json = env['wsgi.input'].read()
            env['REQUEST_METHOD'] = 'POST'
            env['QUERY_STRING'] = ''
            env['HTTP_X_CONTAINER_META_POLICY'] = quote(json)
            body_iter = self._app_call(env)
            status = self._get_status_int()
            if is_success(status):
                resp = Response()
                resp.status = HTTP_OK
                return resp
            elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return self.get_err_response('AccessDenied')
            else:
                return self.get_err_response('InvalidURI')
        elif action == 'logging':
            # put logging
            env['REQUEST_METHOD'] = 'POST'
            env['QUERY_STRING'] = ''
            bodye = self.xmlbody2elem(env['wsgi.input'].read())
            target = bodye.xpath('/BucketLoggingStatus/LoggingEnabled/TargetBucket')
            if target:
                env['HTTP_X_CONTAINER_META_LOGGING_TARGET'] = target[0].text
                prefix = bodye.xpath('/BucketLoggingStatus/LoggingEnabled/TargetPrefix')
                if prefix:
                    env['HTTP_X_CONTAINER_META_LOGGING_PREFIX'] = prefix[0].text
            else:
                env['HTTP_X_CONTAINER_META_LOGGING_TARGET'] = ''
                env['HTTP_X_CONTAINER_META_LOGGING_PREFIX'] = ''

            body_iter = self._app_call(env)
            status = self._get_status_int()
            if is_success(status):
                resp = Response()
                resp.status = HTTP_OK
                return resp
            elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return self.get_err_response('AccessDenied')
            else:
                return self.get_err_response('InvalidURI')
        elif action == 'notification':
            # put it
            body = env['wsgi.input'].read()
            env['REQUEST_METHOD'] = 'POST'
            env['QUERY_STRING'] = ''
            env['HTTP_CONTAINER_META_NOTI'] = quote(body)

            body_iter = self._app_call(env)
            status = self._get_status_int()

            if is_success(status):
                resp = Response()
                resp.status = HTTP_OK
                return resp
            elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return self.get_err_response('AccessDenied')
            else:
                return self.get_err_response('InvalidURI')
        elif action == 'tagging':
            # put tagging
            bodye = self.xmlbody2elem(env['wsgi.input'].read())
            for tag in bodye.xpath('/Tagging/TagSet/Tag'):
                key = tag.xpath('Key')[0].text
                value = tag.xpath('Key')[0].text + tag.xpath('Value')[0].text
                env['HTTP_X_CONTAINER_META_TAG_%s' % key.upper()] = value
            env['REQUEST_METHOD'] = 'POST'
            env['QUERY_STRING'] = ''
            body_iter = self._app_call(env)
            status = self._get_status_int()
            if is_success(status):
                resp = Response()
                resp.status = HTTP_NO_CONTENT
                return resp
            elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return self.get_err_response('AccessDenied')
            else:
                return self.get_err_response('InvalidURI')
        elif action == 'requestPayment':
            # put it
            body = env['wsgi.input'].read()
            env['REQUEST_METHOD'] = 'POST'
            env['QUERY_STRING'] = ''
            env['HTTP_CONTAINER_META_PAYMENT'] = quote(body)

            body_iter = self._app_call(env)
            status = self._get_status_int()

            if is_success(status):
                resp = Response()
                resp.status = HTTP_OK
                return resp
            elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return self.get_err_response('AccessDenied')
            else:
                return self.get_err_response('InvalidURI')
        elif action == 'versioning':
            bodye = self.xmlbody2elem(env['wsgi.input'].read())
            status = bodye.xpath('/VersioningConfiguration/Status')
            if status:
                status = status[0].text

            env['REQUEST_METHOD'] = 'POST'
            env['HTTP_X_VERSIONS_LOCATION'] = self.version_name(self.container_name) if status == 'Enabled' else ''
            env['QUERY_STRING'] = ''
            body_iter = self._app_call(env)
            status = self._get_status_int()

            path = '/v1/AUTH_%s/%s' % (self.account_name, self.version_name(self.container_name))
            env2 = copyenv(env, method='PUT', path=path, query_string='')
            body_iter2 = self._app_call(env2)
            status2 = self._get_status_int()
            if is_success(status) and is_success(status2):
                resp = Response()
                resp.status = HTTP_OK
                return resp
            elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return self.get_err_response('AccessDenied')
            else:
                return self.get_err_response('InvalidURI')
        elif action == 'website':
            # put website
            body = env['wsgi.input'].read()
            env['REQUEST_METHOD'] = 'POST'
            env['QUERY_STRING'] = ''
            env['HTTP_CONTAINER_META_WEBSITE'] = quote(body)

            body_iter = self._app_call(env)
            status = self._get_status_int()

            if is_success(status):
                resp = Response()
                resp.status = HTTP_OK
                return resp
            elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return self.get_err_response('AccessDenied')
            else:
                return self.get_err_response('InvalidURI')
        else:
            return self.get_err_response('InvalidURI')


    def DELETE(self, env, start_response):
        """
        Handle DELETE Bucket request
        """
        key_args = set(['cors','lifecycle','policy','tagging','website'])

        qs = env.get('QUERY_STRING', '')
        args = urlparse.parse_qs(qs, 1)

        if not key_args & set(args):
            # DELETE a Bucket
            version = args.get('versionId')
            if version:
                vid = version[0]
                if vid.lower() == 'lastest':
                    pass
                else:
                    env['PATH_INFO'] = '/v1/AUTH_%s/%s/%s' % (quote(self.account_name),
                                                              quote(self.version_name(self.container_name)),
                                                              vid)

            body_iter = self._app_call(env)
            status = self._get_status_int()

            if status != HTTP_NO_CONTENT:
                if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return self.get_err_response('AccessDenied')
                elif status == HTTP_NOT_FOUND:
                    return self.get_err_response('NoSuchBucket')
                elif status == HTTP_CONFLICT:
                    return self.get_err_response('BucketNotEmpty')
                else:
                    return self.get_err_response('InvalidURI')

            resp = Response()
            resp.status = HTTP_NO_CONTENT
            return resp
        else:
            # DELETE specified data
            action = args.keys().pop()
            if action == 'cors':
                # delete cors
                env['HTTP_X_CONTAINER_META_ACCESS_CONTROL_ALLOW_ORIGIN'] = ''
                env['HTTP_X_CONTAINER_META_ACCESS_CONTROL_MAX_AGE'] = ''
                env['HTTP_X_CONTAINER_META_ACCESS_CONTROL_EXPOSE_HEADERS'] = ''
                env['HTTP_X_CONTAINER_META_ACCESS_CONTROL_ALLOW_METHOD'] = ''
                env['QUERY_STRING'] = ''
                env['REQUEST_METHOD'] = 'POST'

                body_iter = self._app_call(env)
                status = self._get_status_int()

                if is_success(status):
                    resp = Response()
                    resp.status = HTTP_NO_CONTENT
                    return resp
                elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return self.get_err_response('AccessDenied')
                else:
                    return self.get_err_response('InvalidURI')
            elif action == 'lifecycle':
                # delete lifecycle
                env['HTTP_X_CONTAINER_META_TRANS_AT'] = ''
                env['HTTP_X_CONTAINER_META_TRANS_AFTER'] = ''
                env['HTTP_X_CONTAINER_META_TRANS_CLASS'] = ''

                env['HTTP_X_CONTAINER_META_EXPIRATION_AT'] = ''
                env['HTTP_X_CONTAINER_META_EXPIRATION_AFTER'] = ''
                env['HTTP_X_CONTAINER_META_EXPIRATION_PREFIX'] = ''
                env['HTTP_X_CONTAINER_META_EXPIRATION_STATUS'] = ''
                env['REQUEST_METHOD'] = 'POST'
                env['QUERY_STRING'] = ''
                body_iter = self._app_call(env)
                status = self._get_status_int()
                if is_success(status):
                    resp = Response()
                    resp.status = HTTP_NO_CONTENT
                    return resp
                elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return self.get_err_response('AccessDenied')
                else:
                    return self.get_err_response('InvalidURI')
            elif action == 'policy':
                # delete policy
                env['REQUEST_METHOD'] = 'POST'
                env['QUERY_STRING'] = ''
                env['HTTP_X_CONTAINER_META_POLICY'] = ''
                body_iter = self._app_call(env)
                status = self._get_status_int()
                if is_success(status):
                    resp = Response()
                    resp.status = HTTP_NO_CONTENT
                    return resp
                elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return self.get_err_response('AccessDenied')
                else:
                    return self.get_err_response('InvalidURI')
            elif action == 'tagging':
                # delete tagging
                env2 = copy(env)
                container_info = get_container_info(env2, self.app)
                meta_keys = container_info['meta'].keys()
                for key in meta_keys:
                    env['HTTP_X_CONTAINER_META_' + key.replace('-', '_').upper()] = ''
                env['QUERY_STRING'] = ''
                env['REQUEST_METHOD'] = 'POST'

                body_iter = self._app_call(env)
                status = self._get_status_int()

                if is_success(status):
                    resp = Response()
                    resp.status = HTTP_NO_CONTENT
                    return resp
                elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return self.get_err_response('AccessDenied')
                else:
                    return self.get_err_response('InvalidURI')
            elif action == 'website':
                # delete website
                body = env['wsgi.input'].read()
                env['REQUEST_METHOD'] = 'POST'
                env['QUERY_STRING'] = ''
                env['HTTP_CONTAINER_META_WEBSITE'] = quote(body)

                body_iter = self._app_call(env)
                status = self._get_status_int()

                if is_success(status):
                    resp = Response()
                    resp.status = HTTP_OK
                    return resp
                elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return self.get_err_response('AccessDenied')
                else:
                    return self.get_err_response('InvalidURI')
            else:
                return self.get_err_response('InvalidURI')


    def _delete_multiple_objects(self, env):
        def _object_key_iter(xml):
            dom = parseString(xml)
            delete = dom.getElementsByTagName('Delete')[0]
            for obj in delete.getElementsByTagName('Object'):
                key = obj.getElementsByTagName('Key')[0].firstChild.data
                version = None
                if obj.getElementsByTagName('VersionId').length > 0:
                    version = obj.getElementsByTagName('VersionId')[0]\
                        .firstChild.data
                yield (key, version)

        def _get_deleted_elem(key):
            return '  <Deleted>\r\n' \
                   '    <Key>%s</Key>\r\n' \
                   '  </Deleted>\r\n' % (key)

        def _get_err_elem(key, err_code, message):
            return '  <Error>\r\n' \
                   '    <Key>%s</Key>\r\n' \
                   '    <Code>%s</Code>\r\n' \
                   '    <Message>%s</Message>\r\n' \
                   '  </Error>\r\n'  % (key, err_code, message)

        body = '<?xml version="1.0" encoding="UTF-8"?>\r\n' \
               '<DeleteResult ' \
               'xmlns="http://doc.s3.amazonaws.com/2006-03-01">\r\n'
        xml = env['wsgi.input'].read()
        for key, version in _object_key_iter(xml):
            if version is not None:
                # TODO: delete the specific version of the object
                return self.get_err_response('Unsupported')

            tmp_env = dict(env)
            del tmp_env['QUERY_STRING']
            tmp_env['CONTENT_LENGTH'] = '0'
            tmp_env['REQUEST_METHOD'] = 'DELETE'
            controller = ObjectController(tmp_env, self.app, self.account_name,
                                          env['HTTP_X_AUTH_TOKEN'],
                                          self.container_name, key)
            body_iter = controller._app_call(tmp_env)
            status = controller._get_status_int()

            if status == HTTP_NO_CONTENT or status == HTTP_NOT_FOUND:
                body += _get_deleted_elem(key)
            else:
                if status == HTTP_UNAUTHORIZED:
                    body += _get_err_elem(key, 'AccessDenied', 'Access Denied')
                else:
                    body += _get_err_elem(key, 'InvalidURI', 'Invalid URI')

        body += '</DeleteResult>\r\n'
        return Response(status=HTTP_OK, body=body)

    def POST(self, env, start_response):
        """
        Handle POST Bucket (Delete/Upload Multiple Objects) request
        """
        if 'QUERY_STRING' in env:
            args = dict(urlparse.parse_qsl(env['QUERY_STRING'], 1))
        else:
            args = {}

        if 'delete' in args:
            return self._delete_multiple_objects(env)

        if 'uploads' in args:
            # Pass it through, the s3multi upload helper will handle it.
            return self.app(env,start_response)

        if 'uploadId' in args:
            # Pass it through, the s3multi upload helper will handle it.
            return self.app(env, start_response)

        return self.get_err_response('Unsupported')
