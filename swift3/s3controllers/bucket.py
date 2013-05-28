#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: Kun Huang <academicgareth@gmail.com>
# Created Time: 05/28/13 15:31:00 (CST)
# Modified Time: 05/28/13 16:50:31 (CST)


import urlparse
from urllib import unquote, quote
from simplejson import loads
from xml.sax.saxutils import escape as xml_escape
from lxml import etree
from copy import copy
from xml.dom.minidom import parseString

from swift3.s3controllers import BaseController, ObjectController
from swift.common.wsgi import WSGIContext
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
                # TODO this is quite different from swift acl and can't be tested
                # check body access permissions
                # check header canner
                # check header access permissions
                pass
            elif action == 'cors':
                _headers = set(['X-Container-Meta-Access-Control-Expose-Headers',
                                'X-Container-Meta-Access-Control-Allow-Origin',
                                'X-Container-Meta-Access-Control-Max-Age'])
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
                    AllowedMethod = ['POST','GET','PUT','DELETE','HEAD']
                    for i in AllowedMethod:
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
                bodye = etree.Element('LifecycleConfiguration')
                if 'X-Container-Meta-Expiration-Status' in headers:
                    rule = etree.Element('Rule')
                    rule.append(self.create_elem('Status', headers['X-Container-Meta-Expiration-Status']))
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
                # TODO later
                pass
            elif action == 'logging':
                return self.get_err_response('Unsupported')
            elif action == 'notification':
                # TODO later
                pass
            elif action == 'tagging':
                Tagging = etree.Element('Tagging')
                TagSet = etree.Element('TagSet')
                meta_keys = [header[21:] for header in headers if header.startswith('X-Container-Meta-Tag-')]
                for key in meta_keys:
                    Tag = etree.Element('Tag')
                    Tag.append(self.create_elem('Key', key))
                    Tag.append(self.create_elem('Value', headers['X-Container-Meta-Tag-' + key]))
                    TagSet.append(Tag)
                Tagging.append(TagSet)

                if is_success(status):
                    return Response(status=HTTP_OK, content_type='application/xml', body=self.elem2xmlbody(Tagging))
                elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                    return self.get_err_response('AccessDenied')
                else:
                    return self.get_err_response('InvalidURI')

            elif action == 'requestPayment':
                # TODO later
                pass
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
                pass
            elif action == 'location':
                body = '<?xml version="1.0" encoding="UTF-8"?>'
                '<LocationConstraint>China</LocationConstraint>'
                return Response(status=HTTP_OK, content_type='application/xml', body=body)
            elif action == 'versions':
                env['PATH_INFO'] = '/v1/AUTH_%s/%s' % (quote(self.account_name), quote(self.version_name(self.container_name)))
                env['REQUEST_METHOD'] = 'GET'
                body_iter = self._app_call(env)
                status = self._get_status_int()
                # TODO parse body_iter to dict
                if is_success(status):
                    return Response(status=HTTP_OK, content_type='application/xml', body=self.dict2xmlbody(bodyd))
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
            # to create a new one
            if not self.is_unique(self.container_name):
                # TODO return a error response
                return

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
            # TODO this is quite different from swift acl and can't be tested
            # check body access permissions
            # check header canner
            # check header access permissions
            pass
        elif action == 'cors':
            bodye = self.xmlbody2elem(env['wsgi.input'].read())
            env['HTTP_X_CONTAINER_META_ACCESS_CONTROL_ALLOW_ORIGIN'] = ','.join([i.text for i in bodye.xpath('/CORSConfiguration/CORSRule/AllowedOrigin')])
            env['HTTP_X_CONTAINER_META_ACCESS_CONTROL_MAX_AGE'] = ','.join([i.text for i in bodye.xpath('/CORSConfiguration/CORSRule/MaxAgeSeconds')])
            env['HTTP_X_CONTAINER_META_ACCESS_CONTROL_EXPOSE_HEADERS'] = ','.join([i.text for i in bodye.xpath('/CORSConfiguration/CORSRule/ExposeHeader')])
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
            container_info = get_container_info(env, self.app)
            if container_info['versions']:
                return self.get_err_response('AccessDenied')

            bodye = self.xmlbody2elem(env['wsgi.input'].read())

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
            # TODO later
            pass
        elif action == 'logging':
            return self.get_err_response('Unsupported')
        elif action == 'notification':
            # TODO later
            pass
        elif action == 'tagging':
            bodye = self.xmlbody2elem(env['wsgi.input'].read())
            for tag in bodye.xpath('/Tagging/TagSet/Tag'):
                key = tag.xpath('Key')[0].text
                value = tag.xpath('Value')[0].text
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
            # TODO later
            pass
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
            if is_success(status):
                resp = Response()
                resp.status = HTTP_OK
                return resp
            elif status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
                return self.get_err_response('AccessDenied')
            else:
                return self.get_err_response('InvalidURI')
        elif action == 'website':
            pass
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
                env['HTTP_X_CONTAINER_META_ACCESS_CONTROL_ALLOW_ORIGIN'] = ''
                env['HTTP_X_CONTAINER_META_ACCESS_CONTROL_MAX_AGE'] = ''
                env['HTTP_X_CONTAINER_META_ACCESS_CONTROL_EXPOSE_HEADERS'] = ''
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
                pass
            elif action == 'tagging':
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
                pass
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
