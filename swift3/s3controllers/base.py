#!/usr/bin/env python
#-*- coding:utf-8 -*-
# Author: Kun Huang <academicgareth@gmail.com>
# Created Time: 05/28/13 15:42:55 (CST)
# Modified Time: 05/28/13 16:50:35 (CST)


from collections import defaultdict
import re

from lxml import etree
import simplexml

from swift.common.swob import Request, Response
from swift.common.wsgi import WSGIContext
from swift.common.http import HTTP_OK, HTTP_CREATED, HTTP_ACCEPTED, \
    HTTP_NO_CONTENT, HTTP_BAD_REQUEST, HTTP_UNAUTHORIZED, HTTP_FORBIDDEN, \
    HTTP_NOT_FOUND, HTTP_CONFLICT, HTTP_UNPROCESSABLE_ENTITY, is_success, \
    HTTP_NOT_IMPLEMENTED, HTTP_LENGTH_REQUIRED, HTTP_SERVICE_UNAVAILABLE


class BaseController(WSGIContext):
    '''
    Provide some basic useful class.
    '''
    def __init__(self):
        pass

    def create_elem(self, tag, text):
        elem = etree.Element(tag)
        if text:
            elem.text = text
        return elem

    def keyvalue2dict(self, value):
        valued = defaultdict(list)
        for _pair in value.split(','):
            _key, _value = _pair.split('=')
            valued[_key.strip()].append(_value.strip())
        return dict(valued)


    def xmlbody2dict(self, xml):
        return simplexml.loads(xml)


    def xmlbody2elem(self, xml):
        xmlns = 'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"'
        xml = xml.replace(xmlns, '')
        return etree.fromstring(xml)


    def elem2xmlbody(self, elem):
        return etree.tostring(elem, xml_declaration=True)


    def dict2xmlbody(self, dic):
        return simplexml.dumps(dic)

    def get_err_response(self, code):
        """
        Given an HTTP response code, create a properly formatted xml error response

        :param code: error code
        :returns: webob.response object
        """
        error_table = {
            'AccessDenied':
            (HTTP_FORBIDDEN, 'Access denied'),
            'BucketAlreadyExists':
            (HTTP_CONFLICT, 'The requested bucket name is not available'),
            'BucketNotEmpty':
            (HTTP_CONFLICT, 'The bucket you tried to delete is not empty'),
            'InvalidArgument':
            (HTTP_BAD_REQUEST, 'Invalid Argument'),
            'InvalidBucketName':
            (HTTP_BAD_REQUEST, 'The specified bucket is not valid'),
            'InvalidURI':
            (HTTP_BAD_REQUEST, 'Could not parse the specified URI'),
            'InvalidDigest':
            (HTTP_BAD_REQUEST, 'The Content-MD5 you specified was invalid'),
            'BadDigest':
            (HTTP_BAD_REQUEST, 'The Content-Length you specified was invalid'),
            'NoSuchBucket':
            (HTTP_NOT_FOUND, 'The specified bucket does not exist'),
            'SignatureDoesNotMatch':
            (HTTP_FORBIDDEN, 'The calculated request signature does not '
            'match your provided one'),
            'RequestTimeTooSkewed':
            (HTTP_FORBIDDEN, 'The difference between the request time and the'
            ' current time is too large'),
            'NoSuchKey':
            (HTTP_NOT_FOUND, 'The resource you requested does not exist'),
            'Unsupported':
            (HTTP_NOT_IMPLEMENTED, 'The feature you requested is not yet'
            ' implemented'),
            'MissingContentLength':
            (HTTP_LENGTH_REQUIRED, 'Length Required'),
            'ServiceUnavailable':
            (HTTP_SERVICE_UNAVAILABLE, 'Please reduce your request rate')}

        resp = Response(content_type='text/xml')
        resp.status = error_table[code][0]
        resp.body = '<?xml version="1.0" encoding="UTF-8"?>\r\n<Error>\r\n  ' \
                    '<Code>%s</Code>\r\n  <Message>%s</Message>\r\n</Error>\r\n' \
                    % (code, error_table[code][1])
        return resp

    def swift_acl_translate(self, canned=None, acl=None):
        """
        Takes an S3 style ACL and returns a list of header/value pairs that
        implement that ACL in Swift, or "Unsupported" if there isn't a way to do
        that yet.
        """
        if canned == acl == None or (canned is not None and acl is not None):
            raise ValueError('One and only one kind of acl is supported')

        if canned:
            swift_acl = defaultdict(list)
            canned_acl = ['bucket-owner-read', 'bucket-owner-full-control',
                          'public-read', 'public-read-write', 'private',
                          'authenticated-read']
            swift_acl['authenticated-read'] = [['HTTP_X_CONTAINER_READ', '.r:*,.rlistings']]
            swift_acl['private'] = [['HTTP_X_CONTAINER_WRITE', '.'],
                                    ['HTTP_X_CONTAINER_READ', '.']]
            if canned in canned_acl:
                return swift_acl[canned]

        if acl:
            swift_acl = defaultdict(list)
            read = acl['read']['userid'] + acl['read']['user'] + acl['full']['userid'] + acl['full']['user']
            write = acl['write']['userid'] + acl['write']['user'] + acl['full']['userid'] + acl['full']['user']
            return [['HTTP_X_CONTAINER_READ', read],['HTTP_X_CONTAINER_WRITE', write]]


    def validate_bucket_name(self, name):
        """
        Validates the name of the bucket against S3 criteria,
        http://docs.amazonwebservices.com/AmazonS3/latest/BucketRestrictions.html
        True if valid, False otherwise
        """

        if '_' in name or len(name) < 3 or len(name) > 63 or not name[-1].isalnum():
            # Bucket names should not contain underscores (_)
            # Bucket names must end with a lowercase letter or number
            # Bucket names should be between 3 and 63 characters long
            return False
        elif '.-' in name or '-.' in name or '..' in name or not name[0].isalnum():
            # Bucket names cannot contain dashes next to periods
            # Bucket names cannot contain two adjacent periods
            # Bucket names Must start with a lowercase letter or a number
            return False
        elif re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
                      "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", name):
            # Bucket names cannot be formatted as an IP Address
            return False
        else:
            return True


    def version_name(self, name):
        return '_' + name


    def is_unique(self, container):
        # TODO checking ...
        return True

    def get_acl(self, account_name, headers):
        """
        Attempts to construct an S3 ACL based on what is found in the swift headers
        """

        acl = 'private'  # default to private

        if 'x-container-read' in headers:
            if headers['x-container-read'] == ".r:*" or\
                ".r:*," in headers['x-container-read'] or \
                    ",*," in headers['x-container-read']:
                acl = 'public-read'
        if 'x-container-write' in headers:
            if headers['x-container-write'] == ".r:*" or\
                ".r:*," in headers['x-container-write'] or \
                    ",*," in headers['x-container-write']:
                if acl == 'public-read':
                    acl = 'public-read-write'
                else:
                    acl = 'public-write'

        if acl == 'private':
            body = ('<AccessControlPolicy>'
                    '<Owner>'
                    '<ID>%s</ID>'
                    '<DisplayName>%s</DisplayName>'
                    '</Owner>'
                    '<AccessControlList>'
                    '<Grant>'
                    '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                    'XMLSchema-instance" xsi:type="CanonicalUser">'
                    '<ID>%s</ID>'
                    '<DisplayName>%s</DisplayName>'
                    '</Grantee>'
                    '<Permission>FULL_CONTROL</Permission>'
                    '</Grant>'
                    '</AccessControlList>'
                    '</AccessControlPolicy>' %
                    (account_name, account_name, account_name, account_name))
        elif acl == 'public-read':
            body = ('<AccessControlPolicy>'
                    '<Owner>'
                    '<ID>%s</ID>'
                    '<DisplayName>%s</DisplayName>'
                    '</Owner>'
                    '<AccessControlList>'
                    '<Grant>'
                    '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                    'XMLSchema-instance" xsi:type="CanonicalUser">'
                    '<ID>%s</ID>'
                    '<DisplayName>%s</DisplayName>'
                    '</Grantee>'
                    '<Permission>FULL_CONTROL</Permission>'
                    '</Grant>'
                    '<Grant>'
                    '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                    'XMLSchema-instance" xsi:type="Group">'
                    '<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>'
                    '</Grantee>'
                    '<Permission>READ</Permission>'
                    '</Grant>'
                    '</AccessControlList>'
                    '</AccessControlPolicy>' %
                    (account_name, account_name, account_name, account_name))
        elif acl == 'public-read-write':
            body = ('<AccessControlPolicy>'
                    '<Owner>'
                    '<ID>%s</ID>'
                    '<DisplayName>%s</DisplayName>'
                    '</Owner>'
                    '<AccessControlList>'
                    '<Grant>'
                    '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                    'XMLSchema-instance" xsi:type="CanonicalUser">'
                    '<ID>%s</ID>'
                    '<DisplayName>%s</DisplayName>'
                    '</Grantee>'
                    '<Permission>FULL_CONTROL</Permission>'
                    '</Grant>'
                    '<Grant>'
                    '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                    'XMLSchema-instance" xsi:type="Group">'
                    '<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>'
                    '</Grantee>'
                    '<Permission>READ</Permission>'
                    '</Grant>'
                    '</AccessControlList>'
                    '<AccessControlList>'
                    '<Grant>'
                    '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                    'XMLSchema-instance" xsi:type="Group">'
                    '<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>'
                    '</Grantee>'
                    '<Permission>WRITE</Permission>'
                    '</Grant>'
                    '</AccessControlList>'
                    '</AccessControlPolicy>' %
                    (account_name, account_name, account_name, account_name))
        else:
            body = ('<AccessControlPolicy>'
                    '<Owner>'
                    '<ID>%s</ID>'
                    '<DisplayName>%s</DisplayName>'
                    '</Owner>'
                    '<AccessControlList>'
                    '<Grant>'
                    '<Grantee xmlns:xsi="http://www.w3.org/2001/'
                    'XMLSchema-instance" xsi:type="CanonicalUser">'
                    '<ID>%s</ID>'
                    '<DisplayName>%s</DisplayName>'
                    '</Grantee>'
                    '<Permission>FULL_CONTROL</Permission>'
                    '</Grant>'
                    '</AccessControlList>'
                    '</AccessControlPolicy>' %
                    (account_name, account_name, account_name, account_name))
        return Response(body=body, content_type="text/plain")
