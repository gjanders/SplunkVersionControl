#!/usr/bin/env python
from __future__ import absolute_import, division, print_function, unicode_literals
import sys
import os
import requests
import re
import logging
from logging.config import dictConfig

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option
from splunklib.binding import HTTPError

splunkLogsDir = os.environ['SPLUNK_HOME'] + "/var/log/splunk"
#Setup the logging
logging_config = dict(
    version = 1,
    formatters = {
        'f': {'format':
              '%(asctime)s %(name)-12s %(levelname)-8s %(message)s'}
        },
    handlers = {
        'h': {'class': 'logging.StreamHandler',
              'formatter': 'f',
              'level': logging.WARN},
        'file': {'class' : 'logging.handlers.RotatingFileHandler',
              'filename' : splunkLogsDir + '/splunkversioncontrol_postversioncontrolrestore.log',
              'formatter': 'f',
              'maxBytes' :  2097152,
              'level': logging.DEBUG,
              'backupCount' : 5 }
        },        
    root = {
        'handlers': ['h','file'],
        'level': logging.DEBUG,
        },
)

dictConfig(logging_config)

logger = logging.getLogger()
logging.getLogger().setLevel(logging.INFO)

"""
    Send a POST request to a specified URL with the contents of the Splunk authentication token of the current user
    along with the various parameters passed into this class
    Return back the results from calling the remote url to the user as a statistic
"""

@Configuration(type='reporting')
class SVCPostRestore(GeneratingCommand):

    url = Option(require=True)
    splunk_vc_name = Option(require=True)
    app = Option(require=True)
    type = Option(require=True)
    obj_name = Option(require=True)
    tag = Option(require=True)
    restoreAsUser = Option(require=True)
    scope = Option(require=True)
    timeout = Option(require=True)
    
    def generate(self):
        """
          The logic is:
            If the requested savedsearch is owned by the current user, or the requesting user is an admin user, then
            change the dispatch.ttl value of the saved search to the requested newttl value passed in
            If the optional sharing level is not specified check for the savedsearch in the private / user context first
            then app context
            If the owner is specified look under the particular owner context, only someone with admin access can use this option
        """
        urlregex = re.compile("^(?:https:\/\/)[\w0-9_\.-]+:8089/services/splunkversioncontrol_rest_restore$")
        if urlregex.match(self.url):
            url = self.url
        else:
            logger.error("Requested to post to remote url=%s but this did not match the regex" % (self.url))
            yield {'result': 'Invalid url passed in, url must begin with https:// and would normally end in :8089/services/splunkversioncontrol_rest_restore, url=%s' % (self.url) }
            return
        
        body = {}
        body['splunk_vc_name'] = self.splunk_vc_name
        body['app'] = self.app
        body['type'] = self.type
        body['obj_name'] = self.obj_name
        body['tag'] = self.tag
        body['restoreAsUser'] = self.restoreAsUser
        body['scope'] = self.scope
        body['timeout'] = self.timeout
        
        logger.info("Attempting POST request to url=%s with body=\"%s\"" % (url, body))
        
        body['Authorization'] = 'Splunk ' + self._metadata.searchinfo.session_key
        
        logger.debug("Using token %s" % (body['Authorization']))
        
        attempt = requests.post(url, verify=False, data=body)
        if attempt.status_code != 200:
            logger.error("POST request failed with status_code=%s, reason=%s, text=%s on url=%s" % (attempt.status_code, attempt.reason, attempt.text, url))
            yield {'result': 'Unknown failure, received a non-200 response code of %s on the url %s, reason %s, text result is %s' % (attempt.status_code, url, attempt.reason, attempt.text)}
            return
        else:
            logger.debug("Received result of result=%s" % (attempt.text))
            yield { 'result': attempt.text }
        #yield { 'result': self._metadata.searchinfo.session_key }

dispatch(SVCPostRestore, sys.argv, sys.stdin, sys.stdout, __name__)
