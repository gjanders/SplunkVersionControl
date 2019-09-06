#!/usr/bin/env python
from __future__ import absolute_import, division, print_function, unicode_literals
import sys
import os
import requests
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option
from splunklib.binding import HTTPError

@Configuration(type='reporting')
class SVCPostRestore(GeneratingCommand):

    url = Option(require=False)

    def generate(self):
        """
          The logic is:
            If the requested savedsearch is owned by the current user, or the requesting user is an admin user, then
            change the dispatch.ttl value of the saved search to the requested newttl value passed in
            If the optional sharing level is not specified check for the savedsearch in the private / user context first
            then app context
            If the owner is specified look under the particular owner context, only someone with admin access can use this option
        """
        if self.url:
            urlregex = re.compile("^(?:https:\/\/)[\w0-9_\.-]+:8089/services/splunkversioncontrol_rest_restore$")
            if urlregex.match(self.url):
                url = self.url
            else:
                yield {'result': 'Invalid URL passed in, url= must begin with https:// and would normally end in :8089/services/splunkversioncontrol_rest_restore, url provided %s' % (self.url) }
                return
        else:
            url = "https://localhost:8089/services/splunkversioncontrol_rest_restore"

        body = { 'Authorization': 'Splunk ' + self._metadata.searchinfo.session_key }
        attempt = requests.post(url, verify=False, data=body)
        if attempt.status_code != 200:
            yield {'result': 'Unknown failure, received a non-200 response code of %s on the URL %s, text result is %s' % (attempt.status_code, url, attempt.text)}         
            return
        else:
            yield { 'result': attempt.text }
        #yield { 'result': self._metadata.searchinfo.session_key }

dispatch(SVCPostRestore, sys.argv, sys.stdin, sys.stdout, __name__)
