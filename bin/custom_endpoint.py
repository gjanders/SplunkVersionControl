import splunk
import json
import traceback
import requests
from requests.auth import HTTPBasicAuth

class Send(splunk.rest.BaseRestHandler):

    def handle_POST(self):
        sessionKey = self.sessionKey
        payload = self.request['payload']

        try:
            self.response.setHeader('content-type', 'text/html')
            self.response.write(payload)

        except Exception, e:
            self.response.write(traceback.format_exc(e))

    #handle verbs, otherwise Splunk will throw an error
    #handle_GET = handle_POST

