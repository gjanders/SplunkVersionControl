from subprocess import Popen, PIPE
from threading import Timer
import platform
import json
import requests
import os

#Based on https://stackoverflow.com/questions/1191374/using-module-subprocess-with-timeout
def runOSProcess(command, logger, timeout=10, shell=False):
    logger.debug("Begin OS process run of %s" % (command))
    # if this is Linux use the shell
    if platform.system() != "Windows":
        shell = True
    proc = Popen(command, stdout=PIPE, stderr=PIPE, shell=shell)

    timer = Timer(timeout, proc.kill)
    try:
        timer.start()
        stdout, stderr = proc.communicate()
    finally:
        timer.cancel()

    if not timer.isAlive():
        res = False
        logger.warn("OS process timed out after %s seconds, for command %s" % (timeout, command))
        proc.terminate()
        return "", "timeout after %s seconds" % (timeout), False
    else:
        if proc.returncode != 0:
            logger.debug("OS process exited with non-zero code of %s, for command %s" % (proc.returncode, command))
            res = False
        else:
            logger.debug("OS process exited with zero code, for command %s" % (command))
            res = True

    return str(stdout), str(stderr), res

# use the password endpoint to obtain the clear_password passed in, start with the context of this app and then try all contexts
def get_password(password, session_key, logger):
    #TODO move this into shared function to obtain passwords:
    context = os.path.dirname(os.path.dirname(__file__))

    if context.find("/bin/") != -1 or context.find("\\bin\\") != -1:
        if context.find("/bin/") != -1:
            context = context[:context.find("/bin/")]
        else:
            context = context[:context.find("\\bin\\")]

    if platform.system() == "Windows":
        start = context.rfind("\\")
    else:
        start = context.rfind("/")
    context = context[start+1:]
    
    url = "https://localhost:8089/servicesNS/-/" + context + "/storage/passwords?output_mode=json&f=clear_password&search=" + password
    logger.debug("Trying url=%s with session_key to obtain name=%s" % (url, password))
    headers = {'Authorization': 'Splunk %s' % session_key}
    res = requests.get(url, headers=headers, verify=False)
    dict = json.loads(res.text)
    clear_password = False
    if not 'entry' in dict:
        logger.warn("dict=%s did not contain the entries expected on url=%s while looking for password=%s" % (dict, url, password))
        raise Exception('Error while finding password')
    for entry in dict['entry']:
        logger.debug("found=%s looking for :%s:" % (entry['name'], password))
        if entry['name'].find(":" + password + ":") != -1:
            logger.info("Found password for name=%s in app context of context=%s" % (password, context))
            clear_password = entry['content']['clear_password']
            break

    if clear_password:
        return clear_password

    url = "https://localhost:8089/servicesNS/-/-/storage/passwords?output_mode=json&f=clear_password&count=0&search=" + password
    logger.debug("Trying url=%s with session_key to obtain name=%s" % (url, password))
    res = requests.get(url, headers=headers, verify=False)
    dict = json.loads(res.text)
    if not 'entry' in dict:
        logger.warn("dict=%s did not contain the entries expected on url=%s while looking for password=%s" % (dict, url, password))
        raise Exception('Error while finding password')
    for entry in dict['entry']:
        logger.debug("found=%s looking for :%s:" % (entry['name'], password))
        if entry['name'].find(":" + password + ":") != -1:
            logger.debug("Found password for name=%s in all app contexts" % (password))
            clear_password = entry['content']['clear_password']
            break
    
    if not clear_password:
        logger.warn("Unable to obtain name=%s for the password in any app context, last URL used was url=%s" % (password, url))
        raise Exception('No password found')

    return clear_password
    
