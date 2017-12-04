#!/usr/bin/env python

import sys, os, getopt, requests, inspect, traceback, pprint, copy

SERVICE = "SURF Data Repository"
TITLE = SERVICE + " basket download script"
VERSION = "0.1"

TDR_API_BASKET = 'api/basket'
BASE_URL = 'https://tdr-image.surfsara.nl'

class Config:
    DEBUG = False
    DEBUG_COLORS = True
    VERBOSE = False
    QUIET = False
    DRYRUN = False

def message(msg, mtype = 'debug', showstack = False):
    ''' Print message'''

    if (mtype == 'debug' and not Config.DEBUG) \
        or (mtype == 'verbose' and not Config.VERBOSE) \
        or Config.QUIET:
        return

    if Config.DEBUG_COLORS:
        if mtype == 'debug':
            sys.stdout.write('\x1b[32m')
        elif mtype == 'error':
            sys.stderr.write('\x1b[31m')
        elif mtype == 'notice':
            sys.stderr.write('\x1b[30m')
        elif mtype == 'verbose':
            sys.stderr.write('\x1b[29m')

    frames = inspect.stack()
    try:
        sys.stdout.write('%% %s(): ' % frames[2][3])
    finally:
        # this breaks reference cycles in Python interpreter
        del frames

    if Config.DEBUG_COLORS:
        sys.stdout.write('\x1b[0m')

    print(msg)

def error(msg, doExit = False, exitCode = 1):
    message("error: %s" % msg, 'error', True)

    if doExit:
        sys.exit(exitCode)

def debug(msg):
    message(msg)

def notice(msg):
    message(msg, 'notice')

def verbose(msg):
    message(msg, 'verbose')

class DownloadManager(object):
    def __init__(self):
        self.token = None
        self.basket = None
        self.processed = []
        self.cache = {}
        self.files = {}

        requests.packages.urllib3.disable_warnings()

    def setToken(self, token):
        self.token = token
        debug("Token: " + token)

    def setOutputDir(self, target):
        path = "%s/%s" % (os.getcwd(), target)
        if not os.path.exists(path):
            notice("path created: %s" % path)
            os.mkdir(path)

    def downloadBasket(self):
        self.basket = self._requestAuthenticated(TDR_API_BASKET)

        verbose(self.basket)

    def _requestAuthenticated(self, endpoint, headers={}, params={}):
        params['token'] = self.token

        return self._request(endpoint, headers, params)

    def _request(self, endpoint, headers={}, params={}):
        r = requests.get("%s/%s" % (BASE_URL, endpoint), headers=headers, params=params, verify=False)

        debug(r.url)

        if not r or r is None:
            error('internal request failed', True)

        data = r.json() if r.text > "" else {}

        if r.status_code == 200:
            return data
        elif "error" in data:
            error(data["error"], True)
        else:
            return None

    def processBasket(self):
        if self.basket is None or len(self.basket) == 0:
            error('basket is empty', True)

        for b in self.basket:
            pid = b['object'].replace(':', '/')

            print "Processing %s" % b['object']

            self._processObject(pid, b['deposit'], b['fileID'])

    def _processObject(self, pid, deposit=None, fileID=None):
        if pid in self.cache.keys():
            debug("in cache: %s" % pid)
            objectInfo = self.cache[pid]
        else:
            objectInfo = self._request('api/object/%s' % pid)

        if objectInfo is None:
            return False
        elif pid not in self.cache.keys():
            self.cache[pid] = copy.copy(objectInfo)

        if objectInfo['type'] == 'collection':
            for c in objectInfo['collections']:
                if deposit and c['pid'] != deposit:
                    continue
                self._processObject(c, deposit)
            for d in objectInfo['deposits']:
                if deposit and d['pid'] != deposit:
                    continue
                self._processObject(d, deposit)
        elif objectInfo['type'] == 'deposit':
            for f in objectInfo['files']:
                if fileID and f['id'] != fileID:
                    continue
                self._addFile(pid, f)

        return True

    def _addFile(self, pid, fileInfo):
        if pid in self.files:
            if fileInfo['url'] in self.files[pid].keys():
                return False
        else:
            self.files[pid] = {}

        self.files[pid].update({fileInfo['url']: fileInfo})

        return True

    def downloadFiles(self):
        for obj in self.files.iteritems():
            if self.checkStatus()


def usage():
    """ Show usage information """
    print "%s: massively download collections, deposits and individual files from the SURF Data Repository\n" % (TITLE)
    print "Syntax: %s token [options]" % sys.argv[0]
    print "\n where token is your personal access token"
    print "\nOptions:"
    print "--version        prints %s %s" % (TITLE, VERSION)
    print "--debug      -d  set debuglevel to max"
    print "--help       -h  help mode"
    print "             -v  verbose mode"

# parse arguments
def main(argv):
    outputdir = "download"

    # handle arguments
    try:
        opts, args = getopt.gnu_getopt(argv, "hdvf:o:v",  \
            ["help", "version", "debug", "verbose", "output="])
    except getopt.GetoptError as err:
        error(err, True)

    # parse other
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt == "--version":
            print "%s %s" % (TITLE, VERSION)
            sys.exit(1)
        elif opt in ("-d", "--debug"):
            Config.DEBUG = True
        elif opt in ("-v", "--verbose"):
            Config.VERBOSE = True
        elif opt in ("-o", "--output"):
            outputdir = arg

    if not args:
        usage()
        sys.exit(1)

    dm = DownloadManager()
    dm.setToken(args[0])
    dm.setOutputDir(outputdir)
    dm.downloadBasket()
    dm.processBasket()
    dm.downloadFiles()

if __name__ == "__main__":
    main(sys.argv[1:])
