#!/usr/bin/env python

import sys, os, getopt, requests, inspect, traceback, pprint, copy, cchardet, re, time, math

SERVICE = "SURF Data Repository"
TITLE = SERVICE + " basket download script"
VERSION = "0.1"

TDR_API_BASKET = 'api/basket'
TDR_API_STATUS = 'api/status'
TDR_API_STAGE = 'api/stage'

BASE_URL = 'https://tdr-image.surfsara.nl'

STATUS_ONLINE = ['REG', 'DUL']
STATUS_OFFLINE = ['OFL', 'MIG']
STATUS_STAGING = ['UNM']

class Config:
    DEBUG = False
    DEBUG_COLORS = True
    VERBOSE = False
    QUIET = False
    DRYRUN = False
    BUFFER_SIZE = 1024 * 1024

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

def bytesize(size):
    p = int(math.floor(math.log(abs(size), 10) / 3)) if abs(size) else 0
    return ("%%%s %%s" % (".1f" if p else "d")) % (size / math.pow(1000, p), ['B','KB','MB','GB','TB','PB','EB'][p])

class DownloadManager(object):
    def __init__(self):
        self.token = None
        self.basket = None
        self.processed = []
        self.cache = {}
        self.files = {}
        self.options = {}

        requests.packages.urllib3.disable_warnings()

    def setToken(self, token):
        self.token = token
        debug("Token: " + token)

    def setOutputDir(self, directory):
        path = "%s/%s" % (os.getcwd(), directory)
        if not os.path.exists(path):
            notice("path created: %s" % path)
            os.mkdir(path)

        self.options.update({'outputdir': directory})

    def setOptions(self, options):
        for (k,v) in options.iteritems():
            try:
                index = map(str.lower, dir(self)).index(("set%s" % k).lower())
                method = getattr(self, dir(self)[index])
                method(v)
            except Exception, e:
                self.options.update({k: v})

    def downloadBasket(self):
        self.basket = self._requestAuthenticated(TDR_API_BASKET)

        verbose(self.basket)

    def _requestStatus(self, pid, fileID = None):
        return self._request("%s/%s/%s" % (TDR_API_STATUS, pid, "" if fileID is None else fileID))

    def _requestAuthenticated(self, endpoint, headers={}, params={}):
        params['token'] = self.token

        return self._request(endpoint, headers, params)

    def _request(self, uri, headers={}, params={}, method='GET'):
        url = "%s/%s" % (self.options['target'], uri) if self.options['target'] not in uri else uri
        r = requests.request(method, url, headers=headers, params=params, verify=False)

        debug("%s %s" % (method, r.url))

        if r is None:
            error('internal request failed', True)

        # determine the encoding of the response text
        if r.encoding is None:
            r.encoding = cchardet.detect(r.content)['encoding']

        if 'content-type' in r.headers:
            ct = re.search('([a-z]+\/[a-z]+)', r.headers['content-type'], re.I)
            if ct.group(1) in ['application/json', 'text/json']:
                data = r.json() if r.text > "" else {}
            else:
                data = r.text

        if r.status_code == 200:
            return data
        elif data is dict and "error" in data:
            error(data["error"])
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
        for i, (pid, obj) in enumerate(self.files.iteritems()):
            status = self._requestStatus(pid)

            verbose('status: %s' % status)
            if not status:
                continue

            for f in status:
                if f['status'] in STATUS_ONLINE:
                    self._downloadFile(f['url'], f['name'])
                elif f['status'] in STATUS_STAGING:
                    continue
                elif f['status'] in STATUS_OFFLINE:
                    self._stageDeposit(pid)

    def _downloadFile(self, url, filename):
        debug('Downloading %s' % url)

        # request streaming data
        r = requests.get(url, params={'token': self.token}, stream=True, verify=False)

        if r.status_code != 200:
            error('download of %s failed: %s' % (filename, r.reason))
            return False

        filesize = int(r.headers.get('content-length'))
        totsize = 0

        with open("%s/%s" % (self.options['outputdir'], filename), 'wb') as fout:
            start = time.clock()
            for chunk in r.iter_content(chunk_size=Config.BUFFER_SIZE):
                if chunk:
                    size = len(chunk)
                    totsize += size
                    fout.write(chunk)

                # measure download speed
                elapsed = time.clock() - start
                start = time.clock()

                # print progress
                text = " Downloading file %s (%d%%, %s/s)" % (filename, totsize * 100. / filesize, bytesize(int(size / elapsed)))
                sys.stdout.write('\r' + text)
                sys.stdout.flush()

            sys.stdout.write('\n')

        return True

    def _stageDeposit(self, pid):
        debug(' Staging %s' % pid)
        success = self._requestAuthenticated("%s/%s" % (TDR_API_STAGE, pid))
        if not success:
            error('file staging failed: %s' % pid)
            return False

        return True

def usage():
    """ Show usage information """
    print "%s: massively download collections, deposits and individual files from the SURF Data Repository\n" % (TITLE)
    print "Syntax: %s token [options]" % sys.argv[0]
    print "\n where token is your personal access token"
    print "\nOptions:"
    print "--target       -t  set the target instance of %s" % SERVICE
    print "--output       -o  set target download directory"
    print "--buffer-size  -b  set download buffer size (bytes, default: %d)" % Config.BUFFER_SIZE
    print "--version          prints %s %s" % (TITLE, VERSION)
    print "--debug        -d  set debuglevel to max"
    print "--help         -h  help mode"
    print "               -v  verbose mode"

# parse arguments
def main(argv):
    options = {
        'outputdir': "download",
        'target': BASE_URL
    }

    # handle arguments
    try:
        opts, args = getopt.gnu_getopt(argv, "hdvf:o:v",  \
            ["help", "version", "debug", "verbose", "output=", "target="])
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
        elif opt in ("-b", "--buffer-size"):
            Config.BUFFER_SIZE = int(arg)
        elif opt in ("-o", "--output"):
            options.update({'outputdir': arg})
        elif opt in ("-t", "--target"):
            options.update({'target': arg})

    if not args:
        usage()
        sys.exit(1)

    dm = DownloadManager()
    dm.setToken(args[0])
    dm.setOptions(options)
    dm.downloadBasket()
    dm.processBasket()
    dm.downloadFiles()

if __name__ == "__main__":
    main(sys.argv[1:])
