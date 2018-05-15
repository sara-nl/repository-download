#!/usr/bin/env python

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

    if Config.DEBUG and Config.DEBUG_COLORS:
        if mtype == 'debug':
            sys.stdout.write('\x1b[32m')
        elif mtype == 'error':
            sys.stderr.write('\x1b[31m')
        elif mtype == 'notice':
            sys.stderr.write('\x1b[30m')
        elif mtype == 'verbose':
            sys.stderr.write('\x1b[29m')

    if Config.DEBUG:
        frames = inspect.stack()
        try:
            sys.stdout.write('%% %s():%d : ' % (frames[2][3], frames[2][2]))
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

try:
    import sys, os, getopt, requests, inspect, traceback, pprint, copy, cchardet, re, time, math, json, subprocess
except Exception, e:
    error(e, True, 100)

SERVICE = "SURF Data Repository"
TITLE = SERVICE + " download script"
VERSION = "1.0-beta"

TDR_API_BASKET = 'api/basket'
TDR_API_FAVOURITES = 'api/favourites'
TDR_API_OBJECTS = 'api/objects/%s'
TDR_API_STATUS = 'api/objects/%s/%s/status'
TDR_API_STAGE = 'api/objects/%s/%s/stage'

BASE_URL = 'https://tdr-image.surfsara.nl'

STATUS_ONLINE = ['REG', 'DUL']
STATUS_OFFLINE = ['OFL', 'MIG']
STATUS_STAGING = ['UNM']

def bytesize(size):
    p = int(math.floor(math.log(abs(size), 10) / 3)) if abs(size) else 0
    return ("%%%s %%s" % (".1f" if p else "d")) % (size / math.pow(1000, p), ['B','KB','MB','GB','TB','PB','EB'][p])

class FileStatus:
    UNKNOWN = 0
    STAGE = 1
    STAGING = 2
    DOWNLOAD = 3
    DOWNLOADING = 4
    CHECKSUM = 5
    CHECKSUMMING = 6
    FINISHED = 7
    ERROR = 255

class FileObject(object):
    def __init__(self, container, fileObject, status=FileStatus.UNKNOWN):
        self.container = container
        self.object = fileObject
        self.status = status

class DownloadManager(object):
    def __init__(self):
        self.token = None
        self.objects = None
        self.processed = []
        self.cache = {}
        self.files = {}
        self.options = {}
        self.stageObjects = []

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

    def downloadObjectList(self):
        if not self.options['favourites']:
            self.downloadBasket()
        else:
            self.downloadFavourites()

    def downloadBasket(self):
        self.objects = self._requestAuthenticated(TDR_API_BASKET)

        verbose(self.objects)

    def downloadFavourites(self):
        self.objects = self._requestAuthenticated(TDR_API_FAVOURITES)

        verbose(self.objects)

    def _requestStatus(self, pid, fileID = None):
        pids = pid.split(':')
        return self._request(TDR_API_STATUS % (pids[0], pids[1]))

    def _requestAuthenticated(self, endpoint, headers={}, params={}):
        params['token'] = self.token
        return self._request(endpoint, headers, params)

    def _request(self, uri, headers={}, params={}, method='GET'):
        url = "%s/%s" % (self.options['target'], uri) if self.options['target'] not in uri else uri
        r = requests.request(method, url, headers=headers, params=params, verify=self.options['verify'])

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
        elif r.status_code == 401:
            error("could not authorize using token", True)
        elif data is dict and "error" in data:
            error(data["error"])
        else:
            return None

    def processObjectList(self):
        if not self.options['favourites']:
            self.processBasket()
        else:
            self.processFavourites()

    def processBasket(self):
        if self.objects is None or len(self.objects) == 0:
            error('basket is empty', True)

        for b in self.objects:
            pid = b['object']

            self._processObject(pid, b['deposit'], b['fileID'])

    def processFavourites(self):
        if self.objects is None or len(self.objects) == 0:
            error('basket is empty', True)

        for b in self.objects:
            pid = b['object']

            self._processObject(pid)

    def _processObject(self, pid, deposit=None, fileID=None):
        if pid in self.cache.keys():
            debug("in cache: %s" % pid)
            objectInfo = self.cache[pid]
        else:
            objectInfo = self._request(TDR_API_OBJECTS % pid.replace(':', '/'))

        if objectInfo is None:
            return False
        elif pid not in self.cache.keys():
            self.cache[pid] = copy.copy(objectInfo)

        if objectInfo['type'] in ['collection', 'deposit']:
            print "Processing %s" % pid
            if objectInfo['type'] == 'collection':
                # process collections
                for c in objectInfo['collections']:
                    if deposit and c['pid'] != deposit:
                        continue
                    self._processObject(c, deposit)
                # process deposits
                for d in objectInfo['deposits']:
                    if deposit and d['pid'] != deposit:
                        continue
                    self._processObject(d, deposit)
            elif objectInfo['type'] == 'deposit':
                for f in objectInfo['files']:
                    if fileID and f['id'] != fileID:
                        continue
                    if f['status'] in STATUS_OFFLINE:
                        f['dstatus'] = FileStatus.STAGE
                    else:
                        f['dstatus'] = FileStatus.DOWNLOAD

                    f['parent'] = pid

                    self.files[f['url']] = f

        else:
            print "Skipping %s" % pid

        return True

    # report
    def report(self):
        finished = filter(lambda x: x['dstatus'] == FileStatus.FINISHED, self.files.values())
        print "Finished: %s" % map(lambda x: x['name'], finished)

        errors = filter(lambda x: x['dstatus'] == FileStatus.ERROR, self.files.values())
        print "Errors: %s" % map(lambda x: x['name'], errors)

    # initiate download and stage processes
    def startProcesses(self):
        while len(filter(lambda x: not x['dstatus'] in [FileStatus.FINISHED, FileStatus.ERROR], self.files.values())) > 0:
            if len(filter(lambda x: x['dstatus'] in [FileStatus.STAGE, FileStatus.STAGING], self.files.values())) > 0:
                self._processStaging()
            if len(filter(lambda x: x['dstatus'] == FileStatus.DOWNLOAD, self.files.values())) > 0:
                self._processDownloads()
            if len(filter(lambda x: x['dstatus'] == FileStatus.CHECKSUM, self.files.values())) > 0:
                self._processChecksums()

    def _processStaging(self):
        for (i, f) in enumerate(self.files.itervalues()):
            if f['dstatus'] == FileStatus.STAGE:
                if self._stageDeposit(f['parent']):
                    f['dstatus'] = FileStatus.STAGING
                else:
                    f['dstatus'] = FileStatus.ERROR
            elif f['dstatus'] == FileStatus.STAGING:
                if self._statusDeposit(f['parent'], f['id']):
                    f['dstatus'] = FileStatus.DOWNLOAD
                else:
                    f['dstatus'] = FileStatus.ERROR

    def _processDownloads(self):
        for (i, f) in enumerate(self.files.itervalues()):
            if f['dstatus'] == FileStatus.DOWNLOAD:
                if self._downloadFile(f):
                    f['dstatus'] = FileStatus.CHECKSUM
                else:
                    f['dstatus'] = FileStatus.ERROR

    def _processChecksums(self):
        for (i, f) in enumerate(self.files.itervalues()):
            if f['dstatus'] == FileStatus.CHECKSUM:
                if self._checksumFile(f):
                    f['dstatus'] = FileStatus.FINISHED
                else:
                    f['dstatus'] = FileStatus.ERROR

    # download a file and compare the checksum
    def _downloadFile(self, fileObject):
        # request streaming data
        r = requests.get(fileObject['url'], params={'token': self.token}, stream=True, verify=self.options['verify'])

        if r.status_code != 200:
            error('download of file %s failed: %s' % (fileObject['name'], r.reason))
            return False

        debug("%s %s" % (r.request.method, r.url))

        # get file size
        filesize = int(r.headers.get('content-length')) if 'content-length' in r.headers else 1
        totsize = 0

        # download the file in chunks
        with open("%s/%s" % (self.options['outputdir'], fileObject['name']), 'wb') as fout:
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
                progress = "(%d%%, %s, %s/s)" % (totsize * 100. / filesize, bytesize(totsize), bytesize(int(size / elapsed))) if filesize else ""
                if totsize == filesize:
                    sys.stdout.write('\r' + "file %s downloaded %s" % (fileObject['name'], progress))
                else:
                    sys.stdout.write('\r' + "downloading file %s %s" % (fileObject['name'], progress))
                sys.stdout.flush()

            sys.stdout.write('\n')

        return True

    # check the checksum of a downloaded file
    def _checksumFile(self, fileObject):
        text = "comparing local checksum of file '%s'"
        sys.stdout.write(text % fileObject['name'])

        # calculate the local checksum
        output = subprocess.check_output("md5sum %s/%s | awk '{print $1}'" % (self.options['outputdir'], fileObject['name']), shell=True).strip()

        # compare with retrieved checksum
        if output == fileObject['md5']:
            sys.stdout.write("\r" + text % fileObject['name'] + " PASS")
        else:
            sys.stdout.write("\r" + text % fileObject['name'] + " FAIL (%s vs %s)" % (output, fileObject['md5']))

        sys.stdout.write('\n')

        return True

    def _stageDeposit(self, pid):
        # check if deposit has already been staged
        if pid in self.stageObjects:
            return True

        # request stage
        pids = pid.split(':')
        success = self._requestAuthenticated(TDR_API_STAGE % (pids[0], pids[1]))
        if not success:
            error('object staging failed: %s' % pid)
            return False

        debug('staging %s' % pid)
        self.stageObjects.append(pid)

        return True

    def _statusDeposit(self, pid, fileID=None):
        pids = pid.split(':')
        success = self._requestAuthenticated(TDR_API_STATUS % (pids[0], pids[1]))
        if not success:
            error('object status failed: %s' % pid)
            return False

        debug('status %s' % pid)
        return True

def usage(options):
    """ Show usage information """
    print "%s: massively download collections, deposits and individual files from the SURF Data Repository\n" % (TITLE)
    print "Syntax: %s token [options]" % sys.argv[0]
    print "\n where token is your personal access token"
    print "\nOptions:"
    print "--target         -t  set the target instance of %s" % SERVICE
    print "--favourites     -f  download favourites instead of basket (default: %d)" % options['favourites']
    print "--output         -o  set target download directory (default: %d)" % options['outputdir']
    print "--buffer-size    -b  set download buffer size (bytes, default: %d)" % Config.BUFFER_SIZE
    print "--skip-checksum  -s  skip checksum check after download (default: %d)" % options['checksum']
    print "--no-verify          do not verify server certificate (default: %d)" % options['verify']
    print "--version            prints '%s %s'" % (TITLE, VERSION)
    print "--debug          -d  set debuglevel to max"
    print "--help           -h  help mode"
    print "                 -v  verbose mode"

# parse arguments
def main(argv):
    options = {
        'checksum': True,
        'favourites': False,
        'outputdir': "download",
        'target': BASE_URL,
        'verify': False
    }

    # handle arguments
    try:
        opts, args = getopt.gnu_getopt(argv, "hdvo:vfs",  \
            ["help", "version", "debug", "verbose", "output=", "target=", "no-verify", "favourites", "skip-checksum"])
    except getopt.GetoptError as err:
        error(err, True)

    if not args:
        usage(options)
        sys.exit(1)

    # parse other
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt == "--version":
            print "%s %s" % (TITLE, VERSION)
            sys.exit(1)
        elif opt == "--no-verify":
            options.update({'verify': False})
        elif opt in ("-s", "--skip-checksum"):
            options.update({'checksum': False})
        elif opt in ("-f", "--favourites"):
            options.update({'favourites': True})
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

    dm = DownloadManager()
    dm.setToken(args[0])
    dm.setOptions(options)
    dm.downloadObjectList()
    dm.processObjectList()
    dm.startProcesses()
    dm.report()

if __name__ == "__main__":
    main(sys.argv[1:])
