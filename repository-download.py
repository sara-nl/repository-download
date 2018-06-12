#!/usr/bin/env python

class Config:
    DEBUG = False
    DEBUG_COLORS = True
    VERBOSE = False
    QUIET = False
    DRYRUN = False
    BUFFER_SIZE = 8 * 1024 * 1024
    BASE_URL = 'https://tdr-devel.surfsara.nl'

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
            sys.stderr.write('\x1b[33m')

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
    import sys, os, getopt, requests, inspect, traceback, pprint, copy, cchardet, re, time, math, simplejson, subprocess
except Exception, e:
    error(e, True, 100)

SERVICE = "SURF Data Repository"
TITLE = SERVICE + " download tool"
VERSION = "1.0-beta"

TDR_API_BASKET = 'api/basket'
TDR_API_FAVOURITES = 'api/favourites'
TDR_API_OBJECTS = 'api/objects/%s'
TDR_API_STATUS = 'api/objects/%s/%s/status'
TDR_API_STAGE = 'api/objects/%s/%s/stage'

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
    SKIP = 254
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
        self.request = None
        self.rdata = ""
        self.stageObjects = {}
        self.statusObjects = {}

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
            data = self._requestAuthenticated('GET', TDR_API_BASKET)
        else:
            data = self._requestAuthenticated('GET', TDR_API_FAVOURITES)

        self.objects = data['result']

        verbose(self.objects)

    def _requestStatus(self, pid, fileID = None):
        pids = pid.split(':')
        return self._request(TDR_API_STATUS % (pids[0], pids[1]))

    def _requestAuthenticated(self, method, endpoint, headers={}, params={}):
        params['token'] = self.token
        return self._request(endpoint, headers, params, method=method)

    def _request(self, uri, headers={}, params={}, method='GET'):
        url = "%s/%s" % (self.options['target'], uri) if self.options['target'] not in uri else uri

        try:
            self.request = requests.request(method, url, headers=headers, params=params, verify=not self.options['no-verify'], timeout=self.options['request-timeout'])
        except requests.exceptions.ReadTimeout, e:
            error("request time out after %d seconds" % self.options['request-timeout'], True, 2)
        except requests.exceptions.SSLError, e:
            error(e.message, True, 2)

        debug("%s %s" % (method, self.request.url))

        if self.request is None:
            error('internal request failed', True)

        # determine the encoding of the response text
        if self.request.encoding is None:
            self.request.encoding = cchardet.detect(self.request.content)['encoding']

        verbose("%s %s" % (self.request.status_code, self.request.text))

        if 'content-type' in self.request.headers:
            ct = re.search('([a-z]+\/[a-z]+)', self.request.headers['content-type'], re.I)
            if ct.group(1) in ['application/json', 'text/json']:
                try:
                    self.rdata = self.request.json() if self.request.text > "" else {}
                except simplejson.errors.JSONDecodeError, e:
                    error("internal JSON decode error: %s" % e.message, True, 2)
            else:
                self.rdata = self.request.text

        if self.request.status_code == 200:
            return self.rdata
        elif self.request.status_code == 401:
            error("could not authenticate using token", True)
        elif self.rdata is dict and "error" in self.rdata:
            error(self.rdata["error"])
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
            error('favourites list is empty', True)

        for b in self.objects:
            pid = b['object']

            self._processObject(pid)

    def _processObject(self, pid, deposit=None, fileID=None):
        if pid in self.cache.keys():
            debug("in cache: %s" % pid)
            objectInfo = self.cache[pid]
        else:
            data = self._request(TDR_API_OBJECTS % pid.replace(':', '/'))

            if data is None:
                return False

            objectInfo = data['result']

        if pid not in self.cache.keys():
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
                        f['dstatus'] = FileStatus.STAGE if not self.options['skip-staging'] else FileStatus.SKIP
                    else:
                        f['dstatus'] = FileStatus.DOWNLOAD if not self.options['skip-download'] else FileStatus.SKIP

                    f['parent'] = pid

                    self.files[f['url']] = f

        else:
            print "Skipping %s" % pid

        return True

    # report
    def report(self):
        finished = filter(lambda x: x['dstatus'] == FileStatus.FINISHED, self.files.values())

        counts = {}
        for f in finished:
            if not f['parent'] in counts.keys():
                counts[f['parent']] = 0
            counts[f['parent']] += 1

        # report if any objects
        if len(counts) > 0:
            print "Finished (%d objects, %d files): %s" % (len(counts), sum(i for _,i in counts.items()), ", ".join(map(lambda x: "%s (%s)" % x, counts.items())))
        else:
            print "None finished"

        errors = filter(lambda x: x['dstatus'] == FileStatus.ERROR, self.files.values())

        counts = {}
        for f in errors:
            if not f['parent'] in counts.keys():
                counts[f['parent']] = 0
            counts[f['parent']] += 1

        # report if any errors
        if len(counts) > 0:
            print "Errors (%d objects, %d files): %s" % (len(counts), sum(i for _,i in counts.items()), ", ".join(map(lambda x: "%s (%s)" % x, counts.items())))
        else:
            print "No errors"

    # initiate download and stage processes
    def startProcesses(self):
        while len(filter(lambda x: not x['dstatus'] in [FileStatus.FINISHED, FileStatus.ERROR, FileStatus.SKIP], self.files.values())) > 0:
            if len(filter(lambda x: x['dstatus'] in [FileStatus.STAGE, FileStatus.STAGING], self.files.values())) > 0:
                self._processStaging()
            if len(filter(lambda x: x['dstatus'] == FileStatus.DOWNLOAD, self.files.values())) > 0:
                self._processDownloads()
            if len(filter(lambda x: x['dstatus'] == FileStatus.CHECKSUM, self.files.values())) > 0:
                self._processChecksums()

    # process all files and objects to be staged
    def _processStaging(self):
        for (i, f) in enumerate(self.files.itervalues()):
            if f['dstatus'] == FileStatus.STAGE:
                # check if deposit has already been staged recently
                if not f['parent'] in self.stageObjects.keys() or time.time() - self.stageObjects[f['parent']]['updated'] > self.options['stage-interval']:
                    self._stageDeposit(f['parent'])

                if not self._processStageRequest(f):
                    f['dstatus'] = FileStatus.ERROR
            elif f['dstatus'] == FileStatus.STAGING:
                # check if deposit has already been checked for status recently
                if not f['parent'] in self.statusObjects.keys() or time.time() - self.statusObjects[f['parent']]['updated'] > self.options['status-interval']:
                    self._statusDeposit(f['parent'], f['id'])

                # check if status has changed
                if not self._processStatusCheck(f):
                    f['dstatus'] = FileStatus.ERROR

        time.sleep(1)

    def _processStageRequest(self, fileObject):
        # if no status has been found
        if not fileObject['parent'] in self.stageObjects or not self.stageObjects[fileObject['parent']]['result']:
            return False
        # check when last attempt was made
        if 'stage_requested' in fileObject and time.time() - fileObject['stage_requested'] <= self.options['stage-interval']:
            return True

        debug(' Check stage request for file %s' % fileObject['name'])

        # check stage result
        if self.stageObjects[fileObject['parent']]['result']['code'] == '200':
            if fileObject['status'] in STATUS_STAGING:
                fileObject['dstatus'] = FileStatus.STAGING

        fileObject['stage_requested'] = time.time()

        return True

    def _processStatusCheck(self, fileObject):
        # if no status has been found
        if not fileObject['parent'] in self.statusObjects or not self.statusObjects[fileObject['parent']]['result']:
            return False
        # check when last attempt was made
        if 'status_checked' in fileObject and time.time() - fileObject['status_checked'] <= self.options['status-interval']:
            return True

        debug(' Check status for file %s' % fileObject['name'])

        # find file ID in result and check status
        for f in self.statusObjects[fileObject['parent']]['result']:
            if f['id'] == fileObject['id']:
                if f['status'] in STATUS_ONLINE:
                    f['dstatus'] = FileStatus.DOWNLOAD

        fileObject['status_checked'] = time.time()

        return True

    def _processDownloads(self):
        for (i, f) in enumerate(self.files.itervalues()):
            if f['dstatus'] == FileStatus.DOWNLOAD:
                if self._downloadFile(f):
                    f['dstatus'] = FileStatus.CHECKSUM if not self.options['skip-checksum'] else FileStatus.SKIP
                else:
                    f['dstatus'] = FileStatus.ERROR

    def _processChecksums(self):
        for (i, f) in enumerate(self.files.itervalues()):
            if f['dstatus'] == FileStatus.CHECKSUM:
                if self._checksumFile(f):
                    f['dstatus'] = FileStatus.FINISHED
                else:
                    f['dstatus'] = FileStatus.ERROR

    def _stageDeposit(self, pid):
        if len(self.stageObjects) >= self.options['stage-max-count']:
            debug('maximum number of stage requests exceeded')
            return False

        print 'Staging %s' % pid

        pids = pid.split(':')
        success = self._requestAuthenticated('POST', TDR_API_STAGE % (pids[0], pids[1]))

        # add to stage cache
        self.stageObjects.update({pid: {'updated': time.time(), 'result': None}})

        if not success:
            error('object staging of %s failed (%s): %s' % (pid, self.request.status_code, self.rdata['error']))
            return False

        self.stageObjects[pid]['result'] = self.rdata

        return True

    def _statusDeposit(self, pid, fileID=None):
        print 'Status %s' % pid

        pids = pid.split(':')
        success = self._requestAuthenticated(TDR_API_STATUS % (pids[0], pids[1]))

        # add to status cache
        self.statusObjects.update({pid: {'updated': time.time(), 'result': None}})

        if not success:
            error('object status of %s failed (%s): %s' % (pid, self.request.status_code, self.rdata['error']))
            return False

        print self.rdata
        self.statusObjects[pid]['result'] = self.rdata

        return True

    # download a file and compare the checksum
    # if the target file exists, compare size and checksum
    def _downloadFile(self, fileObject):
        # define the target output dir
        targetdir = "%s/%s" % (self.options['outputdir'], fileObject['parent'].replace(':', '/'))
        fileObject['target'] = "%s/%s" % (targetdir, fileObject['name'])

        headers = {}
        mode = 'wb'
        localfilesize = 0

        # check if file is present
        if not self.options['force-overwrite'] and os.path.exists(fileObject['target']):
            # compare size, if equal return
            localfilesize = os.path.getsize(fileObject['target'])
            if localfilesize == int(fileObject['size']):
                print "File %s of %s already downloaded" % (fileObject['name'], fileObject['parent'])
                return True
            elif not self.options['no-resume'] and localfilesize > 0:
                print "Resuming download of file %s of %s at offset %d bytes" % (fileObject['name'], fileObject['parent'], localfilesize)
                headers.update({'Range': "bytes=%d-" % localfilesize})
                mode = 'a+b'

        # request streaming data
        try:
            self.request = requests.get(fileObject['url'], headers=headers, params={'token': self.token}, stream=True, verify=not self.options['no-verify'])
        except Exception, e:
            error(e)

        if self.request.status_code not in [200, 206]:
            error('download of file %s failed: %s' % (fileObject['name'], self.request.reason))
            return False

        debug("%s %s" % (self.request.request.method, self.request.url))

        # get file size
        filesize = int(self.request.headers.get('content-length')) if 'content-length' in self.request.headers else 1
        totsize = localfilesize

        # create the output dir
        try:
            if not os.path.exists(targetdir):
                os.makedirs(targetdir)
        except OSError, e:
            error(e, True, 101)

        # download the file in chunks (append if resuming)
        with open(fileObject['target'], mode) as fout:
            fout.seek(localfilesize, os.SEEK_SET)

            start = time.clock()
            elapsed = 1
            for chunk in self.request.iter_content(chunk_size=Config.BUFFER_SIZE):
                if chunk:
                    size = len(chunk)
                    totsize += size
                    fout.write(chunk)

                # print progress
                progress = "(%d%% of %s, %s/s)" % (totsize * 100. / int(fileObject['size']), bytesize(int(fileObject['size'])), bytesize(int(totsize / elapsed))) if filesize else ""
                if totsize == filesize:
                    sys.stdout.write("\rFile %s of %s downloaded %s" % (fileObject['name'], fileObject['parent'], progress))
                else:
                    sys.stdout.write("\rDownloading file %s of %s %s" % (fileObject['name'], fileObject['parent'], progress))
                sys.stdout.flush()

                # get elapsed time
                elapsed = time.clock() - start

            sys.stdout.write('\n')

        return True

    # check the checksum of a downloaded file
    def _checksumFile(self, fileObject):
        text = "Comparing local checksum of object %s file '%s'"
        sys.stdout.write(text % (fileObject['parent'], fileObject['name']))

        # calculate the local checksum
        try:
            output = subprocess.check_output("md5sum %s | awk '{print $1}'" % (fileObject['target']), shell=True).strip()
        except subprocess.CalledProcessError, e:
            error(e, True, 102)

        # compare with retrieved checksum
        if output == fileObject['md5']:
            sys.stdout.write("\r" + text % (fileObject['parent'], fileObject['name']) + " PASS")
        else:
            sys.stdout.write("\r" + text % (fileObject['parent'], fileObject['name']) + " FAIL (%s (local) vs %s (remote))" % (output, fileObject['md5']))

        # store checksum if requested
        if self.options['store-checksum']:
            with open("%s.md5" % fileObject['target'], 'w') as f:
                f.write(output)
                f.close()

        sys.stdout.write('\n')

        return output == fileObject['md5']

def bools(b):
    return "yes" if b else "no"

def usage(options):
    """ Show usage information """
    print "%s v%s: massively download collections, deposits and individual files from the %s\n" % (TITLE, VERSION, SERVICE)
    print "Syntax: %s [options] token" % sys.argv[0]
    print "\nwhere token is your personal API access token. If you do not have an API token yet, create one on the %s website." % SERVICE
    print "\nOptions:"
    print "--target          -t  set the target instance of %s (default: '%s')" % (SERVICE, Config.BASE_URL)
    print "--favourites          download favourites instead of basket (default: %s)" % bools(options['favourites'])
    print "--output          -o  set target download directory (default: '%s')" % options['outputdir']
    print "--buffer-size     -b  set download buffer size (bytes, default: %d)" % Config.BUFFER_SIZE
    print "--force-overwrite     force overwrite of existing files (default: %s)" % bools(options['force-overwrite'])
    print "--skip-staging        skip staging of objects (default: %s)" % bools(options['skip-staging'])
    print "--skip-download       skip downloading of files (default: %s)" % bools(options['skip-download'])
    print "--skip-checksum       skip checksum check after download (default: %s)" %  bools(options['skip-checksum'])
    print "--no-resume           do not resume partially downloaded files, redownload instead (default: %s)" % bools(options['no-resume'])
    print "--store-checksum      store generated checksum after download (default: %s)" % bools(options['store-checksum'])
    print "--no-verify           verify server certificate (default: %s)" % bools(options['verify'])
    print "--debug           -d  set debuglevel to max (default: %s)" % bools(Config.DEBUG)
    print "--dry-run         -n  dry-run mode, simulate staging, downloads and further processing (default: %s)" % bools(Config.DRYRUN)
    print "--version             prints '%s %s'" % (TITLE, VERSION)
    print "--help            -h  help mode"
    print "                  -v  verbose mode"

# parse arguments
def main(argv):
    options = {
        'store-checksum': False,
        'force-overwrite': False,
        'skip-staging': False,
        'skip-download': False,
        'skip-checksum': False,
        'no-resume': False,
        'favourites': False,
        'request-timeout': 30,
        'status-interval': 30,
        'stage-interval': 60,
        'stage-max-count': 10,
        'outputdir': "download",
        'max-download-size': 0,
        'target': Config.BASE_URL,
        'no-verify': False
    }

    # handle arguments
    try:
        opts, args = getopt.gnu_getopt(argv, "hdb:vo:t:n",  \
            ["help", "version", "debug", "verbose", "output=", "target=", "no-verify", "favourites", "skip-checksum", "store-checksum", "buffer-size=", "dry-run", "no-resume", "force-overwrite", "skip-download", "skip-staging"])
    except getopt.GetoptError as err:
        error(err, True)

    if not args and not ('-h' in opts or '--help' in opts):
        error("missing token")
        usage(options)
        sys.exit(1)

    # parse other
    for opt, arg in opts:
        if opt in ["-h", "--help"]:
            usage()
            sys.exit()
        elif opt == "--version":
            print "%s %s" % (TITLE, VERSION)
            sys.exit(1)
        elif opt in ["--no-verify", "--skip-checksum", "--store-checksum", "--skip-download", "--skip-staging", "--no-resume", "--force-overwrite", "--favourites"]:
            options.update({opt[2:]: True})
        elif opt in ["-d", "--debug"]:
            Config.DEBUG = True
        elif opt in ["-n", "--dry-run"]:
            Config.DRYRUN = True
        elif opt in ["-v", "--verbose"]:
            Config.VERBOSE = True
        elif opt in ["-b", "--buffer-size"]:
            Config.BUFFER_SIZE = int(arg)
        elif opt in ["-o", "--output"]:
            options.update({'outputdir': arg})
        elif opt in ["-t", "--target"]:
            options.update({'target': arg})

    # start procedures
    dm = DownloadManager()
    dm.setToken(args[0])
    dm.setOptions(options)
    dm.downloadObjectList()
    dm.processObjectList()
    dm.startProcesses()
    dm.report()

if __name__ == "__main__":
    main(sys.argv[1:])
