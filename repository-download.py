#!/usr/bin/env python3

# Copyright 2018-2019 SURFsara B.V.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys, os, getopt

class Config:
    DEBUG = False
    DEBUG_COLORS = True
    VERBOSE = False
    QUIET = False
    DRYRUN = False
    BUFFER_SIZE = 2 * 1024 * 1024
    BASE_URL = 'https://repository.surfsara.nl'

def message(msg, mtype='debug', color=0, showstack=False, out=sys.stdout):
    ''' Print message'''

    if (mtype == 'debug' and not Config.DEBUG) \
        or (mtype == 'verbose' and not Config.VERBOSE) \
        or Config.QUIET:
        return

    if Config.DEBUG and Config.DEBUG_COLORS:
        out.write("\x1b[%sm" % color)

    if Config.DEBUG:
        frames = inspect.stack()
        try:
            out.write('%% %s():%d : ' % (frames[2][3], frames[2][2]))
        finally:
            # this breaks reference cycles in Python interpreter
            del frames

    if Config.DEBUG_COLORS:
        out.write('\x1b[0m')

    out.write("%s: %s\n" % (mtype, msg))

def error(msg, exitCode=None):
    message("error: %s" % msg, 'error', 31, True, out=sys.stderr)

    if not exitCode is None:
        sys.exit(exitCode)

def debug(msg):
    message(msg, color=32)

def notice(msg):
    message(msg, 'notice', color=30)

def verbose(msg):
    message(msg, 'verbose', color=33)

try:
    import signal, requests, inspect, pprint, copy, cchardet, re, time, math, simplejson, subprocess
except ModuleNotFoundError as e:
    error("%s found, please install the module by running the command: pip install %s" % (e, str(e).split(' ')[-1].strip('\'')), 1)

SERVICE = "SURF Data Repository"
TITLE = SERVICE + " download tool"
VERSION = "1.0-beta-2"

TDR_API_BASKET = 'api/basket'
TDR_API_FAVOURITES = 'api/favourites'
TDR_API_OBJECTS = 'api/objects/%s'
TDR_API_STATUS = 'api/objects/%s/%s/status'
TDR_API_STAGE = 'api/objects/%s/%s/stage'
TDR_API_STAGE_FILE = 'api/objects/%s/%s/stage/%s'

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
    def __init__(self, token=None, options={}):
        self.setToken(token)
        self.setOptions(options)

        self.objects = None
        self.processed = []
        self.cache = {}
        self.files = {}
        self.request = None
        self.rdata = ""
        self.stageObjects = {}
        self.statusObjects = {}

        self.reset()

        requests.packages.urllib3.disable_warnings()

    def reset(self):
        self.cache = {}
        self.report = {
            'total-download-size': 0,
            'bytes-downloaded': 0
        }

    def setToken(self, token):
        self.token = token
        if not token is None:
            debug("Token: " + token)

    def setOutputDir(self, directory):
        path = "%s/%s" % (os.getcwd(), directory)
        if not os.path.exists(path):
            notice("path created: %s" % path)
            os.mkdir(path)

        self.options.update({'outputdir': directory})

    def setOptions(self, options):
        self.options = {}
        if not options:
            return
        for k, v in options.items():
            try:
                index = map(str.lower, dir(self)).index(("set%s" % k).lower())
                method = getattr(self, dir(self)[index])
                method(v)
            except Exception as e:
                self.options.update({k: v})

    def downloadObjectList(self):
        print("Downloading your %s" % ("basket" if not self.options['favourites'] else "favourites"))
        if not self.options['favourites']:
            data = self._requestAuthenticated('GET', TDR_API_BASKET)
        else:
            data = self._requestAuthenticated('GET', TDR_API_FAVOURITES)

        self.objects = data['result']

        verbose(self.objects)

    def _requestStatus(self, pid, fileID = None):
        pids = pid.split(':')
        url = TDR_API_STATUS % (pids[0], pids[1])

        if fileID:
            url += "/%s" % fileID

        return self._requestAuthenticated('GET', url)

    def _requestStage(self, pid, fileID = None):
        pids = pid.split(':')
        url = TDR_API_STAGE % (pids[0], pids[1])

        if fileID:
            url += "/%s" % fileID

        return self._requestAuthenticated('POST', url)

    def _requestAuthenticated(self, method, endpoint, headers={}, params={}):
        params['token'] = self.token
        return self._request(endpoint, headers, params, method=method)

    def _request(self, uri, headers={}, params={}, method='GET'):
        url = "%s/%s" % (self.options['target'], uri) if self.options['target'] not in uri else uri

        try:
            self.request = requests.request(method, url, headers=headers, params=params, verify=not self.options['no-verify'], timeout=self.options['request-timeout'])
        except requests.exceptions.ReadTimeout as e:
            error("request time out after %d seconds" % self.options['request-timeout'], 2)
        except requests.exceptions.SSLError as e:
            error(e, 2)

        debug("%s %s" % (method, self.request.url))

        if self.request is None:
            error('internal request failed', 3)

        # determine the encoding of the response text
        if self.request.encoding is None:
            self.request.encoding = cchardet.detect(self.request.content)['encoding']

        verbose("%s %s" % (self.request.status_code, self.request.text))

        if 'content-type' in self.request.headers:
            ct = re.search('([a-z]+\/[a-z]+)', self.request.headers['content-type'], re.I)
            if ct.group(1) in ['application/json', 'text/json']:
                try:
                    self.rdata = self.request.json() if self.request.text > "" else {}
                except simplejson.errors.JSONDecodeError as e:
                    error("internal JSON decode error: %s" % e.message, 2)
            else:
                self.rdata = self.request.text

        if self.request.status_code == 200:
            return self.rdata
        elif self.request.status_code == 401:
            error("could not authenticate using token", 2)
        elif self.request.status_code >= 300:
            error("request failed: %s %s" % (self.request.status_code, self.request.reason), 2)
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
        if not self.objects:
            error('basket is empty', 1)

        for b in self.objects:
            pid = b['object']

            self._processObject(pid, b['deposit'], b['fileID'])

    def processFavourites(self):
        if not self.objects:
            error('favourites list is empty', 1)
        for b in self.objects:
            pid = b['object']

            self._processObject(pid)

    def _processObject(self, pid, deposit=None, fileID=None):
        if pid in self.cache:
            debug("in cache: %s" % pid)
            objectInfo = self.cache[pid]
        else:
            print("Processing %s" % pid)

            data = self._request(TDR_API_OBJECTS % pid.replace(':', '/'))

            if data is None:
                return False

            objectInfo = data['result']

        if pid not in self.cache:
            self.cache[pid] = copy.copy(objectInfo)

        if objectInfo['type'] in ['collection', 'deposit']:
            if objectInfo['type'] == 'collection':
                # process collections, limit if optioned
                objects = objectInfo['collections'][:self.options['max-childs']] if self.options['max-childs'] > 0 else objectInfo['collections']
                for c in objects:
                    if deposit and c['pid'] != deposit:
                        continue
                    self._processObject(c, deposit)
                # process deposits, limit if optioned
                objects = objectInfo['deposits'][:self.options['max-childs']] if self.options['max-childs'] > 0 else objectInfo['deposits']
                for d in objects:
                    if deposit and d['pid'] != deposit:
                        continue
                    self._processObject(d, deposit)
            elif objectInfo['type'] == 'deposit':
                # process deposits, limit if optioned
                objects = objectInfo['files'][:self.options['max-files']] if self.options['max-files'] > 0 else objectInfo['files']
                for f in objects:
                    if fileID and f['id'] != fileID:
                        continue
                    if f['status'] in STATUS_OFFLINE:
                        f['dstatus'] = FileStatus.STAGE if not self.options['skip-staging'] else FileStatus.SKIP
                    else:
                        f['dstatus'] = FileStatus.DOWNLOAD if not self.options['skip-download'] else FileStatus.SKIP

                    f['parent'] = pid

                    self.files[f['url']] = f

        else:
            print("Skipping %s" % pid)

        return True

    # report before processes are initiated
    def preReport(self):
        counts = {}
        for f in self.files.values():
            if not f['parent'] in counts:
                counts[f['parent']] = 0
            counts[f['parent']] += 1

        self.report['total-download-size'] = sum(int(i['size']) for _,i in self.files.items())

        print("Total download size: %s in %d files (%d objects)" % (bytesize(self.report['total-download-size']), len(self.files.values()), len(counts)))

    # report after processes are completed
    def postReport(self):
        finished = filter(lambda x: x['dstatus'] == FileStatus.FINISHED, self.files.values())

        counts = {}
        for f in finished:
            if not f['parent'] in counts:
                counts[f['parent']] = 0
            counts[f['parent']] += 1

        # report if any objects
        if counts:
            print("Finished (%d objects, %d files): %s" % (len(counts), sum(i for _,i in counts.items()), ", ".join(map(lambda x: "%s (%s)" % x, counts.items()))))
        else:
            print("None of objects finished")

        errors = filter(lambda x: x['dstatus'] == FileStatus.ERROR, self.files.values())

        counts = {}
        for f in errors:
            if not f['parent'] in counts:
                counts[f['parent']] = 0
            counts[f['parent']] += 1

        # report if any errors
        if counts:
            print("Errors (%d objects, %d files): %s" % (len(counts), sum(i for _,i in counts.items()), ", ".join(map(lambda x: "%s (%s)" % x, counts.items()))))
        else:
            print("No errors")

    # initiate download and stage processes
    def startProcesses(self):
        if len(self.files) == 0:
            notice("There are no files to be processed")
            return True

        while len([*filter(lambda x: not x['dstatus'] in [FileStatus.FINISHED, FileStatus.ERROR, FileStatus.SKIP], self.files.values())]) > 0:
            if len([*filter(lambda x: x['dstatus'] in [FileStatus.STAGE], self.files.values())]) > 0:
                self._processStaging()
            if len([*filter(lambda x: x['dstatus'] in [FileStatus.STAGING, FileStatus.DOWNLOAD], self.files.values())]) > 0:
                self._processDownloads()
            if len([*filter(lambda x: x['dstatus'] in [FileStatus.CHECKSUM], self.files.values())]) > 0:
                self._processChecksums()

            time.sleep(1)

    # process all files and objects to be staged
    def _processStaging(self):
        for (i, f) in enumerate(self.files.values()):
            if f['dstatus'] == FileStatus.STAGE:
                # check if deposit has already been staged recently
                if not 'stage_request' in f:
                    self._stageDepositFile(f)

                # if not self._processStageRequest(f):
                #     f['dstatus'] = FileStatus.ERROR

        return True

    def _processStageRequest(self, fileObject):
        # if no status has been found
        if not 'stage_request' in fileObject or not fileObject['stage_request']['result']:
            return False
        # check when last attempt was made
        if time.time() - fileObject['stage_request']['updated'] <= self.options['stage-interval']:
            return True

        debug(' Check stage request for file %s %s' % (fileObject['name'], fileObject['stage_request']['result']['code']))

        # check stage result, if successful set to staging
        if fileObject['stage_request']['result']['code'] == 200:
            fileObject['dstatus'] = FileStatus.STAGING

        return True

    def _processStatusCheck(self, fileObject):
        # if no status has been found
        if not 'status_request' in fileObject or not fileObject['status_request']['result']:
            return False

        debug(' Check status for file %s' % fileObject['name'])

        if fileObject['status_request']['result']['code'] == 200:
            if fileObject['status_request']['result']['result'] in STATUS_ONLINE:
                fileObject['dstatus'] = FileStatus.DOWNLOAD

        # remove current status result
        del fileObject['status_request']

        return True

    def _processDownloads(self):
        for (i, f) in enumerate(self.files.values()):
            if f['dstatus'] == FileStatus.STAGING:
                # check if deposit has already been checked for status recently
                if not 'status_request' in f:
                    self._statusDepositFile(f)
                elif 'updated' in f['status_request'] and time.time() - f['status_request']['updated'] <= self.options['status-interval']:
                    continue

                # check if status has changed
                if not self._processStatusCheck(f):
                    f['dstatus'] = FileStatus.ERROR
            elif f['dstatus'] == FileStatus.DOWNLOAD:
                if self._downloadFile(f):
                    f['dstatus'] = FileStatus.CHECKSUM if not self.options['skip-checksum'] else FileStatus.FINISHED
                else:
                    f['dstatus'] = FileStatus.ERROR

        return True

    def _processChecksums(self):
        for (i, f) in enumerate(self.files.values()):
            if f['dstatus'] == FileStatus.CHECKSUM:
                if self._checksumFile(f):
                    f['dstatus'] = FileStatus.FINISHED
                else:
                    f['dstatus'] = FileStatus.ERROR

        return True

    def _stageDeposit(self, pid):
        if len(self.stageObjects) >= self.options['stage-max-count']:
            debug('maximum number of stage requests exceeded')
            return False

        print('Staging %s' % pid)

        success = self._requestStage(pid)

        # add to stage cache
        self.stageObjects.update({pid: {'updated': time.time(), 'result': None}})

        if not success:
            error('object staging of %s failed (%s): %s' % (pid, self.request.status_code, self.rdata['error']))
            return False

        self.stageObjects[pid]['result'] = self.rdata

        return True

    def _stageDepositFile(self, fileObject):
        print('Staging file %s of object %s' % (fileObject['name'], fileObject['parent']))

        success = self._requestStage(fileObject['parent'], fileObject['id'])

        # add to stage cache
        fileObject['stage_request'] = {'updated': time.time(), 'result': None}

        if not success:
            error('object staging of %s failed (%s): %s' % (fileObject['parent'], self.request.status_code, self.rdata['error']))
            return False

        fileObject['stage_request']['result'] = self.rdata

        return True

    def _statusDeposit(self, pid):
        print('Status %s' % pid)

        success = self._requestStatus(pid)

        # add to status cache
        self.statusObjects.update({pid: {'updated': time.time(), 'result': None}})

        if not success:
            error('object status of %s failed (%s): %s' % (pid, self.request.status_code, self.rdata['error']))
            return False

        self.statusObjects[pid]['result'] = self.rdata

        return True

    def _statusDepositFile(self, fileObject):
        print('Status file %s of object %s' % (fileObject['name'], fileObject['parent']))

        success = self._requestStatus(fileObject['parent'], fileObject['id'])

        # add to status cache
        fileObject['status_request'] = {'updated': time.time(), 'result': None}

        if not success:
            error('object status of %s failed (%s): %s' % (fileObject['parent'], self.request.status_code, self.rdata['error']))
            return False

        fileObject['status_request']['result'] = self.rdata

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

            # add to reported total download size
            self.report['bytes-downloaded'] += localfilesize

            if localfilesize == int(fileObject['size']):
                print("File %s of %s already downloaded" % (fileObject['name'], fileObject['parent']))
                return True
            elif not self.options['no-resume'] and localfilesize > 0:
                debug("Resuming download of file %s of %s at byte offset %d" % (fileObject['name'], fileObject['parent'], localfilesize))
                headers.update({'Range': "bytes=%d-" % localfilesize})
                mode = 'a+b'

        # request streaming data
        try:
            self.request = requests.get(fileObject['url'], headers=headers, params={'token': self.token}, stream=True, verify=not self.options['no-verify'])
        except Exception as e:
            error(e)

        if self.request.status_code not in [200, 206]:
            error('download of file %s failed: %s' % (fileObject['name'], self.request.reason))
            return False

        debug("%s %s" % (self.request.request.method, self.request.url))

        # get file size
        filesize = int(self.request.headers.get('content-length')) if 'content-length' in self.request.headers else 1
        totsize = localfilesize
        downsize = 0

        # create the output dir
        try:
            if not os.path.exists(targetdir):
                os.makedirs(targetdir)
        except OSError as e:
            error(e, 101)

        # download the file in chunks (append if resuming)
        try:
            with open(fileObject['target'], mode) as fout:
                fout.seek(localfilesize, os.SEEK_SET)

                start = time.process_time()
                for chunk in self.request.iter_content(chunk_size=Config.BUFFER_SIZE):
                    if chunk:
                        size = len(chunk)
                        downsize += size
                        totsize += size
                        fout.write(chunk)

                    # print progress
                    percentage = totsize * 100. / int(fileObject['size'])
                    self.report['bytes-downloaded'] += size
                    progress = "(%d%% of %s, %s/s, %d%% of %s)" % (percentage, bytesize(int(fileObject['size'])), bytesize(int(downsize / (time.process_time() - start))), (self.report['bytes-downloaded'] * 100. / int(self.report['total-download-size'])), bytesize(self.report['total-download-size'])) if filesize else ""

                    if totsize == filesize or (self.options['test'] and percentage > 1):
                        sys.stdout.write("\rFile %s of %s downloaded %s" % (fileObject['name'], fileObject['parent'], progress))
                        break
                    else:
                        sys.stdout.write("\rDownloading file %s of %s %s" % (fileObject['name'], fileObject['parent'], progress))
                    sys.stdout.flush()

                sys.stdout.write('\n')
        except Exception as e:
            error(e, 3)

        return True

    # check the checksum of a downloaded file
    def _checksumFile(self, fileObject):
        text = "Comparing local checksum of file %s of object %s" % (fileObject['name'], fileObject['parent'])
        sys.stdout.write(text)

        # calculate the local checksum
        try:
            output = subprocess.check_output("md5sum %s | awk '{print $1}'" % (fileObject['target']), shell=True).strip()
        except subprocess.CalledProcessError as e:
            error(e, 102)

        # locate checksum
        if 'md5' in fileObject:
            checksum = fileObject['md5']
        elif 'checksum' in fileObject:
            checksum = fileObject['checksum']
        else:
            sys.stdout.write("\nwarning: no checksum found in object for file '%s'\n" % fileObject['name'])
            return False

        # compare with retrieved checksum
        if output == checksum:
            sys.stdout.write("\r" + text + " PASS")
        else:
            sys.stdout.write("\n FAIL (%s (local) vs %s (remote))" % (output, checksum))

        # store checksum if requested
        if self.options['store-checksum']:
            with open("%s.md5" % fileObject['target'], 'w') as f:
                f.write(output)
                f.close()

        sys.stdout.write('\n')

        return output == fileObject['md5']

def signalHandler(signal, frame):
    error('execution interrupted', 1)

def bools(b):
    return "yes" if b else "no"

def allorn(d):
    return "all" if not d else str(d)

def usage():
    print("usage: %s [options] token" % sys.argv[0])

def help(options):
    """ Show usage information """
    print("%s v%s: massively download collections, deposits and individual files from the %s\n" % (TITLE, VERSION, SERVICE))
    usage()
    print("\nwhere token is your personal API access token. If you do not have an API token yet, create one on the %s website." % SERVICE)
    print("\nOptions:")
    print("--target          -t  set the target instance of %s (default: '%s')" % (SERVICE, Config.BASE_URL))
    print("--favourites          download favourites instead of basket (default: %s)" % bools(options['favourites']))
    print("--output          -o  set target download directory (default: '%s')" % options['outputdir'])
    print("--buffer-size     -b  set download buffer size (bytes, default: %d)" % Config.BUFFER_SIZE)
    print("--force-overwrite     force overwrite of existing files (default: %s)" % bools(options['force-overwrite']))
    print("--skip-staging        skip staging of objects (default: %s)" % bools(options['skip-staging']))
    print("--skip-download       skip downloading of files (default: %s)" % bools(options['skip-download']))
    print("--skip-checksum       skip checksum check after download (default: %s)" %  bools(options['skip-checksum']))
    print("--no-resume           do not resume partially downloaded files, redownload instead (default: %s)" % bools(options['no-resume']))
    print("--store-checksum      store generated checksum after download (default: %s)" % bools(options['store-checksum']))
    print("--max-childs      -m  maximum number of childs to process per collection (default: %d" % allorn(options['max-childs']))
    print("--max-files           maximum number of files to download per deposit (default: %d" % allorn(options['max-files']))
    print("--no-verify       -k  do not verify server certificate (default: %s)" % bools(options['no-verify']))
    print("--debug           -d  set debuglevel to max (default: %s)" % bools(Config.DEBUG))
    print("--test                test mode, limits data downloads (default: %s)" % bools(options['test']))
    print("--dry-run         -n  dry-run mode, simulate staging, downloads and further processing (default: %s)" % bools(Config.DRYRUN))
    print("--version             prints '%s %s'" % (TITLE, VERSION))
    print("--help            -h  help mode")
    print("                  -v  verbose mode")

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
        'stage-interval': 10,
        'stage-max-count': 10,
        'outputdir': "download",
        'max-childs': 0,
        'max-files': 0,
        'target': Config.BASE_URL,
        'test': False,
        'no-verify': False
    }

    # handle arguments
    try:
        opts, args = getopt.gnu_getopt(argv, "hdb:vo:t:nkm:",  \
            ["help", "version", "debug", "verbose", "output=", "target=", "no-verify", "favourites", "skip-checksum", "store-checksum",
             "buffer-size=", "dry-run", "no-resume", "force-overwrite", "skip-download", "skip-staging", "test",
             "max-childs=", "max-files="])
    except getopt.GetoptError as err:
        error(err, 1)

    if not args and not ('-h' in opts or '--help' in opts):
        error("missing token")
        usage()
        sys.exit(1)

    # parse other
    for opt, arg in opts:
        if opt in ["-h", "--help"]:
            usage()
            sys.exit()
        elif opt == "--version":
            print("%s %s" % (TITLE, VERSION))
            sys.exit(1)
        elif opt in ["--no-verify", "--skip-checksum", "--store-checksum", "--skip-download", "--skip-staging", "--no-resume", "--force-overwrite", "--favourites", "--test"]:
            options.update({opt[2:]: True})
        elif opt in ["-m", "--max-childs"]:
            options.update({'max-childs': int(arg)})
        elif opt in ["--max-files"]:
            options.update({'max-files': int(arg)})
        elif opt in ["-k"]:
            options.update({'no-verify': True})
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

    # allow graceful exit on interrupt
    signal.signal(signal.SIGINT, signalHandler)

    # start procedures
    dm = DownloadManager(args[0], options)
    dm.downloadObjectList()
    dm.processObjectList()
    dm.preReport()
    dm.startProcesses()
    dm.postReport()

if __name__ == "__main__":
    main(sys.argv[1:])
