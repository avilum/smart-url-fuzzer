import logging
import sys
import os
from logging.handlers import RotatingFileHandler
from multiprocessing.pool import ThreadPool
from optparse import OptionParser

import requests
from requests.packages import urllib3

urllib3.disable_warnings()

# Workers configurations
ASYNC_WORKERS_COUNT = 100  # How many threads will make http requests.
WORKERS_DECREMENTED_COUNT_ON_ERROR = 10  # Retry the fuzzing with x less workers, to decrease the load on the server.
STARTED_JOB_LOG_INTERVAL = 100  # Every x started jobs, a log will be written

# IO Configurations
DEFAULT_PATHS_LIST_FILE = 'words_lists/Filenames_or_Directories_Common.wordlist'
VALID_ENDPOINTS_FILE = 'endpoints.txt'

# HTTP Configuration
RESOURCE_EXISTS_STATUS_CODES = list(range(200, 300)) + [401, 402, 403]
DEFAULT_BASE_URL = 'https://www.example.com'

# Logging configurations
LOGS_DIRECTORY_FULL_NAME = 'logs'
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOGGING_LEVEL = logging.INFO
BACKUP_LOGS_FILES_COUNT = 5
FUZZING_LOGGER_NAME = 'fuzzing'
LOG_FILE_MAX_BYTES = 0.5 * 1000 * 1000  # 500 KB

class FilesFactory(object):
    """
    Manage files and directories
    """
    files = []
    urls = []

    def read_files_from_directory(self, user_path):
        self.files = [os.path.join(user_path, f) for f in os.listdir(user_path) if os.path.isfile(os.path.join(user_path, f))]

    def read_lines_from_files(self):
        for l in self.files:
            h = open(l, 'r')
            self.urls += h.read().splitlines()

    def __init__(self,user_path):
        if os.path.isdir(user_path):
            self.read_files_from_directory(user_path)
            self.read_lines_from_files()
        elif(os.path.isfile(user_path)):
            self.files.append(user_path)
            self.read_lines_from_files()


class LoggerFactory(object):
    """
    Manages loggers
    """

    loggers = {}
    logging_level = LOGGING_LEVEL
    logging.basicConfig(stream=sys.stdout, level=logging_level,
                        format=LOG_FORMAT)

    # Modifying the logger's level to ERROR to prevent console spam
    logging.getLogger('urllib3').setLevel(logging.WARNING)

    @staticmethod
    def get_logger(logger_name):
        """
        Gets a logger by it's name. Created the logger if it don't exist yet.
        :param logger_name: The name of the logger (identifier).
        :return: The logger instance.
        :returns: Logger
        """
        if logger_name not in LoggerFactory.loggers:
            LoggerFactory.loggers[logger_name] = LoggerFactory._get_logger(logger_name)
        return LoggerFactory.loggers[logger_name]

    @staticmethod
    def _get_logger(logger_name, logs_directory_path=LOGS_DIRECTORY_FULL_NAME):
        """
        Creates a logger with rolling file handler,
        Or returns the logger if it already exists.

        :param logger_name: The name of the logger
        :param logs_directory_path: The path of the directory that the logs will be written to.

        :return: An initialized logger instance.
        returns: Logger
        """
        # Creating the logs folder if its doesn't exist
        if not os.path.exists(logs_directory_path):
            os.mkdir(logs_directory_path)

        logger = logging.getLogger(logger_name)
        formatter = logging.Formatter(LOG_FORMAT)

        # Adding a rotating file handler
        rotating_file_handler = RotatingFileHandler(
            os.path.join(logs_directory_path, '{0}.log'.format(logger_name)), maxBytes=LOG_FILE_MAX_BYTES,
            backupCount=BACKUP_LOGS_FILES_COUNT)
        rotating_file_handler.setFormatter(formatter)
        rotating_file_handler.setLevel(LOGGING_LEVEL)
        logger.addHandler(rotating_file_handler)

        return logger


class AsyncURLFuzzer(object):
    """
    An asynchronous http(s) website endpoint locator.
    Discovers active endpoints in websites, based on a list of common URLS.
    """

    def __init__(self, base_url=DEFAULT_BASE_URL, list_file=DEFAULT_PATHS_LIST_FILE,
                 async_workers_count=ASYNC_WORKERS_COUNT,
                 output_file=VALID_ENDPOINTS_FILE, resource_exists_status_codes=RESOURCE_EXISTS_STATUS_CODES):
        """
        Initializes a new member of this class.
        :param base_url: The base url of the website.
        :type base_url: str
        :param list_file: The path of a file, containing the paths to check.
        :type list_file: str
        :param async_workers_count: How many workers (threads) to use.
        :type async_workers_count: int
        :param output_file: The name of the active endpoints output file.
        :type output_file: str
        :param resource_exists_status_codes: A list of HTTP status codes to consider as valid.
        :type resource_exists_status_codes: list
        """
        self._logger = LoggerFactory.get_logger(FUZZING_LOGGER_NAME)
        self._base_url = base_url
        self._list_file_path = list_file
        self._async_workers_count = async_workers_count
        self._output_file_path = output_file
        self._resource_exists_status_codes = resource_exists_status_codes
        self._active_paths_status_codes = {}
        self._checked_endpoints = {}
        self._endpoints_total_count = 0
        self._session = requests.session()

    def start(self):
        """
        Starts the fuzzing with the initialized parameters.
        """
        self._get_website_endpoints()

    def _get_website_endpoints(self, async_workers_count=ASYNC_WORKERS_COUNT):
        """
        Requests asynchronously for all the resources with a number of workers (threads).
        If it fails for HTTP overloads reasons, it retries with less workers, because it's probably a DDOS
        protection mechanism.
        :param async_workers_count: How many workers (threads) to use.
        :type async_workers_count: int
        """
        self._load_paths_list()
        self._logger.info(
            'Getting the endpoints of the website {0} with list file "{1}" and {2} async workers.'.format(
                self._base_url,
                self._list_file_path,
                async_workers_count))
        if 0 >= async_workers_count:
            self._logger.error('Seems like the site does not support fuzzing, as it has a DDOS protection engine.')
            return

        pool = ThreadPool(async_workers_count)
        try:
            tasks = []
            self._logger.debug('Preparing the workers...')
            for i, path in enumerate(self._paths):
                self._logger.debug('Started a worker for the endpoint {0}'.format(path))
                if i > i and i % STARTED_JOB_LOG_INTERVAL == 0:
                    self._logger.info('Started {0} workers'.format(i))

                path = path.strip()
                full_path = '/'.join([self._base_url, path])
                tasks.append(pool.apply_async(self.request_head, (full_path, path)))
            for t in tasks:
                status_code, full_path, path = t.get()
                self._checked_endpoints[path] = path
                if self._is_valid_status_code(status_code):
                    self._active_paths_status_codes[path] = status_code
                self._logger.info(
                    'Fetched {0}/{1}; {2}; {3}'.format(len(self._checked_endpoints), self._endpoints_total_count,
                                                       status_code,
                                                       full_path))
            self._save_output_log()
        except requests.ConnectionError as e:
            pool.terminate()
            self._logger.error(e)
            self._logger.warning('An error occured while fuzzing.'
                                 ' Retrying with less async workers to reduce the server load.')
            retry_workers_count = async_workers_count - WORKERS_DECREMENTED_COUNT_ON_ERROR
            self._get_website_endpoints(retry_workers_count)

    def _is_valid_status_code(self, status_code):
        """
        Checks whether a HTTP status code implies that the resouce exists.
        :param status_code:
        :return: True if the status code implies that the resouce exists, False otherwise.
        """
        return status_code in self._resource_exists_status_codes

    def _save_output_log(self):
        """
        Saves the results to an output file.
        """
        full_status_codes = {'/'.join([self._base_url, p]): code for p, code in self._active_paths_status_codes.items()}
        output_lines = ['{0} : {1}'.format(path, code) for path, code in full_status_codes.items()]
        if 1 >= len(output_lines):
            self._logger.warning(
                'There were no discovered endpoints. consider using a different file from "words_list" directory')
        self._logger.info('The following endpoints are active:{0}{1}'.format(os.linesep, os.linesep.join(output_lines)))
        with open(self._output_file_path, 'a+') as output_file:
            output_lines.sort()
            output_file.write(os.linesep.join(output_lines))
        self._logger.info('The endpoints were exported to "{0}"'.format(self._output_file_path))

    def _load_paths_list(self):
        """
        Loads the list of paths from the configured status.
        """
        if not os.path.exists(self._list_file_path):
            raise FileNotFoundError('The file "{0}" does not exist.'.format(self._list_file_path))
        with open(self._list_file_path) as paths_file:
            paths = [p.strip().lstrip('/').rstrip('/') for p in paths_file.readlines()]
            paths = [p for p in paths if p not in self._active_paths_status_codes]
            if not self._endpoints_total_count:
                self._endpoints_total_count = len(paths)
            self._paths = paths

    def request_head(self, url, path):
        """
        Executes a http HEAD request to a url.
        :param url: The full url to contact.
        :param path: The uri of the request.
        :return: A tuple of 3 variables:
            the recieved status code (int),
            the url argument (str),
            the path argument (str).
        """
        if url != '':
            res = self._session.head(url, verify=False, allow_redirects=True)
            return res.status_code, url, path


if __name__ == '__main__':
    # Parsing the parameters.
    parser = OptionParser(description=
                          'An Asynchronous, robust websites endpoint discovery tool with smart error handling. '
                          'Locates resources in websites based on a list of paths. '
                          'Check out the "words_list"" directory for lists examples.',
                          usage='%prog -u https://example.com/', version='%prog 0.1')
    parser.add_option('-u', '--url', dest='base_url', help='The target website to scan.', default=DEFAULT_BASE_URL)
    parser.add_option('-l', '--list', dest='list_file', help='A file containing the paths to check (separated with lines).',
                      default=DEFAULT_PATHS_LIST_FILE)
    (options, args) = parser.parse_args()
    list_file = options.list_file
    base_url = options.base_url
    if base_url is None:
        parser.print_help()
        sys.exit()

    # Suspending warning logs from requests and urllib3
    logging.getLogger("urllib3").setLevel(logging.ERROR)
    logging.getLogger("requests").setLevel(logging.ERROR)

    if (os.path.isdir(base_url) or os.path.isfile(base_url)):
        FilesFactory(base_url)
        for u in FilesFactory.urls:
            fuzzer = AsyncURLFuzzer(u, list_file)
            fuzzer.start()
    else:
        fuzzer = AsyncURLFuzzer(base_url, list_file)
        fuzzer.start()
