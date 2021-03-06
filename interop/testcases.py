import abc, filecmp, os, string, tempfile, random, logging, sys
from Crypto.Cipher import AES

KB = 1<<10
MB = 1<<20

def random_string(length: int):
  """Generate a random string of fixed length """
  letters = string.ascii_lowercase
  return ''.join(random.choice(letters) for i in range(length))

class TestCase(abc.ABC):
  _name = ""
  _abbreviation = ""
  _files = []
  _www_dir = None
  _download_dir = None

  def __str__(self):
    return self._name

  def abbreviation(self):
    return self._abbreviation

  def www_dir(self):
    if not self._www_dir:
      self._www_dir = tempfile.TemporaryDirectory(dir = "/tmp", prefix = "www_")
    return self._www_dir.name + "/"
  
  def download_dir(self):
    if not self._download_dir:
      self._download_dir = tempfile.TemporaryDirectory(dir = "/tmp", prefix = "download_")
    return self._download_dir.name + "/"

  # see https://www.stefanocappellini.it/generate-pseudorandom-bytes-with-python/ for benchmarks
  def _generate_random_file(self, size: int):
    filename = random_string(10)
    enc = AES.new(os.urandom(32), AES.MODE_OFB, b'a' * 16)
    f = open(self.www_dir() + filename, "wb")
    f.write(enc.encrypt(b' ' * size))
    f.close()
    logging.debug("Generated random file: %s of size: %d", filename, size)
    return filename

  def _check_files(self):
    if len(self._files) == 0:
      raise Exception("No test files generated.")
    num_files = len([ n for n in os.listdir(self.download_dir()) if os.path.isfile(os.path.join(self.download_dir(), n)) ])
    if num_files != len(self._files):
      logging.info("Downloaded the wrong number of files. Got %d, expected %d.", num_files, len(self._files))
      return False
    for f in self._files:
      fp = self.download_dir() + f
      if not os.path.isfile(fp):
        logging.info("File %s does not exist.", fp)
        return False
      if not filecmp.cmp(self.www_dir() + f, fp, shallow=False):
        logging.info("File contents of %s do not match.", fp)
        return False
    logging.debug("Check of downloaded files succeeded.")
    return True

  def cleanup(self):
    if self._www_dir:
      self._www_dir.cleanup()
      self._www_dir = None
    if self._download_dir:
      self._download_dir.cleanup()
      self._download_dir = None

  @abc.abstractmethod
  def get_paths(self):
    pass

  @abc.abstractmethod
  def check(self):
    pass

class TestCaseHandshake(TestCase):
  def __init__(self):
    self._name = "handshake"
    self._abbreviation = "H"

  def get_paths(self):
    self._files = [ self._generate_random_file(1*KB) ]
    return self._files

  def check(self):
    return self._check_files()

class TestCaseTransfer(TestCase):
  def __init__(self):
    self._name = "transfer"
    self._abbreviation = "DC"

  def get_paths(self):
    self._files = [ 
      self._generate_random_file(2*MB),
      self._generate_random_file(3*MB),
      self._generate_random_file(5*MB),
    ]
    return self._files

  def check(self):
    return self._check_files()

class TestCaseRetry(TestCase):
  def __init__(self):
    self._name = "retry"
    self._abbreviation = "S"

  def get_paths(self):
    self._files = [ self._generate_random_file(10*KB), ]
    return self._files

  def check(self):
    return self._check_files()

class TestCaseResumption(TestCase):
  def __init__(self):
    self._name = "resumption"
    self._abbreviation = "R"

  def get_paths(self):
    self._files = [ 
      self._generate_random_file(5*KB),
      self._generate_random_file(10*KB),
    ]
    return self._files

  def check(self):
    return self._check_files()


TESTCASES = [ 
  TestCaseHandshake(),
  TestCaseTransfer(),
  TestCaseRetry(),
  TestCaseResumption(),
]
