import re

from setuptools import setup

# override open to support encoding
from codecs import open

version = None
with open('nimbus/__init__.py', 'r', encoding='utf-8') as f:
    version = re.search(r'^VERSION\s*=\s*[\'"]([^\'"]*)[\'"]', f.read(),
                        re.MULTILINE).group(1)
    if not version:
        raise RuntimeError('Cannot find version information')

def fread(filename, split=False):
    """
    may raise IOError exceptions from file operations
    """
    if split:
        result = []
    else:
        result = ''

    with open(filename, 'rb', encoding='utf-8') as f:
        for line in f:
            if split:
                if line.lstrip().startswith('#'):
                    continue
                result.append(line.rstrip('\r\n'))
            else:
                result += line
    return result

LONG_DESC = fread('README.md')

setup(name='nimbus',
      version=version,
      description='Infrastructure tools for Amazon Web Services',
      url='http://github.com/uscis/nimbus',
      author='Andy Brody',
      author_email='git@abrody.com',
      license='Public Domain',

      packages=['nimbus'],

      entry_points={
          'console_scripts': [
              'nimbus=nimbus.cli:cli',
          ],
      },

      install_requires=fread('requirements.txt', split=True),

      # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
      classifiers=[
          # How mature is this project? Common values are
          #   3 - Alpha
          #   4 - Beta
          #   5 - Production/Stable
          'Development Status :: 3 - Alpha',

          # Indicate who your project is intended for
          'Intended Audience :: Developers',
          'Intended Audience :: System Administrators',

          # Pick your license as you wish (should match "license" above)
          'License :: Public Domain',

          # Specify the Python versions you support here. In particular, ensure
          # that you indicate whether you support Python 2, Python 3 or both.
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.6',
          'Programming Language :: Python :: 2.7',
      ],

      zip_safe=False)
