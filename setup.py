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

readme = open('README.rst', 'r', encoding='utf-8').read()

setup(name='nimbus',
      version=version,
      description='Infrastructure tools for Amazon Web Services',
      long_description=readme,
      url='https://github.com/uscis/nimbus',
      author='Andy Brody',
      author_email='git@abrody.com',
      license='Public Domain',

      packages=['nimbus'],

      entry_points={
          'console_scripts': [
              'nimbus=nimbus.cli:cli',
          ],
      },

      install_requires=[
          'atomicwrites >= 1.1.5, < 2.0',
          'beautifulsoup4 >= 4.5.1, < 5.0',
          'boto3 >= 1.4.0, < 2.0',
          'click >= 6.6, < 7.0',
          'pyyaml >= 3.11, < 4.0',
          'requests >= 2.11.1, < 3.0',
          'requests-kerberos >= 0.10.0, < 1.0',
      ],

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
