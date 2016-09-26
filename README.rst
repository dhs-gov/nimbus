Nimbus: tools for interacting with Amazon Web Services
======================================================

.. image:: https://img.shields.io/pypi/v/nimbus.svg
    :target: https://pypi.python.org/pypi/nimbus

Local development / usage
-------------------------

Prerequisites: Python 2, virtualenv (``pip install virtualenv``)

1. Clone this repository, ``cd nimbus``
2. Make a virtualenv: ``virtualenv venv`` (or use virtualenvwrapper)
3. Activate the virtualenv: ``. venv/bin/activate``
4. Install nimbus editable: ``pip install -e .``
5. Try out nimbus: ``nimbus --help``

Releasing new package versions
------------------------------

TODO

- http://peterdowns.com/posts/first-time-with-pypi.html
- https://packaging.python.org/distributing/#upload-your-distributions

Publish to testpypi
~~~~~~~~~~~~~~~~~~~

Python runs a test mode version of the Python Package Index where you can test
out publishing updates. This is useful to double check that everything works
before publishing to the produciton PyPI, where you can never reuse version
numbers.

Register the package:

.. code-block:: bash

    python setup.py register -r https://testpypi.python.org/pypi

Build and upload (``sdist``, then ``upload``) in one go:

.. code-block:: bash

    python setup.py sdist upload -r https://testpypi.python.org/pypi


Publish to PyPI
~~~~~~~~~~~~~~~

Tag the version, here using 0.0.1:

.. code-block:: bash

    git tag v0.0.1
    git push --tags

Register the package, if you haven't already:

.. code-block:: bash

    python setup.py register

Build and upload:

.. code-block:: bash

    python setup.py sdist upload


License
-------

`The project is in the public domain`_, and all contributions will also be
released in the public domain. By submitting a pull request, you are agreeing
to waive all rights to your contribution under the terms of the `CC0 Public
Domain Dedication`_.

This project constitutes an original work of the United States Government.

.. _`The project is in the public domain`: ./LICENSE.md
.. _`CC0 Public Domain Dedication`: http://creativecommons.org/publicdomain/zero/1.0/
