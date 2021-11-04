Tagging a Release
=================

To tag a release:

1.  Update the version number in the [Python library](../src/scitokens/__init__.py)

1.  Update the version number in the [RPM packaging](python-scitokens.spec) and add a changelog entry

1.  [Draft a GitHub release](https://github.com/scitokens/scitokens/releases/new) with a new version tag
    (e.g., `v1.6.2`), a short release title, and a list of changes in the description

1.  Contact [OSG Software](osg-sw-notices@cs.wisc.edu) to request a new RPM release in the OSG Yum repositories
