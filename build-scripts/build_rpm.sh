#!/bin/sh -xe

# First, install the necessary OSG build stuff

rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
yum -y install yum-plugin-priorities

rpm -Uvh https://repo.opensciencegrid.org/osg/3.4/osg-3.4-el7-release-latest.rpm

yum -y install osg-build python2-devel python-setuptools

mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

pushd /scitokens
chown root: configs/python-scitokens.spec

# Extract the version from the spec file
VERSION="$(grep "Version:" configs/python-scitokens.spec | awk '{print $2;}')"

# Archive the current python-scitokens directory
git archive --format tar HEAD --prefix=scitokens-$VERSION/ | gzip >~/rpmbuild/SOURCES/scitokens-$VERSION.tar.gz

# Build the RPM
rpmbuild -ba configs/python-scitokens.spec

popd
# Copy the built rpm to the current directory for things to pick it up
cp ~/rpmbuild/RPMS/noarch/* /scitokens/

#osg-build rpmbuild 


#osg-koji setup -u /path/to/cert -k /path/to/key --no-proxy --write-client-conf --dot-koji-symlink

