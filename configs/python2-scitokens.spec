%global srcname scitokens

Name: python2-%{srcname}
Version: 0.1.6
Release: 1%{?dist}
Summary: SciToken reference implementation library

License: Apache 2.0
URL: https://pypi.python.org/pypi/%{srcname}

# Generated from:
# git archive v%{version} --prefix=scitokens-%{version}/ | gzip -7 > ~/rpmbuild/SOURCES/scitokens-%{version}.tar.gz
Source0: %{srcname}-%{version}.tar.gz

BuildArch: noarch
Requires: python-jwt
Requires: python2-cryptography

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}

%description
SciToken reference implementation library

%prep
%setup -q -n %{srcname}-%{version}

%build
python setup.py build

%install
python setup.py install -O1 --root %{buildroot}

%files -n python2-%{srcname}
%doc README.rst
%{python_sitelib}/%{srcname}*.egg-info/
%{python_sitelib}/%{srcname}/*.py*
