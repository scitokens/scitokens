%global srcname scitokens

Name: python2-%{srcname}
Version: 0.1.5
Release: 1%{?dist}
Summary: SciToken reference implementation library

License: Apache 2.0
URL: https://pypi.python.org/pypi/%{srcname}
Source0: https://pypi.python.org/packages/1d/95/977c83da81b3d8b7259f53290f82a9368157889bd0b6b0037463b6fd2ea2/scitokens-0.1.5.tar.gz

BuildArch: noarch
Requires: python-jwt, python2-cryptography, python2-urltools

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}

%description
SciToken reference implementation library

%prep
%setup -q -n scitokens-%{version}

%build
python setup.py build

%install
python setup.py install -O1 --root %{buildroot}

%files -n python2-%{srcname}
%doc README.rst
%{python_sitelib}/%{srcname}*.egg-info/
%{python_sitelib}/%{srcname}/*.py*
