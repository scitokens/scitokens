# Created by pyp2rpm-3.2.3
%global pypi_name scitokens

Name:           python-%{pypi_name}
Version:        0.3.1
Release:        1%{?dist}
Summary:        SciToken reference implementation library

License:        Apache 2.0
URL:            https://scitokens.org
Source0:        https://files.pythonhosted.org/packages/source/s/%{pypi_name}/%{pypi_name}-%{version}.tar.gz
BuildArch:      noarch
 
BuildRequires:  python2-devel
BuildRequires:  python2-setuptools

%description
SciToken reference implementation library

%package -n     python2-%{pypi_name}
Summary:        %{summary}
Provides:       python-%{pypi_name}
 
Requires:       python2-jwt
Requires:       python2-cryptography
%description -n python2-%{pypi_name}
SciToken reference implementation library

%prep
%autosetup -n %{pypi_name}-%{version}
# Remove bundled egg-info
rm -rf %{pypi_name}.egg-info

%build
%py2_build

%install
# Must do the subpackages' install first because the scripts in /usr/bin are
# overwritten with every setup.py install.
%py2_install
cp %{buildroot}/%{_bindir}/scitokens-admin-create-key %{buildroot}/%{_bindir}/scitokens-admin-create-key-%{python2_version}
ln -s %{_bindir}/scitokens-admin-create-key-%{python2_version} %{buildroot}/%{_bindir}/scitokens-admin-create-key-2
cp %{buildroot}/%{_bindir}/scitokens-admin-create-token %{buildroot}/%{_bindir}/scitokens-admin-create-token-%{python2_version}
ln -s %{_bindir}/scitokens-admin-create-token-%{python2_version} %{buildroot}/%{_bindir}/scitokens-admin-create-token-2

%files -n python2-%{pypi_name}
%doc README.rst
%{_bindir}/scitokens-admin-create-key
%{_bindir}/scitokens-admin-create-key-2
%{_bindir}/scitokens-admin-create-key-%{python2_version}
%{_bindir}/scitokens-admin-create-token
%{_bindir}/scitokens-admin-create-token-2
%{_bindir}/scitokens-admin-create-token-%{python2_version}
%{python2_sitelib}/%{pypi_name}
%{python2_sitelib}/%{pypi_name}-%{version}-py?.?.egg-info

%changelog
* Wed Nov 01 2017 Derek Weitzel <dweitzel@cse.unl.edu> - 0.3.1-1
- Fix packaging to include internal util module

* Wed Nov 01 2017 Derek Weitzel <dweitzel@cse.unl.edu> - 0.3.0-1
- Initial package.
