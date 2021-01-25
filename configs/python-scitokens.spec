# Created by pyp2rpm-3.2.3
%global pypi_name scitokens

Name:           python-%{pypi_name}
Version:        1.3.1
Release:        1%{?dist}
Summary:        SciToken reference implementation library

License:        Apache 2.0
URL:            https://scitokens.org
Source0:        https://files.pythonhosted.org/packages/source/s/%{pypi_name}/%{pypi_name}-%{version}.tar.gz
BuildArch:      noarch
 
%if 0%{?rhel} >= 8
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
%else
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  python2-devel
BuildRequires:  python-setuptools
%endif


%description
SciToken reference implementation library

%if 0%{?rhel} >= 8
%package -n     python3-%{pypi_name}
Requires:       python3-jwt >= 1.6.1
Requires:       python3-cryptography
Summary:        %{summary}
%else
%package -n     python3-%{pypi_name}
Requires:       python36-jwt >= 1.6.1
Requires:       python36-cryptography
Summary:        %{summary}

%package -n     python2-%{pypi_name}
Requires:       python-jwt >= 1.6.1
Requires:       python2-cryptography
Summary:        %{summary}
%endif

%if 0%{?rhel} >= 8
%description -n python3-%{pypi_name}
SciToken reference implementation library
%else
%description -n python2-%{pypi_name}
SciToken reference implementation library

%description -n python3-%{pypi_name}
SciToken reference implementation library
%endif


%prep
%autosetup -n %{pypi_name}-%{version}
# Remove bundled egg-info
rm -rf %{pypi_name}.egg-info

%build
%if 0%{?rhel} >= 8
%py3_build
%else
%py3_build
%py2_build
%endif

%install
# Must do the subpackages' install first because the scripts in /usr/bin are
# overwritten with every setup.py install.
%if 0%{?rhel} >= 8
%py3_install
%else
%py3_install
mv %{buildroot}%{_bindir}/scitokens-admin-create-key %{buildroot}%{_bindir}/scitokens-admin-create-key3
mv %{buildroot}%{_bindir}/scitokens-admin-create-token %{buildroot}%{_bindir}/scitokens-admin-create-token3

%py2_install
mv %{buildroot}%{_bindir}/scitokens-admin-create-key %{buildroot}%{_bindir}/scitokens-admin-create-key2
mv %{buildroot}%{_bindir}/scitokens-admin-create-token %{buildroot}%{_bindir}/scitokens-admin-create-token2
touch %{buildroot}%{_bindir}/scitokens-admin-create-key 
touch %{buildroot}%{_bindir}/scitokens-admin-create-token 
%endif

%if 0%{?rhel} >= 8
%files -n python3-%{pypi_name}
%license LICENSE
%{python3_sitelib}/%{pypi_name}
%{python3_sitelib}/%{pypi_name}-%{version}-py?.?.egg-info
%doc README.rst
%{_bindir}/scitokens-admin-create-key
%{_bindir}/scitokens-admin-create-token
%else

%files -n python3-%{pypi_name}
%license LICENSE
%{python3_sitelib}/%{pypi_name}
%{python3_sitelib}/%{pypi_name}-%{version}-py?.?.egg-info
%doc README.rst
%ghost %{_bindir}/scitokens-admin-create-key
%ghost %{_bindir}/scitokens-admin-create-token
%{_bindir}/scitokens-admin-create-key3
%{_bindir}/scitokens-admin-create-token3

%files -n python2-%{pypi_name}
%license LICENSE
%{python2_sitelib}/%{pypi_name}
%{python2_sitelib}/%{pypi_name}-%{version}-py?.?.egg-info
%doc README.rst
%ghost %{_bindir}/scitokens-admin-create-key
%ghost %{_bindir}/scitokens-admin-create-token
%{_bindir}/scitokens-admin-create-key2
%{_bindir}/scitokens-admin-create-token2
%endif

%if 0%{?rhel} < 8
%post -n python3-%{pypi_name}
if [ ! -L %{_bindir}/scitokens-admin-create-key ]; then
  ln -sf scitokens-admin-create-key3 %{_bindir}/scitokens-admin-create-key
  ln -sf scitokens-admin-create-token3 %{_bindir}/scitokens-admin-create-token
fi

%post -n python2-%{pypi_name}
if [ ! -L %{_bindir}/scitokens-admin-create-key ]; then
  ln -sf scitokens-admin-create-key2 %{_bindir}/scitokens-admin-create-key
  ln -sf scitokens-admin-create-token2 %{_bindir}/scitokens-admin-create-token
fi
%endif


%changelog
* Mon Jan 25 2021 Derek Weitzel <dweitzel@cse.unl.edu> - 1.3.1-1
- Fix dependency change of behavior in PyJWT
- Add lifetime argument to scitokens-admin-create-token

* Wed Sep 30 2020 Diego Davila <didavila@ucsd.edu> - 1.2.4-3
- Force the creation of symlinks so it doesn't fail on update (software-4233)

* Mon Sep 28 2020 Diego Davila <didavila@ucsd.edu> - 1.2.4-2
- Avoid overwriting of scripts: scitokens-admin-create-* (software-4233) 

* Tue Sep 22 2020 Derek Weitzel <dweitzel@cse.unl.edu> - 1.2.4-1
- Same version in setup.py and spec

* Fri Sep 11 2020 Diego Davila <didavila@ucsd.edu> - 1.2.2-3
- Add conditions to build both py2 and py3 packages for el7 (software-4233)

* Mon Aug 10 2020 Diego Davila <didavila@ucsd.edu> - 1.2.2-2
- Add conditions to build for el8 (software-4126)

* Fri Feb 22 2019 Derek Weitzel <dweitzel@cse.unl.edu> - 1.2.2-1
- Add EC support to the admin tools

* Sun Oct 21 2018 Derek Weitzel <dweitzel@cse.unl.edu> - 1.2.1-1
- Support multiple audiences in verifier

* Tue Jul 10 2018 Derek Weitzel <dweitzel@cse.unl.edu> - 1.2.0-1
- Merge in the "scope" change accidently mentioned in 1.1.0

* Fri Jul 6 2018 Derek Weitzel <dweitzel@cse.unl.edu> - 1.1.0-1
- Add support for updated RFC for "scope"
- Add support for Elliptic Curve cryptography

* Tue Jan 30 2018 Derek Weitzel <dweitzel@cse.unl.edu> - 1.0.2-1
- Fix bug when configuration is not specified

* Tue Jan 30 2018 Derek Weitzel <dweitzel@cse.unl.edu> - 1.0.0-1
- Add optional configuration file
- Fix bug for missing kid
- Add automatic jti generation

* Mon Nov 06 2017 Derek Weitzel <dweitzel@cse.unl.edu> - 0.3.3-1
- Add subject testing in the Enforcer

* Mon Nov 06 2017 Derek Weitzel <dweitzel@cse.unl.edu> - 0.3.2-3
- Include dependency for python-setuptools

* Fri Nov 03 2017 Derek Weitzel <dweitzel@cse.unl.edu> - 0.3.2-2
- Update packaging to not include 2 scripts for the admin-create*
- Include the correct package for python-jwt dependency

* Thu Nov 02 2017 Derek Weitzel <dweitzel@cse.unl.edu> - 0.3.2-1
- Version bump to include spec in tag

* Wed Nov 01 2017 Derek Weitzel <dweitzel@cse.unl.edu> - 0.3.1-1
- Fix packaging to include internal util module

* Wed Nov 01 2017 Derek Weitzel <dweitzel@cse.unl.edu> - 0.3.0-1
- Initial package.
