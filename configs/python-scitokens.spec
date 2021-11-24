# Created by pyp2rpm-3.2.3
%global pypi_name scitokens

Name:           python-%{pypi_name}
Version:        1.6.2
Release:        1%{?dist}
Summary:        SciToken reference implementation library

License:        Apache 2.0
URL:            https://scitokens.org
Source0:        https://files.pythonhosted.org/packages/source/s/%{pypi_name}/%{pypi_name}-%{version}.tar.gz
BuildArch:      noarch

# build requirements
BuildRequires:  python3-devel
BuildRequires:  python%{python3_pkgversion}-setuptools

# test requirements
BuildRequires:  python%{python3_pkgversion}-cryptography
BuildRequires:  python%{python3_pkgversion}-pytest
BuildRequires:  python%{python3_pkgversion}-jwt >= 1.6.1

%description
SciToken reference implementation library

%package -n     python%{python3_pkgversion}-%{pypi_name}
Requires:       python%{python3_pkgversion}-jwt >= 1.6.1
Requires:       python%{python3_pkgversion}-cryptography
Obsoletes:      python3-scitokens < 1.6.2-2
Summary:        %{summary}
%{?python_provide:%python_provide python%{python3_pkgversion}-%{pypi_name}}

%description -n python%{python3_pkgversion}-%{pypi_name}
SciToken reference implementation library

%prep
%autosetup -n %{pypi_name}-%{version}
# Remove bundled egg-info
rm -rf %{pypi_name}.egg-info

%build
%py3_build

%install
# Must do the subpackages' install first because the scripts in /usr/bin are
# overwritten with every setup.py install.
%py3_install

%check
export PYTHONPATH="%{buildroot}%{python3_sitelib}"
(cd tests/ && %{__python3} -m pytest --verbose -ra .)

%files -n python%{python3_pkgversion}-%{pypi_name}
%license LICENSE
%{python3_sitelib}/%{pypi_name}
%{python3_sitelib}/%{pypi_name}-%{version}-py*.egg-info
%doc README.rst
%{_bindir}/scitokens-admin-create-key
%{_bindir}/scitokens-admin-create-token


%changelog
* Wed Nov 3 2021 Brian Lin <blin@cs.wisc.edu> - 1.6.2-1
- Fix Python library version (SOFTWARE-4879)

* Wed Nov 3 2021 Brian Lin <blin@cs.wisc.edu> - 1.6.1-1
- Reduce PyJWT version requirement made possible by #121 (SOFTWARE-4879)

* Mon Oct 11 2021 Derek Weitzel <dweitzel@cse.unl.edu> - 1.6.0-1
- Ensure compatibility with older versions of PyJWT
- Adding multiple aud in token support

* Mon Oct 11 2021 Derek Weitzel <dweitzel@cse.unl.edu> - 1.5.0-1
- Include tests in distribution
- Bump pyjwt version
- Add test run with minimum dependencies
- Run continuous integration on macOS and windows
- Check verified claims for issuer in SciToken.serialize
- Add base SciTokensException class
- Remove verify=False keyword from calls to decode()
- Print package list in CI jobs
- Use python3_pkgversion macro in RPM package names
- Move package version declaration into 'scitokens' module
- Fix deprecation warning from cryptography.utils.int_from_bytes

* Mon Apr 19 2021 Derek Weitzel <dweitzel@cse.unl.edu> - 1.4.0-1
- Add WLCG Token Discovery static function

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
