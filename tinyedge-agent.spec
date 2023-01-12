%define name tinyedge-agent
%define version 0.1.1

Name:    %{name}    
Version: %{version}
Release:        1%{?dist}
Summary: System workloads agent for tinyedge.io

License: GPL        
URL:  github.com/tupyy/tinyedge-agent
Source0: %{name}-%{version}.tar.gz 

Requires: podman

%description
Agent for tinyedge-operator

%prep

%built
%gobuild -o %{gobuilddir}/tinyedge-agent main.go

%install
install -m 0755 -vd                     %{buildroot}%{_bindir}
install -m 0755 -vp %{gobuilddir}/bin/* %{buildroot}%{_bindir}/

%files
%defattr(755,root,root)
%{_bindir}/%{name}
%dir
%{_sysconfdir}/tinyedge-agent/config.yaml

%post
systemctl enable --now podman.socket

%changelog
* Thu Jan 12 2023 Cosmin Tupangiu <cosmin@redhat.com> 0.1.1-1
- new package built with tito

* Thu Jan 12 2023 Cosmin Tupangiu <cosmin@redhat.com>
- wait for vault to create certificate (cosmin@redhat.com)

* Thu Jan 12 2023 Cosmin Tupangiu <cosmin@redhat.com>
- wait for vault to create certificate (cosmin@redhat.com)

* Thu Jan 12 2023 Cosmin Tupangiu <cosmin@redhat.com> 0.1.0-1
- new package built with tito

* Wed Sep 28 2022 Cosmin Tupangiu <cosmin@redhat.com>
* Wed Oct 13 2022 Fix data races
* Wed Dec 12 2022 Add grpc client
- 
