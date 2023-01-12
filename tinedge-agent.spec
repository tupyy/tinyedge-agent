%define name tinyedge-agent
%define version 0.1.0

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
%setup -q

%install
install -D -m 0755 tinyedge-agent $RPM_BUILD_ROOT/usr/bin/tinyedge-agent
install -D -m 0755 config.yaml $RPM_BUILD_ROOT/etc/tinyedge-agent/config.yaml

%files
%defattr(755,root,root)
%{_bindir}/%{name}
%dir
%{_sysconfdir}/tinyedge-agent/config.yaml

%post
systemctl enable --now podman.socket

%changelog
* Thu Jan 12 2023 Cosmin Tupangiu <cosmin@redhat.com> 0.1.0-1
- new package built with tito

* Wed Sep 28 2022 Cosmin Tupangiu <cosmin@redhat.com>
* Oct 13 2022 Fix data races
* Jan 12 2023 Add grpc client
- 
