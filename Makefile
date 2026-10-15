PREFIX ?= /usr
SYSCONFDIR ?= /etc
DESTDIR ?=
PYTHON ?= python3

PKGDATADIR = $(PREFIX)/share/localpasskey
UNITDIR = $(PREFIX)/lib/systemd/system
MODULESLOADDIR = $(PREFIX)/lib/modules-load.d
LIBEXECDIR = $(PREFIX)/lib/localpasskey
CHROME_NMHDIR = $(SYSCONFDIR)/opt/chrome/native-messaging-hosts
CHROMIUM_NMHDIR = $(SYSCONFDIR)/chromium/native-messaging-hosts
EXTDIR = $(PKGDATADIR)/chromium-extension
POLKITDIR = $(PREFIX)/share/polkit-1/actions
MANDIR = $(PREFIX)/share/man
APPDIR = $(PREFIX)/share/applications
ICONDIR = $(PREFIX)/share/icons/hicolor

SERVICE_MODULES = $(filter-out localpasskey/gui.py,$(wildcard localpasskey/*.py))

.PHONY: all check install install-service install-gui deb clean

all:

check:
	$(PYTHON) -m unittest discover -s tests -t .

install: install-service install-gui

install-service:
	install -d $(DESTDIR)$(PKGDATADIR)/localpasskey
	install -m 0644 $(SERVICE_MODULES) $(DESTDIR)$(PKGDATADIR)/localpasskey/
	install -D -m 0755 bin/localpasskeyd $(DESTDIR)$(PREFIX)/sbin/localpasskeyd
	install -D -m 0755 bin/localpasskey $(DESTDIR)$(PREFIX)/bin/localpasskey
	install -D -m 0755 bin/localpasskey-bridge $(DESTDIR)$(LIBEXECDIR)/localpasskey-bridge
	install -D -m 0644 data/org.localpasskey.bridge.json $(DESTDIR)$(CHROME_NMHDIR)/org.localpasskey.bridge.json
	install -D -m 0644 data/org.localpasskey.bridge.json $(DESTDIR)$(CHROMIUM_NMHDIR)/org.localpasskey.bridge.json
	install -d $(DESTDIR)$(EXTDIR)
	install -m 0644 browser/chromium/manifest.json browser/chromium/service_worker.js $(DESTDIR)$(EXTDIR)/
	install -D -m 0644 data/localpasskey.service $(DESTDIR)$(UNITDIR)/localpasskey.service
	install -D -m 0644 data/org.localpasskey.policy $(DESTDIR)$(POLKITDIR)/org.localpasskey.policy
	install -D -m 0644 data/modules-load.conf $(DESTDIR)$(MODULESLOADDIR)/localpasskey.conf
	install -D -m 0644 data/localpasskeyd.conf $(DESTDIR)$(SYSCONFDIR)/localpasskey/localpasskeyd.conf
	install -D -m 0644 man/localpasskeyd.8 $(DESTDIR)$(MANDIR)/man8/localpasskeyd.8
	install -D -m 0644 man/localpasskey.1 $(DESTDIR)$(MANDIR)/man1/localpasskey.1

install-gui:
	install -D -m 0644 localpasskey/gui.py $(DESTDIR)$(PKGDATADIR)/localpasskey/gui.py
	install -D -m 0755 bin/localpasskey-gui $(DESTDIR)$(PREFIX)/bin/localpasskey-gui
	install -D -m 0644 data/org.localpasskey.Manager.desktop $(DESTDIR)$(APPDIR)/org.localpasskey.Manager.desktop
	install -D -m 0644 data/icons/hicolor/scalable/apps/org.localpasskey.Manager.svg \
		$(DESTDIR)$(ICONDIR)/scalable/apps/org.localpasskey.Manager.svg
	install -D -m 0644 man/localpasskey-gui.1 $(DESTDIR)$(MANDIR)/man1/localpasskey-gui.1

deb:
	dpkg-buildpackage --build=binary --no-sign
	mkdir -p dist
	version=$$(dpkg-parsechangelog -S Version) && \
		mv ../localpasskey_$${version}_* ../localpasskey-gui_$${version}_* dist/

clean:
	find . -name __pycache__ -prune -exec rm -rf {} +
