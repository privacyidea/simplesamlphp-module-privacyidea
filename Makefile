info:
	@echo "make clean        - remove all automatically created files"
	@echo "make debianzie    - prepare the debian build environment in DEBUILD"
	@echo "make builddeb     - build .deb file locally on ubuntu 14.04LTS!"
	@echo "make ppa-dev      - upload to launchpad development repo"
	@echo "make ppa          - upload to launchpad stable repo"
	
#VERSION=1.3~dev5
SHORT_VERSION=3.0~dev1
#SHORT_VERSION=2.10~dev7
VERSION_JESSIE=${SHORT_VERSION}
VERSION=${SHORT_VERSION}
LOCAL_SERIES=`lsb_release -a | grep Codename | cut -f2`
SRCDIRS=deploy dictionaries docs lib templates themes www src
SRCFILES=Changelog  composer.json  default-enable  LICENSE  Makefile  privacyidea.json  README.md 

SIGNING_KEY=53E66E1D2CABEFCDB1D3B83E106164552E8D8149

clean:
	rm -fr DEBUILD

PACKNAME=privacyidea-simplesamlphp
BUILDDIR=DEBUILD/${PACKNAME}.org

debianize:
	make clean
	mkdir -p ${BUILDDIR}/debian
	cp -r ${SRCDIRS} ${SRCFILES} ${BUILDDIR} || true
	cp LICENSE ${BUILDDIR}/debian/copyright
	(cd DEBUILD; tar -zcf ${PACKNAME}_${SHORT_VERSION}.orig.tar.gz --exclude=${PACKNAME}.org/debian ${PACKNAME}.org)
	(cd DEBUILD; tar -zcf ${PACKNAME}_${VERSION}.orig.tar.gz --exclude=${PACKNAME}.org/debian ${PACKNAME}.org)
	(cd DEBUILD; tar -zcf ${PACKNAME}_${VERSION_JESSIE}.orig.tar.gz --exclude=${PACKNAME}.org/debian ${PACKNAME}.org)

builddeb-nosign:
	make debianize
	cp -r deploy/debian-ubuntu/* ${BUILDDIR}/debian/
	sed -e s/"trusty) trusty; urgency"/"$(LOCAL_SERIES)) $(LOCAL_SERIES); urgency"/g deploy/debian-ubuntu/changelog > ${BUILDDIR}/debian/changelog
	(cd ${BUILDDIR}; debuild -b -i -us -uc)

builddeb:
	make debianize
	################## Renew the changelog
	cp -r deploy/debian-ubuntu/* ${BUILDDIR}/debian/
	sed -e s/"trusty) trusty; urgency"/"$(LOCAL_SERIES)) $(LOCAL_SERIES); urgency"/g deploy/debian-ubuntu/changelog > ${BUILDDIR}/debian/changelog
	################# Build
	(cd ${BUILDDIR}; debuild --no-lintian)

lintian:
	(cd DEBUILD; lintian -i -I --show-overrides ${PACKNAME}_*_amd64.changes)

ppa-dev:
	make debianize
	# trusty
	cp -r deploy/debian-ubuntu/* ${BUILDDIR}/debian/
	(cd ${BUILDDIR}; debuild -sa -S)
	# xenial
	sed -e s/"trusty) trusty; urgency"/"xenial) xenial; urgency"/g deploy/debian-ubuntu/changelog > ${BUILDDIR}/debian/changelog
	(cd ${BUILDDIR}; debuild -sa -S)
	# bionic
	sed -e s/"trusty) trusty; urgency"/"bionic) bionic; urgency"/g deploy/debian-ubuntu/changelog > ${BUILDDIR}/debian/changelog
	(cd ${BUILDDIR}; debuild -sa -S)
	dput ppa:privacyidea/privacyidea-dev DEBUILD/${PACKNAME}_${VERSION}*_source.changes

ppa:
	make debianize
	# trusty
	cp deploy/debian-ubuntu/changelog ${BUILDDIR}/debian/
	cp -r deploy/debian-ubuntu/* ${BUILDDIR}/debian/
	(cd ${BUILDDIR}; debuild -sa -S)
	# xenial
	sed -e s/"trusty) trusty; urgency"/"xenial) xenial; urgency"/g deploy/debian-ubuntu/changelog > ${BUILDDIR}/debian/changelog
	(cd ${BUILDDIR}; debuild -sa -S)
	dput ppa:privacyidea/privacyidea DEBUILD/${PACKNAME}_${VERSION}*_source.changes
