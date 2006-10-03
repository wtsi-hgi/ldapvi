index.html: ldapvi.xsl ldapvi.xml
	xsltproc $^ >$@

.PHONY: push
push: index.html
	rsync -av index.html bob.askja.de:html/ldapvi/
