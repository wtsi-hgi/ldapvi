manual.html: html.xsl manual.xml
	xsltproc $^ >$@

.PHONY: push
push: manual.html
	rsync -av manual.xml bob.askja.de:html/ldapvi/manual/
	rsync -av manual.html bob.askja.de:html/ldapvi/manual/index.html
