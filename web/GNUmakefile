index.html: ldapvi.xsl ldapvi.xml
	xsltproc $^ >$@

.PHONY: push
push: index.html
	rsync -av index.html bob.askja.de:html/ldapvi/
	rsync -av ../ldapvi/NEWS bob.askja.de:html/ldapvi/ldapvi-news.txt
