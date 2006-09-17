<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:output method="html" indent="yes"/>

  <xsl:template match="@*|node()">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
    </xsl:copy>
  </xsl:template>

  <xsl:template match="processing-instruction('xml-stylesheet')"/>

  <xsl:template match="page">
    <html>
      <head>
	<title>
	  <xsl:value-of select="@title"/>
	</title>
	<link rel="stylesheet" type="text/css">
	  <xsl:attribute name="href">
	    <xsl:value-of select="@style"/>
	  </xsl:attribute>
	</link>
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
      </head>
      <body>
	<p/>
	<h1>
	  <xsl:value-of select="@title"/>
	</h1>
	<xsl:apply-templates/>
      </body>
    </html>
  </xsl:template>

  <xsl:template mode="sidebar" match="section">
    <li>
      <a>
	<xsl:attribute name="href">
	  <xsl:text>#</xsl:text>
	  <xsl:value-of select="@name"/>
	</xsl:attribute>
	<b><xsl:value-of select="@title"/></b>
      </a>
    </li>
  </xsl:template>

  <xsl:template match="intro">
    <xsl:apply-templates/>
  </xsl:template>

  <xsl:template match="anchor">
    <a>
      <xsl:attribute name="name">
	<xsl:value-of select="@name"/>
      </xsl:attribute>
    </a>
  </xsl:template>

  <xsl:template match="section">
    <h3>
      <xsl:value-of select="@title"/>
    </h3>
    <xsl:apply-templates/>
  </xsl:template>

  <xsl:template match="p">
    <p>
      <xsl:if test="@name">
	<a>
	  <xsl:attribute name="name">
	    <xsl:value-of select="@name"/>
	  </xsl:attribute>
	</a>
      </xsl:if>
      <xsl:if test="@title">
	<b>
	  <xsl:value-of select="@title"/>.&#160;
	</b>
      </xsl:if>
      <xsl:apply-templates/>
    </p>
  </xsl:template>
</xsl:stylesheet>
