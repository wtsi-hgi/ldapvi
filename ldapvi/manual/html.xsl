<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:output method="html" indent="yes"/>

  <xsl:template match="@*|node()">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
    </xsl:copy>
  </xsl:template>

  <xsl:template match="processing-instruction('xml-stylesheet')"/>

  <xsl:template match="manual">
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
	<div class="sidebar">
	  <div class="sidebar-title">
	    Contents
	  </div>
	  <div class="sidebar-main">
	    <ul>
	      <xsl:apply-templates mode="sidebar" select="chapter"/>
	    </ul>
	  </div>
	</div>
	<h1>
	  <xsl:value-of select="@title"/>
	</h1>
	<xsl:apply-templates/>
      </body>
    </html>
  </xsl:template>

  <xsl:template mode="sidebar" match="chapter">
    <li>
      <a>
	<xsl:attribute name="href">
	  <xsl:text>#</xsl:text>
	  <xsl:value-of select="@name"/>
	</xsl:attribute>
	<b><xsl:value-of select="@title"/></b>
      </a>
      <xsl:if test="section">
	<ul class="sub" style="margin: 0 0 0 0">
	  <xsl:apply-templates mode="sidebar" select="section"/>
	</ul>
      </xsl:if>
    </li>
  </xsl:template>

  <xsl:template mode="sidebar" match="section">
    <li>
      <a>
	<xsl:attribute name="href">
	  <xsl:text>#</xsl:text>
	  <xsl:value-of select="../@name"/>
	  <xsl:text>-</xsl:text>
	  <xsl:value-of select="@name"/>
	</xsl:attribute>
	<xsl:value-of select="@title"/>
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

  <xsl:template match="extra-parameter">
    <a>
      <xsl:attribute name="name">
	<xsl:text>parameter-</xsl:text>
	<xsl:value-of select="@long"/>
      </xsl:attribute>
    </a>
  </xsl:template>

  <xsl:template match="chapter">
    <h2>
      <xsl:value-of select="@title"/>
      <a>
	<xsl:attribute name="name">
	  <xsl:value-of select="@name"/>
	</xsl:attribute>
      </a>
    </h2>
    <xsl:apply-templates/>
    <br/><br/>
  </xsl:template>

  <xsl:template match="section">
    <h3>
      <xsl:value-of select="@title"/>
      <a>
	<xsl:attribute name="name">
	  <xsl:value-of select="../@name"/>
	  <xsl:text>-</xsl:text>
	  <xsl:value-of select="@name"/>
	</xsl:attribute>
      </a>
    </h3>
    <xsl:apply-templates/>
    <br/>
  </xsl:template>

  <xsl:template match="link">
    <a>
      <xsl:attribute name="href">
	<xsl:value-of select="."/>
      </xsl:attribute>
      <xsl:value-of select="."/>
    </a>
  </xsl:template>

  <xsl:template match="code">
    <pre style="background-color: #eeeeee; color: #000000"
	 class="code">
      <xsl:apply-templates/>
    </pre>
  </xsl:template>

  <xsl:template match="tty">
    <pre style="background-color: #000000;
		color: #ffffff;
		border: 0px;"
	 class="code">
      <xsl:apply-templates/>
    </pre>
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

  <xsl:template match="green">
    <span style="color: #00ff00">
      <xsl:apply-templates/>
    </span>
  </xsl:template>

  <xsl:template match="red">
    <span style="color: #ff0000">
      <xsl:apply-templates/>
    </span>
  </xsl:template>

  <xsl:template match="yellow">
    <span style="color: #ffff00">
      <xsl:apply-templates/>
    </span>
  </xsl:template>

  <xsl:template match="blue">
    <span style="color: #0000ff">
      <xsl:apply-templates/>
    </span>
  </xsl:template>

  <xsl:template match="parameter">
    <table cellspacing="0" width="90%">
      <tr style="">
	<td style="font-weight: bold; border-bottom: 1px solid #000000"
	    width="50">
	  <a>
	    <xsl:attribute name="name">
	      <xsl:text>parameter-</xsl:text>
	      <xsl:value-of select="@long"/>
	    </xsl:attribute>
	  </a>
	  <xsl:if test="@short">
	    <tt>-<xsl:value-of select="@short"/></tt>
	  </xsl:if>
	</td>
	<td style="border-bottom: 1px solid #000000"
	    width="30%">
	  <tt style="font-weight: bold">--<xsl:value-of select="@long"/></tt>
	  <xsl:text>&#160;&#160;</xsl:text>
	  <xsl:choose>
	    <xsl:when test="@args">
	      <i><xsl:value-of select="@args"/></i>
	    </xsl:when>
	    <xsl:when test="@values">
	      <xsl:value-of select="@values"/>
	    </xsl:when>
	  </xsl:choose>
	  <xsl:text>&#160;&#160;</xsl:text>
	</td>
	<td style="border-bottom: 1px solid #000000">
	  <xsl:value-of select="@brief"/>
	</td>
      </tr>
      <tr>
	<td/>
	<td colspan="2">
	  <xsl:apply-templates/>
	</td>
      </tr>
      <tr><td>&#160;</td></tr>
    </table>
  </xsl:template>

  <xsl:template match="list-options">
    <table>
      <xsl:apply-templates mode="options" select="..//parameter"/>
      <xsl:apply-templates mode="options" select="..//extra-parameter"/>
    </table>
  </xsl:template>

  <xsl:template mode="options" match="parameter|extra-parameter">
    <tr style="">
      <td width="20">&#160;</td>
      <td>
	<xsl:if test="@short">
	  <tt>-<xsl:value-of select="@short"/></tt>
	</xsl:if>
      </td>
      <td>&#160;</td>
      <td>
	<tt>--<xsl:value-of select="@long"/></tt>
      </td>
      <td>&#160;</td>
      <td>
	<a>
	  <xsl:attribute name="href">
	    <xsl:text>#parameter-</xsl:text>
	    <xsl:value-of select="@long"/>
	  </xsl:attribute>
	  <xsl:value-of select="@brief"/>
	</a>
      </td>
    </tr>
  </xsl:template>

  <xsl:template match="list-configuration-options">
    <xsl:apply-templates mode="configuration" select="//parameter"/>
    <xsl:apply-templates mode="configuration" select="//extra-parameter"/>
  </xsl:template>

  <xsl:template mode="configuration" match="parameter|extra-parameter">
    <xsl:if test="not(@suppress-configuration)">
      <xsl:text> &#160;&#x2799;&#160;</xsl:text>
      <a>
	<xsl:attribute name="href">
	  <xsl:text>#parameter-</xsl:text>
	  <xsl:value-of select="@long"/>
	</xsl:attribute>
	<xsl:value-of select="@long"/>
      </a>
    </xsl:if>
  </xsl:template>

  <xsl:template match="mode-table">
    <table cellspacing="0">
      <xsl:apply-templates/>
    </table>
  </xsl:template>

  <xsl:template match="mode">
    <tr>
      <td width="20">&#160;</td>
      <td style="border-bottom: 1px solid #707070">
	<tt><xsl:apply-templates/></tt>
      </td>
      <td style="border-bottom: 1px solid #707070;
		 border-right: 1px solid #707070">
	&#160;
      </td>
      <td style="border-bottom: 1px solid #707070">
	&#160;
      </td>
      <td style="border-bottom: 1px solid #707070" valign="top">
	<xsl:choose>
	  <xsl:when test="@label">
	    <xsl:value-of select="@label"/>
	  </xsl:when>
	  <xsl:otherwise>
	    Short for
	    <tt><xsl:value-of select="@short"/></tt>
	  </xsl:otherwise>
	</xsl:choose>
      </td>
    </tr>
  </xsl:template>
</xsl:stylesheet>
