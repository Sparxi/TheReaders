<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <html>
            <body>
                <h2>
                    <xsl:value-of   select="/author/name"/>
                </h2>

                <table border="1">
                    <tr bgcolor="#9acd32">
                        <th>Genre</th>
                        <th>Title</th>
                        <th>PageCount</th>
                        <th>Damaged</th>
                    </tr>
                    <xsl:for-each select="author/book">
                        <tr>
                            <td><xsl:value-of select="@genre"/></td>
                            <td><xsl:value-of select="title"/></td>
                            <td><xsl:value-of select="pageCount"/></td>
                            <td><xsl:value-of select="damaged"/></td>
                        </tr>
                    </xsl:for-each>
                </table>
            </body>
        </html>
    </xsl:template>
</xsl:stylesheet>