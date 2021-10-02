<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <Readers>
            <Name>
                <xsl:value-of   select="/Readers/Name"/>
            </Name>
            <BooksPerWeek>
                <xsl:value-of   select="/Readers/BooksPerWeek"/>
            </BooksPerWeek>
            <FavouriteGenres>
                <xsl:for-each select="/Readers/FavouriteGenres/Genre">
                    <Genre>
                        <xsl:value-of   select="."/>
                    </Genre>
                </xsl:for-each>
            </FavouriteGenres>
        </Readers>
    </xsl:template>
</xsl:stylesheet>