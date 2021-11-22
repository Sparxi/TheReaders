package com.example.thereaders;

import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.util.encoders.Base64;
import org.yaml.snakeyaml.external.biz.base64Coder.Base64Coder;
import sk.ditec.zep.dsigner.xades.XadesSig;
import sk.ditec.zep.dsigner.xades.plugin.DataObject;
import sk.ditec.zep.dsigner.xades.plugins.xmlplugin.XmlPlugin;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampToken;

import static com.example.thereaders.AbstractTest.readResource;

public class TimeStamp {

    public void createOutputXML(String inputXML, String xml_file, String timestamp){
        try {
            String stampedOutput = "";
            BufferedWriter outputXML = new BufferedWriter(new FileWriter(xml_file));
            int index = inputXML.lastIndexOf("</xades:SignedProperties>");

            stampedOutput = inputXML.substring(0, index + 25);
            stampedOutput += "<xades:UnsignedProperties>";
            stampedOutput += "<xades:UnsignedSignatureProperties>";
            stampedOutput += "<xades:SignatureTimeStamp Id=\"signatureIdSignatureTimeStamp\">";
            stampedOutput += "<xades:EncapsulatedTimeStamp>";
            stampedOutput += timestamp;
            stampedOutput += "</xades:EncapsulatedTimeStamp>";
            stampedOutput += "</xades:SignatureTimeStamp>";
            stampedOutput += "</xades:UnsignedSignatureProperties>";
            stampedOutput += "</xades:UnsignedProperties>";
            stampedOutput += inputXML.substring(index + 25);

            outputXML.write(stampedOutput);
            outputXML.close();

        } catch (IOException e1) {
            e1.printStackTrace();
        }
    }

    public void addTimeStampToXML(String xml_file) throws IOException {

        String inputXML = readResource(xml_file);
        String timestamp = "";
        String wrapper = inputXML;
        wrapper = wrapper.substring(wrapper.indexOf("<ds:SignatureValue Id=\"signatureId20SignatureValue\"") + 166);
        wrapper = wrapper.substring(0, wrapper.indexOf("</ds:SignatureValue>"));

        // get TimeStampResponse
        try {
            int charIterator;
            String responseString = "";
            URL url = new URL("http://test.ditec.sk/timestampws/TS.asmx");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setDoOutput(true);
            connection.setDoInput(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "text/xml; charset=utf-8");
            connection.setRequestProperty("SOAPAction", "http://www.ditec.sk/GetTimestamp");
            OutputStream output = connection.getOutputStream();
            Writer outputWriter = new OutputStreamWriter(output);

            outputWriter.write("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                    "<soap:Envelope " +
                    "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
                    "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" " +
                    "xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                    "  <soap:Body>\n" +
                    "    <GetTimestamp xmlns=\"http://www.ditec.sk/\">\n" +
                    "      <dataB64>" + Base64.toBase64String(wrapper.getBytes()) + "</dataB64>\n" +
                    "    </GetTimestamp>\n" +
                    "  </soap:Body>\n" +
                    "</soap:Envelope>");

            outputWriter.flush();
            outputWriter.close();

            // create response
            InputStream inStream = connection.getInputStream();

            while ((charIterator = inStream.read()) != -1)
                responseString = responseString + (char) charIterator;
            inStream.close();

            int i = responseString.indexOf("<GetTimestampResult>");
            responseString = responseString.substring(i + 20);
            i = responseString.indexOf("</GetTimestampResult>");
            responseString = responseString.substring(0, i);

            // decode response
            try {
                TimeStampResponse responseDecoded = new TimeStampResponse(Base64.decode(responseString));

                if ((responseDecoded.getStatus() == 0) || (responseDecoded.getStatus() == 1)) {
                    TimeStampToken tsToken = responseDecoded.getTimeStampToken();
                    timestamp = Base64Coder.encodeString(Base64Coder.encodeLines(tsToken.getEncoded()));
                    System.out.println("\n" + timestamp);
                }
                else {
                    System.err.println("Status failure");
                    System.exit(1);
                }

            } catch (TSPException e) {
                e.printStackTrace();
            }

        } catch (IOException e) {
            System.err.println(e);
        }

        //create output
        createOutputXML(inputXML, xml_file, timestamp);
    }
}
