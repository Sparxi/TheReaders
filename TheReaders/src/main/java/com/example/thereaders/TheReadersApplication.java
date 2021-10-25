package com.example.thereaders;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.servlet.http.HttpServletRequest;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

@SpringBootApplication
@RestController
public class TheReadersApplication {

    public static void main(String[] args) {
        SpringApplication.run(TheReadersApplication.class, args);
    }

    @CrossOrigin
    @PostMapping("/validate")
    public ResponseEntity<String> validateXML(HttpServletRequest request) {
        String XMLString = this.readXML(request);
        String validationResult = this.validate(XMLString);

        if (validationResult == null){
            return new ResponseEntity<>(HttpStatus.OK);
        }
        else{
            return new ResponseEntity<>(validationResult, HttpStatus.FORBIDDEN);
        }
    }

    @CrossOrigin
    @PostMapping("/save")
    public ResponseEntity<String> saveXML(HttpServletRequest request) {
        String XMLString = this.readXML(request);
        String validationResult = this.validate(XMLString);

        if (validationResult != null){
            return new ResponseEntity<>(validationResult,HttpStatus.BAD_REQUEST);
        }
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            InputSource is = new InputSource(new StringReader(XMLString));
            Document doc = db.parse(is);

            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");

            StreamResult result = new StreamResult(new StringWriter());
            DOMSource source = new DOMSource(doc);
            transformer.transform(source, result);
            String formatedXML = result.getWriter().toString();
            FileWriter fw = new FileWriter("./files/readers.xml");
            fw.write(formatedXML);
            fw.close();

        } catch (ParserConfigurationException | IOException | TransformerException | SAXException e) {
            e.printStackTrace();
        }
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @CrossOrigin
    @PostMapping("/visualize")
    public ResponseEntity<String> visualizeXML(HttpServletRequest request){
        String XMLString = this.readXML(request);
        String validationResult = this.validate(XMLString);

        if (validationResult != null){
            return new ResponseEntity<>(validationResult,HttpStatus.BAD_REQUEST);
        }

        try {
            TransformerFactory tf = TransformerFactory.newInstance();

            Source xslDoc = new StreamSource("./files/styleSheet.xsl");
            Source xmlDoc = new StreamSource(new StringReader(XMLString));

            //Transform XML to HTML using XSL
            OutputStream htmlFile = new FileOutputStream("./files/readers.html");
            Transformer trasformer = tf.newTransformer(xslDoc);
            trasformer.transform(xmlDoc, new StreamResult(htmlFile));

            //Return HTML response
            InputStream inputStream = new FileInputStream("./files/readers.html");
            InputStreamResource inputStreamResource = new InputStreamResource(inputStream);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentLength(Files.size(Paths.get("./files/readers.html")));
            return new ResponseEntity(inputStreamResource, headers, HttpStatus.OK);
        }
        catch (TransformerException | IOException e) {
            e.printStackTrace();
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }
    @CrossOrigin
    @PostMapping("/sign")
    public ResponseEntity<String> signXML(){
      Signer signer = new Signer();
      signer.sign();
      return new ResponseEntity<>(HttpStatus.OK);
    }

    private String readXML(HttpServletRequest request) {
        try {
            String str, wholeXML = "";
            BufferedReader br = request.getReader();
            while ((str = br.readLine()) != null) {
                wholeXML += str;
            }
            return wholeXML;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
    private String validate(String XML){
        try {
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = factory.newSchema(new File("./files/schema.xsd"));
            Validator validator = schema.newValidator();
            Source source = new StreamSource(new StringReader(XML));

            validator.validate(source);
        } catch (IOException | SAXException e) {
            return e.getMessage();
        }
        return null;
    }
}
