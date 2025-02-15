package org.lab1;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.util.Base64;

/**
 * Программа для обфускирование и деобфускирование XML-файла
 */
public class Lab1 {

    /**
     *  <mode> - обфускация или деобфускация
     *  <inputFilePath> - входной файл
     *  <outputFilePath> - выходной файл
     */
    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.out.println("Usage: java XMLObfuscator <mode> <inputFilePath> <outputFilePath>" +
                    "\nModes: true (obfuscate), false (deobfuscate)");
            return;
        }

        Boolean mode = Boolean.parseBoolean(args[0]);
        String inputFilePath = args[1];
        String outputFilePath = args[2];

        Document document = getDocumentFromXml(new File(inputFilePath));
        removeWhitespaceNodes(document.getDocumentElement());
        changeObfuscateDocument(document, mode);
        transformDocToFile(document, outputFilePath);
    }

    /**
     * Преобразование XML файла в документ
     *
     * @param file - файл
     * @return - лист нод
     */
    private static Document getDocumentFromXml(File file) throws Exception {
        DocumentBuilder dBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = dBuilder.parse(file);
        doc.getDocumentElement().normalize();
        return doc;
    }

    /**
     * Удаление пустых текстовых узлов
     *
     * @param element - элемент документа
     */
    private static void removeWhitespaceNodes(Element element) {
        NodeList children = element.getChildNodes();
        for (int i = children.getLength() - 1; i >= 0; i--) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.TEXT_NODE && child.getTextContent().trim().isEmpty()) {
                element.removeChild(child);
            } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                removeWhitespaceNodes((Element) child);
            }
        }
    }

    /**
     * Изменения состояния документа
     *
     * @param document - документ
     * @param obfuscate - обфускация или деобфускация
     */
    private static void changeObfuscateDocument(Document document, Boolean obfuscate) {
        NodeList nodeList = document.getElementsByTagName("*");
        for (int i = 0; i < nodeList.getLength(); i++) {
            Node childNode = nodeList.item(i);
            if (childNode.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element) childNode;
                if (element.getFirstChild() != null && element.getFirstChild().getNodeType() == Node.TEXT_NODE) {
                    String originalText = element.getFirstChild().getTextContent().trim();
                    String transformedText = obfuscate ? obfuscateText(originalText) : deobfuscateText(originalText);
                    element.getFirstChild().setTextContent(transformedText);
                }
            }
        }
    }

    /**
     * Обфускация
     *
     * @param text - текст
     */
    private static String obfuscateText(String text) {
        return Base64.getEncoder().encodeToString(text.getBytes());
    }

    /**
     * Деобфускация
     *
     * @param text - текст
     */
    private static String deobfuscateText(String text) {
        return new String(Base64.getDecoder().decode(text));
    }

    /**
     * Трансформация документа в файл
     *
     * @param document - документ
     * @param outputFilePath - файл
     */
    private static void transformDocToFile(Document document, String outputFilePath) throws Exception {
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        DOMSource source = new DOMSource(document);
        StreamResult result = new StreamResult(new File(outputFilePath));
        transformer.transform(source, result);
    }

}
