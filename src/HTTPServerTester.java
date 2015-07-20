import java.io.File;
import java.util.Scanner;
import java.io.IOException;
import java.util.regex.PatternSyntaxException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.BufferedWriter;
import java.io.OutputStreamWriter;
import java.io.InputStream;
import java.net.Socket;
import java.net.SocketException;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.text.ParseException;

/* Chen Cong <chen.cong@cs.rutgers.edu> */

class HTTPServerTester {

    /* Test case file syntax */
    private static String testCaseSeparator = "============\n";
    private static String testCasePartSeparator = "------------\n";

    /* Report syntax */
    private static String reportSeparator = "\n==============================\n";

    /* Socket timeout */
    private static int socketTimeout = 100000;

    /* Get SHA-256 digest of a byte array */
    private static String sha256(byte[] bytes) {
        MessageDigest sha256 = null;
        try{
            sha256 = MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }

        byte[] digest = sha256.digest(bytes);
        StringBuilder digestStringBuilder = new StringBuilder();
        for (byte digestDigit : digest) {
            digestStringBuilder.append(String.format("%02x", digestDigit));
        }
        return digestStringBuilder.toString();
    }

    /* Get the value of a header as a list */
    private static List<String> getValueAsList(String header) throws Exception {
        try{
            String headerValue = getValueAsString(header);
            String[] headerValueParts = headerValue.split(",");
            List<String> result = new ArrayList<String>();
            for (String headerValuePart : headerValueParts) {
                result.add(headerValuePart.trim());
            }
            return result;
        }
        catch (Exception e) {
            throw new Exception("The header \"" + header + "\" is not in good format");
        }
    }

    /* Get the value of a header as a string */
    private static String getValueAsString(String header) throws Exception {
        try{
            String[] headerParts = header.split(":");
            int keyLength = headerParts[0].length();
            return header.substring(keyLength + 1, header.length()).trim();
        }
        catch (Exception e) {
            throw new Exception("The header \"" + header + "\" is not in good format");
        }
    }

    /* Read testcases */
    private static String readTestCases(InputStream inputStream) {
	    StringBuilder result = new StringBuilder();
        Scanner scanner = new Scanner(inputStream);
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine();
            result.append(line).append("\n");
        }
        scanner.close();
        return result.toString();
    }

    /* Read from socket to get response header */
    private static String readResponseHeader(InputStream inputStream) throws IOException {
        List<Byte> byteList = new ArrayList<Byte>();

        /* Read byte from socket until we are at the last \n of \r\n\r\n */
        int currentByteInt = -1;
        byte currentMinus1Byte = (byte) 0;
        byte currentMinus2Byte = (byte) 0;
        byte currentMinus3Byte = (byte) 0;
        while ((currentByteInt = inputStream.read()) != -1) {
            byte currentByte = (byte) currentByteInt;
            if (currentByte == (byte) 0x0a &&
                    currentMinus1Byte == (byte) 0x0d &&
                    currentMinus2Byte == (byte) 0x0a &&
                    currentMinus3Byte == (byte) 0x0d) {
                break;
            }
            byteList.add(currentByte);
            currentMinus3Byte = currentMinus2Byte;
            currentMinus2Byte = currentMinus1Byte;
            currentMinus1Byte = currentByte;
        }

        /* Generate String from the byte array */
        byte[] byteArray = new byte[byteList.size()];
        for (int bi = 0; bi < byteList.size(); bi++) {
            byteArray[bi] = byteList.get(bi);
        }
        String headerString = new String(byteArray);
        
        return headerString;
    }

    /* Test Allow field, should contain POST, GET, HEAD */
    private static List<String> testAllowField(List<String> responseHeaders) {
        List<String> bugs = new ArrayList<String>();

        boolean allowExists = false;
        Iterator<String> responseHeadersIterator = responseHeaders.iterator();
        while (responseHeadersIterator.hasNext()) {
            String responseHeader = responseHeadersIterator.next();

            if (responseHeader.startsWith("Allow:")) {
                allowExists = true;

                List<String> allowValueList = new ArrayList<String>();
                try{
                    allowValueList = getValueAsList(responseHeader);
                }
                catch (Exception e) {
                    bugs.add(e.getMessage());
                }
                if (!allowValueList.contains("POST") || !allowValueList.contains("GET") || !allowValueList.contains("HEAD")) {
                    bugs.add("\"Allow\" must contain: GET, POST, HEAD");
                }
            }
        }
        if (allowExists == false) {
            bugs.add("Response header not found: \"Allow: GET, POST, HEAD\"");
        }

        return bugs;
    }

    /* Test Expires field, should be a future date */
    private static List<String> testExpiresField(List<String> resposneHeaders) {
        List<String> bugs = new ArrayList<String>();

        boolean expiresExists = false;
        Iterator<String> responseHeadersIterator = resposneHeaders.iterator();
        while (responseHeadersIterator.hasNext()) {
            String responseHeader = responseHeadersIterator.next();

            /* Expires: anytime in the future */
            if (responseHeader.startsWith("Expires")) {
                expiresExists = true;

                String expiresValue = new String();
                try{
                    expiresValue = getValueAsString(responseHeader);
                }
                catch (Exception e) {
                    bugs.add(e.getMessage());
                }

                /* Parse expire date */
                SimpleDateFormat format = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz");
                Date expiresDate = null;
                try{
                    expiresDate = format.parse(expiresValue);
                }
                catch (ParseException e) {
                    bugs.add("\"Expires\" is not in a good date format");
                }

                /* Expire date must be in the future */
                Date today = new Date();
                if (expiresDate != null && !expiresDate.after(today)) {
                    bugs.add("The date of \"Expires\" must be in the future");
                }
            }
        }

        if (expiresExists == false) {
            bugs.add("Response header not found: \"Expires: a future date\"");
        }

        return bugs;
    }

    /* Get the shasum of payload */
    private static String getPayloadShasum(InputStream inputStream, int payloadSize) throws IOException {
        byte[] payload = new byte[payloadSize];
        boolean nullPayload = false;
        for (int pi = 0; pi < payloadSize; pi++) {
            int payloadInt = inputStream.read();
            if (payloadInt == -1) {
                if (pi == 0) {
                    nullPayload = true;
                }
                break;
            }
            else {
                payload[pi] = (byte) payloadInt;
            }
        }

        String payloadShasum = new String();
        if (nullPayload) {
            payloadShasum = sha256(new byte[0]);
        }
        else {
            payloadShasum = sha256(payload);
        }
        return payloadShasum;
    }

    /* Entry method */
    public static void main(String[] args) {
        /* Parse args */
        String hostname = null;
        int port = 0;
        try {
            hostname = args[0];
            port = Integer.parseInt(args[1]);
        }
        catch (Exception e) {
            System.out.println("Usage error: java -jar HTTPServerTester.jar <address> <port>");
            return;
        }

        /* Get the test cases in pure text */
        String rawTestCases = null;
        try{
            rawTestCases = readTestCases(HTTPServerTester.class.getResourceAsStream("resources/TestCases.txt"));
        }
        catch (Exception e) {
            System.out.println("Unable to read test case file: " + e.getMessage());
            return;
        }

        /* Split test cases by testCaseSeparator */
        String[] testCases = null;
        try {
            testCases = rawTestCases.split(testCaseSeparator);
        }
        catch (PatternSyntaxException e) {
            System.out.println("Test cases are not correctly separated in test case file");
            return;
        }

        /* Run test case */
        int testNumber = 1;
        for (String testCase : testCases) {

            /* bug list */
            List<String> bugs = new ArrayList<String>();

            /* Extract request  and response from the test case string */
            String[] testParts = null;
            try {
                testParts = testCase.split(testCasePartSeparator);
            }
            catch (PatternSyntaxException e) {
                System.out.println("Test case parts are not correctly separated in test case file");
                return;
            }

            String request = null;
            String response = null;
            try{
                request = testParts[0];
                response = testParts[1];
            }
            catch (Exception e) {
                System.out.println("Test case parts are not correctly separated in test case file");
                return;
            }

            /* Split expected response into header and payload shasum */
            String[] responseParts = null;
            try {
                responseParts = response.split("\n\n");
            }
            catch (PatternSyntaxException e) {
                System.out.println("Response parts are not correctly separated in test case file");
                return;
            }

            /* Get expected response headers */
            List<String> testCaseResponseHeaders = new ArrayList<String>();
            try{
                testCaseResponseHeaders = new ArrayList<String>(Arrays.asList(responseParts[0].split("\n")));
            }
            catch (Exception e) {
                System.out.println("Response headers are not correctly separated in test case file");
                return;
            }

            /* Get expected response payload shasum if any */
            String testCaseResponsePayloadShasum = null;
            if (responseParts.length == 2) {
                testCaseResponsePayloadShasum = responseParts[1];
            }

            /* Get the first 64 hexits of shasum, because SHA-256 has 256 = 64 * 4 bits */
            if (testCaseResponsePayloadShasum != null) {
                if (testCaseResponsePayloadShasum.length() > 64) {
                    testCaseResponsePayloadShasum = testCaseResponsePayloadShasum.substring(0, testCaseResponsePayloadShasum.length() - 1);
                }
            }

            /* Create socket */
            Socket socket = null;
            try {
                socket = new Socket(hostname, port);
            }
            catch (IOException | SecurityException e) {
                System.out.println("Failed to create socket: " + e.getMessage());
                return;
            }
            catch (IllegalArgumentException e) {
                System.out.println("Port must be between 0 ~ 65535");
                return;
            }
            catch (NullPointerException e) {
                System.out.println("Address must not be null");
                return;
            }

            /* Set socket timeout */
            try{
                socket.setSoTimeout(socketTimeout);
            }
            catch (SocketException e) {
                System.out.println("Failed to set socket timeout: " + e.getMessage());
                return;
            }

            /* Write request to the socket */
            try {
                BufferedWriter socketWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
                if (!request.isEmpty()) {
                    socketWriter.write(request.replace("\n", "\r\n"));
                    socketWriter.flush();
                }
                else {
                    request = "<Null request>";
                }
            }
            catch (IOException e) {
                bugs.add("Failed to send request: " + e.getMessage());
                continue;
            }
            System.out.println("Test Case " + testNumber + "\n\n# Request:\n" + request.replace("\n\n", "\n<Blank line>") + "\n\n# Feedback:");
            testNumber++;

            /* Get response, store header fields into a list */
            List<String> responseHeaders = new ArrayList<String>();
            try{
                InputStream socketInputStream = socket.getInputStream();

                /* Read response header string and split it into a list */
                String headerString = null;
                try{
                    headerString = readResponseHeader(socketInputStream);
                }
                catch (IOException e) {
                    bugs.add("Failed to read response: " + e.getMessage());
                    continue;
                }
                String[] headerStringLines = headerString.split("\r\n");
                responseHeaders = new ArrayList<String>(Arrays.asList(headerStringLines));

                /* Get the status code of the test case, which is in fact the first line */
                String testCaseStatusCode = testCaseResponseHeaders.get(0);

                /* Do static tests, that is, the response should be LITERALLY the same as the test case */
                testCaseResponseHeaders.removeAll(responseHeaders);
                if (testCaseResponseHeaders.size() != 0) {
                    for (String missedResponseHeader : testCaseResponseHeaders) {
                        bugs.add("Response header not found: \"" + missedResponseHeader + "\"");
                    }
                }

                /* Then do dynamic tests, that is, test the value of certain headers with a function */
                /* 200: Allow: GET, POST, HEAD */
                if (testCaseStatusCode.equals("HTTP/1.0 200 OK")){
                    List<String> testAllowFieldResult = testAllowField(responseHeaders);
                    bugs.addAll(testAllowFieldResult);
                }
                /* 200, 304: Expires: a future date */
                if (testCaseStatusCode.equals("HTTP/1.0 200 OK") ||
                        testCaseStatusCode.equals("HTTP/1.0 304 Not Modified")){
                    List<String> testExpiresFieldResult = testExpiresField(responseHeaders);
                    bugs.addAll(testExpiresFieldResult);
                }
                

                /* If test case includes a shasum, then check payload, compare shasum */
                /* First get payload size */
                int payloadSize = 0;
                if (testCaseResponsePayloadShasum != null) {
                    for (String responseHeader : responseHeaders) {
                        if (responseHeader.startsWith("Content-Length:")) {
                            String contentLengthValue = new String();
                            try{
                                contentLengthValue = getValueAsString(responseHeader);
                            }
                            catch (Exception e) {
                                bugs.add(e.getMessage());
                            }

                            try {
                                payloadSize = Integer.parseInt(contentLengthValue);
                            }
                            catch (NumberFormatException e) {
                                bugs.add("The value of \"Content-Length\" is not a valid integer");
                            }
                        }
                    }

                    /* Then check the payload's shasum and compare */
                    if (payloadSize < 0) {
                        bugs.add("The value of \"Content-Length\" must not be negative");
                    }
                    else {
                        String payloadShasum = new String();
                        try{
                            payloadShasum = getPayloadShasum(socketInputStream, payloadSize);
                        }
                        catch (IOException e) {
                            bugs.add("Failed to read payload");
                        }

                        if (!payloadShasum.equals(testCaseResponsePayloadShasum)) {
                            bugs.add("Payload is not correct");
                        }
                    }
                }
                /* Close the socket and input stream */
                try{
                    socketInputStream.close();
                    socket.close();
                }
                catch(IOException e) {
                    bugs.add("Failed to close socket");
                }
            }
            catch (Exception e) {
                bugs.add("Failed to receive response: " + e.getMessage());
            }

            /* Display feedback */
            if (bugs.size() == 0) {
                System.out.println(" - Passed!");
            }
            for (String bug : bugs) {
                System.out.println(" - " + bug);
            }
            System.out.println(reportSeparator);
        }
    }
}