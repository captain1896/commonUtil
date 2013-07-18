
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.safehaus.uuid.UUID;


/**
 * String util functions
 * 
 */
public final class StringUtil {
    
    private static final String K_HEX_CHARS = "0123456789abcdefABCDEF";
    
    private static final int BASE_62 = 62;
    
    private static final String UICONTENTREX = "^[0-9A-Za-z_ \\u0100-\\uFFFF\\.\\,\\-@]+$";
    
    private static final String FIRSTNUMBERREX = "(^[1-9]\\d*)";
    
    private StringUtil() { }
    
    
    /**
     * Replace the place holders in the given string and return the result
     * @param body
     * @param map
     * @return
     */
    public static String replacePlaceHolders(String body, Map<String, String> map) {
        String result = body;
        Set<Entry<String, String>> s = map.entrySet();
        Iterator<Entry<String, String>> iterator = s.iterator();
        while (iterator.hasNext()) {
            String temp = iterator.next().getKey();
            result = result.replace(temp,  map.get(temp));
        }
        return result;
    }
    
    
    /**
     * Read the file content into a string
     * @param path
     * @return
     * @throws ServicesException
     */
    public static String readDataFromFile(String path) throws ServicesException {
        String tempBody = null;
        String data = null;
        try {
            FileReader fileReader = new FileReader(path);
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            tempBody = bufferedReader.readLine();
            while (tempBody != null) {
                if (data == null) {
                    data = tempBody;
                } else {
                    data = data + tempBody;
                }
                tempBody = bufferedReader.readLine();
            }

            bufferedReader.close();
        } catch (FileNotFoundException fe) {
            throw new ServicesException("Could not read from the file " + path);
        } catch (IOException fe) {
            throw new ServicesException("Could not read from the file " + path);
        }

        return data;
    }

    
    /**
     * Log the stack trace to the log file.
     * @param throwable
     * @param log
     */
    public static void logStackTrace(Throwable throwable, Log log) {
        StringWriter sw = new StringWriter();
        throwable.printStackTrace(new PrintWriter(sw));
        log.error(sw.toString());  
    }
    
    
    /**
     * Returns a string with ... appended to the end if the length is greater than
     * the given length param.
     * @param str
     * @param length
     * @return
     */
    public static String shortenString(String str, int length) {
        if (StringUtils.isEmpty(str)) {
            return "";
        }
        if (length < 3) {
            return "...";
        }
        // shorted the string to length
        if (str.length() > length) {
            return str.substring(0, length - 3) + "...";
        }
        return str;
    }
    
    
    /**
     * Shorten the length of a tweet, english character count as 0.5
     * @param str
     * @param length
     * @return
     */
    public static String shortenTweet(String str, int length) {
        if (StringUtils.isEmpty(str)) {
            return "";
        }
        if (length < 3) {
            return "...";
        }
        // shorted the string to length
        if (getTweetLength(str) > length) {
            StringBuilder sb = new StringBuilder();
            int count = 0;
            int max = (length * 2) - 3;
            for (int i = 0; i < str.length() && count < max; i++) {
                sb.append(str.charAt(i));
                if (str.charAt(i) < 256) count += 1;
                else count += 2;
            }
            sb.append("...");
            return sb.toString();
        } else {
            return str;
        }
    }
    
    
    /**
     * Get the length of a tweet, english character count as 0.5
     * @param str
     * @return
     */
    public static int getTweetLength(String str) {
        int length = 0;
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) < 256) length += 1;
            else length += 2;
        }
        return length / 2;
    }
    
    /**
     * Get the String of a tweet string with size, english character count as 0.5
     * @param str
     * @return
     */
    public static int getTweetLength(String str, int size) {
        int length = 0;
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) < 256) length += 1;
            else length += 2;
            if (length >= (size * 2)) 
                return i;
        }
        return length;
    }
    
    
    //test main function
/*    public static void main(String[] args) {
        String s = "1234ºº×Ö1234ºº×Öºº×Öºº×Öºº×Öºº×Ö";
        // System.out.println(getTweetString(s, 10));
    }*/
    
    
    /**
     * Convert byte array into hex string
     * @param bytes
     * @return
     */
    public static String byteArrayToHexString(byte[] bytes) {
        if (bytes == null) {
            return "";
        }
        
        StringBuffer b = new StringBuffer(bytes.length * 2);
        for (int i = 0; i < bytes.length; ++i) {
            int hex = bytes[i] & 0xFF;
            b.append(K_HEX_CHARS.charAt(hex >> 4));
            b.append(K_HEX_CHARS.charAt(hex & 0x0f));
        }
        return b.toString();
    }
    
    
    /**
     * Convert hex string into byte array
     * @param hex
     * @return
     */
    public static byte[] hexStringToByteArray(String hex) {
        if (StringUtils.isEmpty(hex)) {
            return new byte[0];
        }
        
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i + 1 < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + 
                            Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    
    /**
     * Convert a string type uuid to byte array
     * @param uuid
     * @return
     */
    public static byte[] uuidToByteArray(String uuid) {
        try {
            return new UUID(uuid).asByteArray();
        } catch (Exception e) {
            // invalid uuid, use default
            return new UUID().asByteArray();
        }
    }
    
    
    /**
     * Convert a byte array to string type uuid
     * @param uuid
     * @return
     */
    public static String byteArrayToUuid(byte[] uuid) {
        try {
            return new UUID(uuid).toString();
        } catch (Exception e) {
            // invalid uuid, use default
            return new UUID().toString();
        }
    }
    
    public static boolean byteArrayCompare(byte[] a, byte[] b) {
        if (a.length == b.length) {
            for (int i = 0; i < a.length; i++) {
                if (a[i] != b[i]) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    /**
     * Generates 16 Byte random String
     * @return unique random string
     */
    public static String get16ByteRandomString() {
        return RandomStringUtils.randomAlphanumeric(16);
    }
    
    
    /**
     * Converts the base 10 long to the given base.
     * Supports up to base 62. If the given base is greater than 62, it will just return 
     * the long in a String representation.
     * 
     * @param baseTenLong
     * @param base
     * @return
     */
    public static String convertToBase62(long baseTenLong) {
        // special case
        if (baseTenLong == 0) return "0";

        String digits = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String s = "";
        long l = baseTenLong;
        while (l > 0) {
            int d = (int) (l % BASE_62);
            s = digits.charAt(d) + s;
            l = l / BASE_62;
        }
        return s;
    }
    
    /**
     * Converts the base 62 String to a base 10 Long.
     * 
     * @param base62String
     * @return
     */
    public static long convertFromBase62(String base62String) {
        long base10long = 0;
        int j = 0;
        for (int i = base62String.length() - 1; i >= 0; i--) {
            base10long += valueOfBase62(base62String.charAt(i)) * Math.pow(BASE_62, j);
            j++;
        }
        return base10long;
    }
    

    private static int valueOfBase62(char c) {
        if (c >= 'a' && c <= 'z') {
            return (int) c - 87;
        } else if (c >= 'A' && c <= 'Z') {
            return (int) c - 29;
        } else if (c >= '0' && c <= '9') {
            return (int) c - 48;
        } else {
            return 0;
        }
    }
    
    /**
     *
     * @param source
     * @return source if can't convert chars from latin to utf-8
     */
    public static String convertLatin2Utf8(String source) {
        if (StringUtils.isEmpty(source)) {
            return "";
        }
        try {
            byte[] sourceBytes = source.getBytes("iso-8859-1");
            return new String(sourceBytes, "utf-8");
        } catch (Exception e) {
            return source;
        }
    }
    //convert Latin to point ,default use UTF-8
    public static String converLatinByAssign(String source , String encoding) {
        if ("GBK".equals(StringUtils.upperCase(encoding))) {
            return convertLatin(source , encoding);
        } else {
            return convertLatin2Utf8(source);
        }
    }

    // convert Latin to related encoding character
    public static String convertLatin(String source , String encoding) {
        if (StringUtils.isEmpty(source)) {
            return "";
        }
        try {
            byte[] sourceBytes = source.getBytes("iso-8859-1");
            return new String(sourceBytes , encoding);
        } catch (Exception e) {
            return source;
        }
    }
    
    
    /**
     * Hash the given string and return a byte array
     * @param s
     * @return
     */
    public static byte[] hash(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return md.digest(s.getBytes("UTF-8"));
        } catch (Exception e) {
            return new byte[0];
        } 
    }
    
    
    /**
     * Convenient method to decode a utf-8 url
     * @param s
     * @return
     */
    public static String urlDecode(String s) {
        return urlDecode(s, "UTF-8");
    }
    
    
    /**
     * Decode a url with specific codec
     * @param s
     * @param codec
     * @return
     */
    public static String urlDecode(String s, String codec) {
        try {
            return URLDecoder.decode(s, codec);
        } catch (UnsupportedEncodingException e) {
            return s;
        } catch (Exception e) {
            return s;
        }
    }
    
    /**
     * Convenient method to encode a utf-8 url
     * @param s
     * @return
     */
    public static String urlEncode(String s) {
        return urlEncode(s, "UTF-8");
    }
    
    
    /**
     * Encode a url with specific codec
     * @param s
     * @param codec
     * @return
     */
    public static String urlEncode(String s, String codec) {
        if (s == null) {
            return "";
        }
        try {
            String tmp = URLEncoder.encode(s, codec);
            return tmp.replace("+", "%20");
        } catch (UnsupportedEncodingException e) {
            return s;
        }
    }
    
    public static boolean isValidContent(String content) {
        Pattern pattern = Pattern.compile(UICONTENTREX);
        Matcher matcher = pattern.matcher(content);
        return matcher.matches();
    }
    
    public static long getFirstNumber(String content) {
        long result = 0;
        try {
            Pattern pattern = Pattern.compile(FIRSTNUMBERREX);
            Matcher matcher = pattern.matcher(content);
            if (matcher.find()) {
                result = Long.valueOf(matcher.group());
            }
        } catch (Exception e) {
            result = 0;
        }
        return result;
    }
    
    /**replace like content
     * @param content
     * @return
     */
    public static String replaceLikeStr(String content) {
        String sText = StringUtils.replace(content, "%", "\\%");
        sText = StringUtils.replace(sText, "_", "\\_");
        return StringUtils.isBlank(sText) ? "" : sText;
    }
    
    public static String replaceReturn(String content , String split) {
        return StringUtils.replace(StringUtils.replace(content, "\r\n", split), "\n", split);
    }
    public static String replace2Return(String content , String split) {
        return StringUtils.replace(content, split, "\n");
    }
}
