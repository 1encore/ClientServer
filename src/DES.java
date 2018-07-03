import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

public class DES {
    static Cipher ecipher;
    static Cipher dcipher;

    public DES(SecretKey key) throws Exception{
        ecipher = Cipher.getInstance("DES");
        dcipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        ecipher.init(Cipher.ENCRYPT_MODE, key);
        dcipher.init(Cipher.DECRYPT_MODE, key);
    }

    public String encrypt(String str) throws Exception {
        // Perevod string v baity cherez UTf-8
        byte[] utf8 = str.getBytes("UTF8");

        // Encrypt delaem
        byte[] enc = ecipher.doFinal(utf8);

        // Perevod baitov d base 64 potom berem string
        return new sun.misc.BASE64Encoder().encode(enc);
    }

    public String decrypt(String str) throws Exception {
        // Perevod stringa d base 64 potom v baity
        byte[] dec = new sun.misc.BASE64Decoder().decodeBuffer(str);
        //decrypt
        byte[] utf8 = dcipher.doFinal(dec);

        // return cherez utf8
        return new String(utf8, "UTF8");
    }


    public static DES getEncrypter(String key) throws Exception {
        DESKeySpec dks = new DESKeySpec(key.getBytes());
        SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
        SecretKey desKey = skf.generateSecret(dks);
        DES encrypter = new DES(desKey);
        return encrypter;
    }
}
