import java.net.*;
import java.io.*;
import java.util.*;
import com.google.gson.Gson;

public class Client{
    public static String myKey = "u7024668";

    public static void main(String[] args) {

        Scanner in = new Scanner(System.in);
        RSA rsa = new RSA("SHA1withRSA");
        Gson gson = new Gson();
        try{
            Socket socket = new Socket("127.0.0.1", 1010);

            ObjectOutputStream outStream =
                    new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream inStream =
                    new ObjectInputStream(socket.getInputStream());

            DES encrypter = DES.getEncrypter(myKey);

            System.out.println("Insert your message");

            Thread sender = new Thread(new Runnable() {
                @Override
                public void run() {
                    while(true){
                        try {
                            String txt = in.nextLine();
                            Message msg = new Message(txt);

                            byte[] signedData = rsa.sign(txt, "./resources/private_pkcs8.pem.txt");
                            msg.setSign(rsa.bytesToHex(signedData));
                            String json = gson.toJson(msg);
                            json = encrypter.encrypt(json);

                            outStream.writeObject(json);
                        }catch (Exception e){
                            e.printStackTrace();
                        }
                    }
                }
            });
            sender.start();

            Thread receiver = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        String getjs;
                        while ((getjs = (String) inStream.readObject()) != null) {
                            getjs = encrypter.decrypt(getjs);
                            Message getMsg = gson.fromJson(getjs, Message.class);
                            if (rsa.verifySig(getMsg.getText(), "./resources/public.pem.txt", rsa.hexToBytes(getMsg.getSign()))) {
                                System.out.println("Server: " + getMsg.getText());
                            }
                        }
                    }catch (Exception e){
                        e.printStackTrace();
                    }
                }
            });
            receiver.start();

        }catch (Exception e) {
            e.printStackTrace();
        }
    }
}