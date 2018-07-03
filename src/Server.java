import java.net.*;
import java.io.*;
import java.util.Scanner;

import com.google.gson.Gson;

public class Server{
    public static String myKey = "u7024668";
    public static void main(String[] args) {

        System.out.println("Waiting for connection...");
        RSA rsa = new RSA("SHA1withRSA");
        Gson gson = new Gson();
        try{

            ServerSocket server = new ServerSocket(1010);
            Socket socket = server.accept();

            DES encrypter = DES.getEncrypter(myKey);

            System.out.println("Client connected");

            ObjectInputStream inStream =
                    new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream outStream =
                    new ObjectOutputStream(socket.getOutputStream());

            Scanner sc = new Scanner(System.in);

            Thread receiver = new Thread(() -> {
                Message msg = null;
                String json;
                try {
                    while(null != (json = (String) inStream.readObject())) {
                        json = encrypter.decrypt(json);
                        msg = gson.fromJson(json, Message.class);
                        if (rsa.verifySig(msg.getText(), "./resources/public.pem.txt", rsa.hexToBytes(msg.getSign()))) {
                            System.out.println("[" + socket.getPort() + "] Client: " + msg.toString());
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
            receiver.start();

            Thread sender = new Thread(() -> {
                while(true){
                    String txt = sc.next();
                    try {
                        Message newms = new Message(txt);
                        byte[] signedData = rsa.sign(txt, "./resources/private_pkcs8.pem.txt");
                        newms.setSign(rsa.bytesToHex(signedData));
                        String newjs = gson.toJson(newms);
                        newjs = encrypter.encrypt(newjs);
                        outStream.writeObject(newjs);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });
            sender.start();
        }catch (Exception e) {
            e.printStackTrace();
        }
    }
}
