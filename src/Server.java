/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 * @author Marah
 */

import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Scanner;

// Server class
class Server {
    static KeyPair keypair;

    public static void main(String[] args) {
        ServerSocket server = null;


        try {

            // server is listening on port 1234
            server = new ServerSocket(6668);
            server.setReuseAddress(true);


            //create keys to server

            keypair =  Hyper.generateKeyPair();
            System.out.println(
                    "The Public Key is: "
                            + DatatypeConverter.printHexBinary(
                            keypair.getPublic().getEncoded()));


            System.out.println(
                    "The Private Key is: "
                            + DatatypeConverter.printHexBinary(
                            keypair.getPrivate().getEncoded()));
            // running infinite loop for getting
            // client request
            while (true) {

                // socket object to receive incoming client
                // requests
                Socket client = server.accept();

                // Displaying that new client is connected
                // to server
                System.out.println("New client connected"
                        + client.getInetAddress()
                        .getHostAddress());

                // create a new thread object
                ClientHandler clientSock
                        = new ClientHandler(client);

                // This thread will handle the client
                // separately
                new Thread(clientSock).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (server != null) {
                try {
                    server.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    // ClientHandler class
    private static class ClientHandler implements Runnable {
         GCMParameterSpec GCM =null;
        private final Socket clientSocket;
        symmetric symmetric = new symmetric();
        SecretKey symmetrickey = null;
        String EncryptType = "";
        byte[] nonce = new byte[32];

        // Constructor
        public ClientHandler(Socket socket) {
            this.clientSocket = socket;
        }

        public void run() {
            OutputStream out = null;
            ObjectInputStream in = null;
            try {

                // get the outputstream of client
                out = clientSocket.getOutputStream();
                PrintStream ps = new PrintStream(clientSocket.getOutputStream());
                BufferedReader Stringin = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                in = new ObjectInputStream(clientSocket.getInputStream());
                DataOutputStream dataOut = new DataOutputStream(clientSocket.getOutputStream());
                String res = "";
                ObjectOutputStream ObjectdataOut = new ObjectOutputStream(clientSocket.getOutputStream());
                DataInputStream dIn = new DataInputStream(clientSocket.getInputStream());

                this.EncryptType = Stringin.readLine();
                if(this.EncryptType.equals("2")) {
                    // decrypt received

                    //Send Serve public Key
                    PublicKey publicKey = keypair.getPublic();
                    PrintWriter oout = new PrintWriter(clientSocket.getOutputStream(), true);
                    // oout.println(DatatypeConverter.printHexBinary(publicKey.getEncoded()));

                    ObjectdataOut.writeObject(publicKey);

                    //Receive Session key
                    Scanner scan = new Scanner(clientSocket.getInputStream());
                    String strCSK=scan.nextLine();
                    byte[] decSK=DatatypeConverter.parseHexBinary(strCSK);


                    //decrypt session key
                    strCSK=Hyper.Decrept2(decSK,keypair.getPrivate());
                    decSK=DatatypeConverter.parseHexBinary(strCSK);
                    SecretKey secretKey= new SecretKeySpec(decSK, 0, decSK.length, "AES");
                    System.out.println("The Session key  is: " + DatatypeConverter.printHexBinary(secretKey.getEncoded()));
                    symmetrickey=secretKey;
                    this.symmetric.SymmetricKey=secretKey;
                    dIn.readFully(nonce);
                    GCM=this.symmetric.getGCMParameterSpec(nonce);

                  //send acceptance message
                     oout.println("ok");

                }

                while (true) {
                    // writing the received message from
                    // client

                    System.out.println("new request");
                    ArrayList received, decrypted = new ArrayList<>();
                    received = (ArrayList) in.readObject();

                    if (this.EncryptType.equals("0")||this.EncryptType.equals("1")) {
                        for (int i = 0; i < received.size(); i++) {
                            decrypted.add(received.get(i).toString());
                            System.out.println("received :"+decrypted.get(i).toString());
                        }
                    }



                    if(this.EncryptType.equals("2"))  {
                        // decrypt received

                        for (int i = 0; i < received.size(); i++) {

                            decrypted.add(this.Decrypt(this.EncryptType, received.get(i).toString()));
                            System.out.println("received :" + received.get(0).toString());
                            System.out.println("decrypted :" + decrypted.get(i).toString());
                        }



                    }


                    if (decrypted.get(0).toString().equals("login")) {
                        ConnectToDatabase c = new ConnectToDatabase();

                      //  if (this.EncryptType.equals("0") || this.EncryptType.equals("1")) {
                            res = c.Login(decrypted.get(1).toString(), decrypted.get(2).toString());

                            if (this.EncryptType.equals("1")) {
                                SecureRandom random = SecureRandom.getInstanceStrong();
                                final byte[] nonce = new byte[32];
                                random.nextBytes(nonce);
                                GCM=this.symmetric.getGCMParameterSpec(nonce);
                                this.symmetrickey = this.symmetric.createAESKey(decrypted.get(2).toString());

                                System.out.println("The Symmetric Key is :"
                                        + DatatypeConverter.printHexBinary(
                                        this.symmetrickey.getEncoded()));
                                dataOut.write( nonce);
                            }
                            if(this.EncryptType.equals("2"))
                            {res = this.Encrypt(this.EncryptType, res);
                            }

                        ps.println(res);
                        System.out.println(res);

                    }
                    else if (decrypted.get(0).toString().equals("signup")) {
                        ConnectToDatabase c = new ConnectToDatabase();
                        if (this.EncryptType.equals("0") || this.EncryptType.equals("1")) {
                            res = c.Signup(decrypted.get(1).toString(), decrypted.get(2).toString());

                            if (this.EncryptType.equals("1")) {
                                SecureRandom random = SecureRandom.getInstanceStrong();
                                final byte[] nonce = new byte[32];
                                random.nextBytes(nonce);
                                GCM=this.symmetric.getGCMParameterSpec(nonce);
                                this.symmetrickey = this.symmetric.createAESKey(received.get(2).toString());

                                System.out.println("The Symmetric Key is :"
                                        + DatatypeConverter.printHexBinary(
                                        this.symmetrickey.getEncoded()));
                                dataOut.write( nonce);
                            }
                            System.out.println(res);
                            ps.println(res);
                        }
                        else  if(this.EncryptType.equals("2")){

                            String Encrypted = this.Encrypt(this.EncryptType, res);
                            ArrayList response = new ArrayList();
                            response.add(res);

                            ps.println(Encrypted);
                        }

                        System.out.println(res);

                    }
                    else if (received.get(0).toString().equals("-1")) break;
                    else {
                        if (this.EncryptType.equals("1")||this.EncryptType.equals("2")) {
                            decrypted.clear();
                            for (int i = 0; i < received.size()-1; i++) {

                                decrypted.add(this.Decrypt(this.EncryptType, received.get(i).toString()));
                                System.out.println("received "+received.get(i).toString());
                                System.out.println("Decrypt "+decrypted.get(i).toString());

                            }
                           // if(this.EncryptType.equals("1")){
                            String receivedMAc=received.get(received.size() - 1).toString();
                            System.out.println("receivedMAc :"+receivedMAc);
                            String Mac= java.util.Arrays.toString(symmetric.MAC(decrypted));

                               System.out.println("Mac :"+Mac);
                                if ( ! Mac.equals(receivedMAc)) {
                                System.err.println("WrongMac");
                                continue; }
                                else System.out.println("matched MAC");
                            //}
                        }

                        else if (this.EncryptType.equals("0")) {
                            for (int i = 0; i < received.size(); i++) {
                                System.out.println("received "+received.get(i).toString());
                                decrypted.add(received.get(i).toString());

                            }
                        }



                        if (decrypted.get(0).toString().equals("addPass")) {
                            ConnectToDatabase c = new ConnectToDatabase();
                            res = c.addPass(decrypted.get(1).toString(), decrypted.get(2).toString(), decrypted.get(3).toString(), decrypted.get(4).toString(), decrypted.get(5).toString(), decrypted.get(6).toString());

                        }
                        else if (decrypted.get(0).toString().equals("updatePass")) {
                            ConnectToDatabase c = new ConnectToDatabase();
                            res = c.updatePass(decrypted.get(1).toString(), decrypted.get(2).toString(), decrypted.get(3).toString(), decrypted.get(4).toString(), decrypted.get(5).toString(),decrypted.get(6).toString(),decrypted.get(7).toString());

                        }
                        else if (decrypted.get(0).toString().equals("deletePass")) {
                            ConnectToDatabase c = new ConnectToDatabase();
                            res = c.deletePass(decrypted.get(1).toString(), decrypted.get(2).toString());

                        }
                        else if (decrypted.get(0).toString().equals("getPass")) {
                            ConnectToDatabase c = new ConnectToDatabase();
                            res = c.getAllPass(decrypted.get(1).toString());


                        }



                        if (this.EncryptType.equals("0")) {
                            ps.println(res);
                        }
                        else if (this.EncryptType.equals("1")||this.EncryptType.equals("2")) {

                            String Encrypted = this.Encrypt(this.EncryptType, res);
                            ArrayList response = new ArrayList();
                            response.add(res);


                            // if(this.EncryptType.equals("1")){

                            String Mac = java.util.Arrays.toString(symmetric.MAC(response));
                            System.out.println("Mac :" + Mac);
                            ps.println(Encrypted + "MAC:" + Mac);
                        }


                        System.out.println(res);

                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                try {
                    if (out != null) {
                        out.close();
                    }
                    if (in != null) {
                        in.close();
                        clientSocket.close();
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        public String Encrypt(String Type, String Data) {
                try {
                    return this.symmetric.encrypt(Data,GCM);
                } catch (Exception e) {
                    e.printStackTrace();
                }

            return "";
        }

        public String Decrypt(String Type, String Data) {
           // if (Type.equals("1"))
                try {

                    return this.symmetric.decrypt(Data,GCM);
                } catch (Exception e) {
                    e.printStackTrace();
                }

            return "";
        }

    }
}


