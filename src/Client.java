
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.xml.bind.DatatypeConverter;
import java.net.*;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Scanner;

public class Client {
    // initializing socket and input output streams
    private ObjectOutputStream dataOut = null;
    private Scanner sc = null;
    private Socket skt = null;
    String id = "-1";
    String EncryptType = "";
    private symmetric symmetric=new symmetric();
    private GCMParameterSpec GCM=null;
    byte[] nonce = new byte[32];
    private SecretKey symmetrickey;
    private PublicKey serverpublickey;

    // constructor to create a socket with given IP and port address
    public Client(String address, int port) {
        boolean logged_in = false;
        // Establishing connection with server
        try {
            // creating an object of socket
            skt = new Socket(address, port);
            System.out.println("Connection Established!! ");
            // taking input from user
            sc = new Scanner(System.in);
            // opening output stream on the socket
            dataOut = new ObjectOutputStream(skt.getOutputStream());


            ArrayList<String> User_request = new ArrayList<String>();
            PrintStream ps = new PrintStream(skt.getOutputStream());
            DataOutputStream NonceOut = new DataOutputStream(skt.getOutputStream());
            System.out.println("Enter 0 for no Encryption \n      1 for symmetric Encryption \n      2 for Asymmetric Encryption");
            this.EncryptType =  sc.nextLine();
            ps.println(this.EncryptType);


            //....read public key server
            if(this.EncryptType.equals("2"))
            {
                //receive server public key
                ObjectInputStream in = new ObjectInputStream(skt.getInputStream());
                PublicKey strSPuK=(PublicKey) in.readObject();
                PrintWriter out = new PrintWriter(skt.getOutputStream(), true);

                serverpublickey=strSPuK;
                System.out.println("The Public Key is: " + DatatypeConverter.printHexBinary(serverpublickey.getEncoded()));


                //Generate session Key
                symmetrickey=symmetric.GenerateSessionKey();
                System.out.println("The Session Key is :" + DatatypeConverter.printHexBinary(symmetrickey.getEncoded()));
                //Encrypt session key
                byte[] EncryptedKey=Hyper.Encrept(DatatypeConverter.printHexBinary(symmetrickey.getEncoded()),serverpublickey);

               //send session key
                System.out.println("The Encrypted Session Key is :"+DatatypeConverter.printHexBinary(EncryptedKey));
               out.println(DatatypeConverter.printHexBinary(EncryptedKey));

               SecureRandom random = SecureRandom.getInstanceStrong();
                final byte[] nonce = new byte[32];
                random.nextBytes(nonce);

                NonceOut.write(nonce);

                GCM=this.symmetric.getGCMParameterSpec(nonce);



                //receive acceptance message
                Scanner scan2 = new Scanner(skt.getInputStream());
                String acceptanceM=scan2.nextLine();
                if (acceptanceM.equals("ok")){
                    System.out.println("The acceptance message received");
   }
                else
                    System.out.println("Connection refused .. try again later");
//try again


            }




            while (!logged_in) {
                System.out.println("input \"exit\" ,\"login\" or \"signup\" ");
                String next = sc.nextLine();

                if (next.equals("exit")) {
                    break;
                } else if (next.equals("login")) {
                    System.out.println("enter username and password");
                    User_request.add("login");
                    User_request.add(sc.nextLine());
                    User_request.add(sc.nextLine());
                } else if (next.equals("signup")) {
                    System.out.println("enter username and password");
                    User_request.add("signup");
                    User_request.add(sc.nextLine());
                    String p=sc.nextLine();
                    while (p.length()<8){
                        System.out.println("retype  password of 8 char at least");
                        p=sc.nextLine();
                    }
                    User_request.add(sc.nextLine());

                }
                try {
                    String response = "";
                    ArrayList<String> Encrypted_user_request = new ArrayList<String>();
                    BufferedReader in = new BufferedReader(new InputStreamReader(skt.getInputStream()));

                    DataInputStream dIn = new DataInputStream(skt.getInputStream());

                    //Symmetric
                     if (this.EncryptType.equals("1")||this.EncryptType.equals("0")) {
                        //not encrypted
                        dataOut.writeObject(User_request); // writing to the underlying output stream

                       if( this.EncryptType.equals("1")) {
                           //get GCM
                           dIn.readFully(nonce);
                           symmetrickey=symmetric.createAESKey(User_request.get(2));
                           System.out.println("The Symmetric Key is :"
                                   + DatatypeConverter.printHexBinary(
                                   symmetrickey.getEncoded()));
                       }


                        //get plain response //not encrypted
                        response = in.readLine();
                       System.out.println("server response :"+response);

                    }
                     else if(this.EncryptType.equals("2")){

                         for (int i = 0; i < User_request.size(); i++) {

                             Encrypted_user_request.add(this.Encrypt(this.EncryptType, User_request.get(i)));

                         }
                         dataOut.writeObject(Encrypted_user_request); // writing to the underlying output stream


                         //get plain response //not encrypted
                         response = in.readLine();
                         response=Decrypt(this.EncryptType,response);
                         System.out.println("server response :"+response);


                     }



                    //test if success
                    if (response.contains(":")) {
                        logged_in = true;
                        this.id = response.split(":")[0].charAt(response.split(":")[0].length()-1)+"";

                    }


                }
                // For handling errors while writing to output stream
                catch (IOException io) {
                    System.out.println(io);
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }


        } catch (IOException uh) {
            System.out.println(uh);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        // to store the input messages given by the user
        String str = "";


        while (logged_in) {

            ArrayList<String> request = new ArrayList<String>();
            ArrayList<String> Encrypted = new ArrayList<String>();
            System.out.println("input \"Done\" to exit.\n addPass\tgetPass\tupdatePass\tdeletePass ");
            str = sc.nextLine();

            try {
                BufferedReader in = new BufferedReader(new InputStreamReader(skt.getInputStream()));

                if (str.equals("Done")) {
                    request.add("-1");
                    dataOut.writeObject(request);

                    break;
                }
                else if (str.equals("addPass")) {
                    System.out.println("enter address , email , password,hint,attached");
                    request.add("addPass");
                    request.add(sc.nextLine());
                    request.add(sc.nextLine());
                    request.add(sc.nextLine());
                    request.add(sc.nextLine());
                    request.add(sc.nextLine());
                    request.add(this.id);
                }
                else if (str.equals("getPass")) {
                    request.add("getPass");
                    request.add(this.id);

                }
                else if (str.equals("updatePass")) {
                    System.out.println("enter enter address , email , password,hint,attached ,id ");
                    request.add("updatePass");
                    request.add(sc.nextLine());
                    request.add(sc.nextLine());
                    request.add(sc.nextLine());
                    request.add(sc.nextLine());
                    request.add(sc.nextLine());
                    request.add(sc.nextLine());
                    request.add(this.id);

                }
                else if (str.equals("deletePass")) {
                    System.out.println("enter id ");
                    request.add("deletePass");
                    request.add(sc.nextLine());
                    request.add(this.id);
                }
                else {
                    System.out.println("wrong operation");
                    continue;
                }

                if( this.EncryptType.equals("0")){

                    dataOut.writeObject(request);
                    String Response=in.readLine();
                    System.out.println("server response :"+Response);

                }

                else if(this.EncryptType.equals("1") ||this.EncryptType.equals("2")) {

                    for (int i = 0; i < request.size(); i++) {

                        Encrypted.add(this.Encrypt(this.EncryptType, request.get(i)));
                        System.out.println( request.get(i)+"\t\t"+Encrypted.get(i).toString());
                    }
                    //if(this.EncryptType.equals("1")) {

                         String mac=java.util.Arrays.toString(this.symmetric.MAC(request));
                    System.out.println("Mac :mac");
                        Encrypted.add(mac);
                    //}
                    System.out.println("sending request ");
                        dataOut.writeObject(Encrypted); // writing to the underlying output stream



                    String[] Response=in.readLine().split("MAC:");

                    System.out.println("encrypted Response : "+Response);
                    String DecryptedResponse = this.Decrypt(this.EncryptType, Response[0]);

                   // if(this.EncryptType.equals("1")) {
                        ArrayList text = new ArrayList();
                        text.add(DecryptedResponse);
                        String Mac=java.util.Arrays.toString(this.symmetric.MAC(text));
                        String receivedMAc=Response[1];
                        if ( !Mac.equals(receivedMAc))
                            System.err.println("wrongMac");
                        else
                            System.out.println("Decrypted Response : "+DecryptedResponse);

                    //}
                    //else
                      //  System.out.println(DecryptedResponse);
                }

                // reading input


                // For handling errors while writing to output stream
            } catch (Exception e) {
                e.printStackTrace();
            }

        }
        System.out.println(" Connection Terminated!! ");
        // for closing the connection
        try {
            dataOut.close();
            skt.close();
        } catch (IOException io) {
            System.out.println(io);
        }
    }


    public String Encrypt(String Type, String Data) {
        //if (Type.equals("1"))
            try {
                return this.symmetric.encrypt( Data,this.symmetric.getGCMParameterSpec(nonce));
            } catch (Exception e) {
                e.printStackTrace();
            }
        return "";
    }

    public String Decrypt(String Type, String Data) {
      //  if (Type.equals("1"))
            try {
                return this.symmetric.decrypt(Data,this.symmetric.getGCMParameterSpec(nonce));
            } catch (Exception e) {
                e.printStackTrace();
            }

        return "";
    }

    public static void main(String argvs[]) {
        // creating object of class Client
        Client client = new Client("localhost", 6668);

    }
}