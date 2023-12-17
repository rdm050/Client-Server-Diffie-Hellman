import javax.crypto.KeyAgreement;
import javax.crypto.KeyAgreement;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Client implements Runnable {

    private Socket client;
    private BufferedReader in;
    private PrintWriter out;
    private boolean done;

    @Override
    public void run() {
        try{
            client = new Socket("127.0.0.1", 1234);
            out = new PrintWriter(client.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(client.getInputStream()));

            InputHandler inHandler = new InputHandler();
            Thread t = new Thread(inHandler);
            t.start();

            String inMessage;
            while (( inMessage = in.readLine()) != null) {
                System.out.println("Server: " + inMessage);
                if (inMessage.equals("Correct"))
                    System.out.println(DiffieHellman());
            }
        }catch (IOException e) {
            shutdown();
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    public byte[] DiffieHellman() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException, InvalidKeySpecException, InvalidKeyException {

        // Create a Diffie-Hellman key pair (public and private).
        KeyPairGenerator Lukekpg = KeyPairGenerator.getInstance( "DH");
        Lukekpg.initialize( Skip.sDHParameterSpec );
        KeyPair LukekeyPair = Lukekpg.genKeyPair( );  // xLuke & yLuke


        DataInputStream in = new DataInputStream( client.getInputStream( ) );
        DataOutputStream out =
                new DataOutputStream( client.getOutputStream( ) );
        out.flush();
        // Send our public key to host.
        byte[ ] keyBytes = LukekeyPair.getPublic( ).getEncoded ();
        out.writeInt( keyBytes.length );  // length yLuke in bytes
        out.write( keyBytes );  // send yLuke as byte string

        // Accept public key from host (length, key in bytes).
        keyBytes = new byte[ in.readInt( ) ];  // read length of xHan
        in.readFully( keyBytes ); // read xHan as string of bytes
        KeyFactory kf = KeyFactory.getInstance( "DH" );
        X509EncodedKeySpec x509Spec =
                new X509EncodedKeySpec( keyBytes );
        PublicKey HanPublicKey = kf.generatePublic(x509Spec);  //yHan



        // Calculate the secret session key.
        KeyAgreement Lukeka = KeyAgreement.getInstance( "DH" );
        Lukeka.init( LukekeyPair.getPrivate( ) );  // using xLuke
        Lukeka.doPhase( HanPublicKey, true ); // init withyHan
        byte[ ] secret = Lukeka.generateSecret( );  // Shared secret key.
        // compute secret key Luke = g**yHan mod p
        // Terminate.
        out.close();
        in.close();

        //  in c:\jdk1.2.2\jre\classes\edu.shsu.util.BASE64
        return secret;

    }

    public void shutdown() {
        done = true;
        try{
            in.close();
            out.close();
            if (!client.isClosed()) {
                client.close();
            }
        } catch (IOException e) {
            //ignore
        }
    }

    class InputHandler implements Runnable {

        @Override
        public void run() {
            try{
                BufferedReader inReader = new BufferedReader(new InputStreamReader(System.in));
                while (!done) {
                    String message = inReader.readLine();
                    if (message.equals("/quit")) {
                        out.println(message);
                        inReader.close();
                        shutdown();
                    } else {
                        out.println(message);
                    }
                }
            }catch (IOException e){
                shutdown();
            }
        }
    }

    public static void main(String[] args) {
        Client client = new Client();
        client.run();
    }
}