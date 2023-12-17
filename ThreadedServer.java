import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

class ThreadedServerEcho extends Thread // Actual server code.
{
    private Socket clientServer;
    private int countClients;

    public ThreadedServerEcho(Socket i, int c) {
        clientServer = i;
        countClients = c;
    }

    public void run() {
        try {  // Attach reader / writer streams.
            BufferedReader inPut = new BufferedReader
                    (new InputStreamReader(clientServer.getInputStream()));

            PrintWriter outPut = new PrintWriter
                    (clientServer.getOutputStream(), true /* autoFlush */);

            // Treat as simple file I/O
            outPut.println("Welcome to Echo Server");
            outPut.println("Enter 'Stop' to terminate server. ");
            outPut.println("Please enter your password: ");
            boolean lt = false;
            while (!lt) {

                String input = inPut.readLine();
                if (login(input)) {
                    outPut.println("Password Correct");
                    lt = true;
                }
                else
                    outPut.println("Incorrect password! ");


            }

            outPut.println("Correct");
            System.out.println(DiffieHellman());

            outPut.println("You may now choose your encryption method:");

            boolean finished = false;
            while (!finished) {
                String strIn = inPut.readLine();
                if (strIn == null)
                    finished = true;
                else {
                    outPut.println("Echo: " + strIn);
                    if (strIn.trim().equals("Stop"))
                        finished = true;
                }
            }
            inPut.close();
            outPut.close();  //Free communications resources
            clientServer.close();                  // and socket.
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    public byte[] DiffieHellman() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException {
        // Create a Diffie-Hellman key pair (public and private).
        KeyPairGenerator Hankpg = KeyPairGenerator.getInstance( "DH" );
        Hankpg.initialize(Skip.sDHParameterSpec);  // using SKIP
        KeyPair HankeyPair = Hankpg.genKeyPair( );  // xHan, yHan
        // Contains our public and private keys.

        // Create server socket and wait for connection. Then create streams.

        DataInputStream in = new DataInputStream( clientServer.getInputStream(  ) );
        DataOutputStream out = new DataOutputStream( clientServer.getOutputStream(  ) );

        // Accept public key from client (length, key in bytes).
        byte[ ] keyBytes = new byte[ in.readInt( ) ];  // length yLuke in bytes
        in.readFully( keyBytes );  // read yLuke as string of bytes
        KeyFactory kf = KeyFactory.getInstance( "DH" );
        X509EncodedKeySpec x509Spec =
                new X509EncodedKeySpec( keyBytes );
        PublicKey LukePublicKey = kf.generatePublic(x509Spec); // yLuke

        // Send our public key.
        keyBytes = HankeyPair.getPublic(  ).getEncoded(  );  //get yHan
        out.writeInt( keyBytes.length );  // write length yHan  // send len yHan
        out.write( keyBytes );  // write yHan as string of bytes

        // Calculate the secret session key.
        KeyAgreement Secretka = KeyAgreement.getInstance( "DH" );
        Secretka.init( HankeyPair.getPrivate(  ) );
        Secretka.doPhase( LukePublicKey, true );
        byte[ ] secret = Secretka.generateSecret(  );  // Shared secret key.
        // Han secret = g**yLuke mod p
        // Terminate.
        out.close();
        in.close();

        //  in c:\jdk1.2.2\jre\classes\edu.shsu.util.BASE64.  See class definition.
        //  Prints the key using base 64.  This is necessary due to the long key length.
        return secret;
    }


    public boolean login(String pword) throws NoSuchAlgorithmException, IOException {
        MessageDigest sha = MessageDigest.getInstance("MD5");
        byte[] md = sha.digest(pword.getBytes());
        BigInteger bi = new BigInteger(1, md);
        String out = bi.toString(16);

        File file = new File("/Users/mg/CryptoLab1/src/pword.txt");
        BufferedReader br = new BufferedReader(new FileReader(file));
        String st;

        while ((st = br.readLine()) != null) {
            if (st.equals(out))
                return true;

        }
        return false;
    }
}
 class Skip {
    // http://skip.incog.com/spec/numbers.html
    // Simple Key Management for Internet Protocols – SKIP.
    // Using DH (Diffie-Hellman standard).  1024 DH parameter defined by SKIP. First 79 bytes of ASCII
    // representation of a quote by Gandhi.  "Whatever you do is insignificant, but it is very important that
    // you do it."     512, 1024, and 2048 bit modulus parameters are supported.  The resulting keys are
    // the length of the modulus, i.e., 512, 1024, or 2048 bits.

    private static final String skip1024String =
                    "F488FD584E49DBCD" + "20B49DE49107366B" + "336C380D451D0F7C" + "88B31C7C5B2D8EF6" +
                    "F3C923C043F0A55B" + "188D8EBB558CB85D" + "38D334FD7C175743" + "A31D186CDE33212C" +
                    "B52AFF3CE1B12940" + "18118D7C84A70A72" + "D686C40319C80729" + "7ACA950CD9969FAB" +
                    "D00A509B0246D308" + "3D66A45D419F9C7C" + "BD894B221926BAAB" + "A25EC355E92F78C7";

    // Create modulus from string  => “p”
    private static final BigInteger skip1024Modulus
            = new BigInteger(skip1024String, 16);

    //Base => “g”
    private static final BigInteger skip1024Base
            = BigInteger.valueOf(2);

    //DH parameter specification
    public static final DHParameterSpec sDHParameterSpec =
            new DHParameterSpec( skip1024Modulus, skip1024Base );
}