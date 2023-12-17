import java.io.*;
import java.net.*;
public class Server  // Scale Up
{  public static void main(String[ ] args )
{
    int CountClients = 1;

    try
    {  // Attempt to set up a communications socket.
        ServerSocket serv = new ServerSocket(1234);

        while(true) // Connect clients forever.
        {
            // Sleep while listening for client to request connection!
            Socket clientServer = serv.accept( );
            System.out.println("Starting client server " + CountClients);
            // Create a new server (thread) for the client.
            new ThreadedServerEcho( clientServer, CountClients ).start( );
            CountClients++;
        }
    }
    catch ( Exception evt )
    {  System.out.println( evt );  }
}
}
