using System;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

class Program
{
    static void Main(string[] args)
    {
        if (args.Length < 1 || Array.Exists(args, arg => arg.Equals("--help", StringComparison.OrdinalIgnoreCase)))
        {
            ShowHelp();
            return;
        }
        // Use the first command-line argument as the target host
        string targetHost = args[0];

        // Check for the optional "--use" parameter
        SslProtocols desiredTlsVersion = SslProtocols.None;
        for (int i = 1; i < args.Length - 1; i++)
        {
            if (args[i].Equals("--use", StringComparison.OrdinalIgnoreCase))
            {
                string tlsVersion = args[i + 1].ToLowerInvariant();
                Console.WriteLine(tlsVersion);
                switch (tlsVersion)
                {
                    case "tls13":
                        desiredTlsVersion = SslProtocols.Tls13;
                        break;
                    case "tls12":
                        desiredTlsVersion = SslProtocols.Tls12;
                        break;
                    case "tls11":
                        desiredTlsVersion = SslProtocols.Tls11;
                        break;
                    case "tls":
                        desiredTlsVersion = SslProtocols.Tls;
                        break;
                    default:
                        Console.WriteLine("Invalid TLS version. Use one of the following: tls13, tls12, tls11, tls.");
                        return;
                }
            }
            else
            {
                Console.WriteLine($"Invalid parameter: {args[i]}");
                ShowHelp();
                return;
            }
        }

        // Create a TCP connection to the host
        using TcpClient tcpClient = new TcpClient(targetHost, 443);

        // Establish an SSL/TLS connection over the TCP connection
        using SslStream sslStream = new SslStream(tcpClient.GetStream(), false);

        try
        {
            if (desiredTlsVersion != SslProtocols.None)
            {
                // Authenticate the SSL/TLS connection with the target host using the specified TLS version
                sslStream.AuthenticateAsClient(targetHost, null, desiredTlsVersion, false);
            }
            else
            {
                // Authenticate the SSL/TLS connection with the target host without specifying a TLS version
                sslStream.AuthenticateAsClient(targetHost);
            }
            Console.WriteLine("Values being used:");
            Console.WriteLine($"Negotiated Cipher Suite: {sslStream.NegotiatedCipherSuite}");
            Console.WriteLine($"Cipher: {sslStream.CipherAlgorithm}");
            Console.WriteLine($"Hash Algorithm: {sslStream.HashAlgorithm}");
            Console.WriteLine($"Key Exchange Algorithm: {sslStream.KeyExchangeAlgorithm}");
            Console.WriteLine($"SSL/TLS Protocol version: {sslStream.SslProtocol}");
        }
        catch (AuthenticationException ex)
        {
            Console.WriteLine($"Error establishing SSL/TLS connection: {ex}");
        }
    }

    private static void ShowHelp()
    {
        Console.WriteLine("Usage: TlsVersionChecker.exe <target_host> [--use tls13|tls12|tls11|tls]");
        Console.WriteLine("\nOptions:");
        Console.WriteLine("  --help          Show this help message");
        Console.WriteLine("  --use VERSION   Force the use of a specific TLS version (e.g., tls13, tls12, tls11, tls)");
    }
}
