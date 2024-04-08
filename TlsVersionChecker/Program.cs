using System;
using CommandLine;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.ConstrainedExecution;
using CommandLine.Text;

class Program
{
    //[("tcp", isDefault: true, HelpText = "Connect using TcpClient")]
    class UseTcpClient
    {
        [Option('t', "target-host", Required = true, HelpText = "The host to connect with")]
        public string TargetHost { get; set; }

        [Option('u', "use-tls-version", Default = "system", Required = false, HelpText = "Force the use of a specific TLS version (e.g., tls13, tls12, tls11, tls, system)")]
        public string TlsVersion { get; set; }

        [Option('c', "cert-path", Required = false, HelpText = "Path to client certificate to be used in connection")]
        public string CertificatePath { get; set; }

        [Option('p', "cert-pwd", Required = false, HelpText = "Certificate password")]
        public string CertificatePassword { get; set; }

        [Usage(ApplicationAlias = "TlsVersionChecker.exe")]
        public static IEnumerable<Example> Examples
        {
            get
            {
                return new List<Example>() {
                    new Example("Conect to host using default system TLS config", new UseTcpClient { TargetHost = "example.com" }),
                    new Example("Conect to host using TLS 1.2", new UseTcpClient { TargetHost = "example.com", TlsVersion = "tls12" }),
                    new Example("Conect to host using a client certificate", new UseTcpClient { TargetHost = "example.com", CertificatePath = "C:/cert.pfx", CertificatePassword = "123456" })
                };
            }
        }
    }

    private static int ConectUsingTcpClient(UseTcpClient opts)
    {
        try
        {
            SslProtocols desiredTlsVersion = SslProtocols.None;

            switch (opts.TlsVersion)
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
                case "system":
                    desiredTlsVersion = SslProtocols.None;
                    break;
                default:
                    Console.WriteLine("Invalid TLS version. Use one of the following: tls13, tls12, tls11, tls, system");
                    return 0;
            }

            using (TcpClient tcpClient = new TcpClient(opts.TargetHost, 443))
            using (SslStream sslStream = new SslStream(tcpClient.GetStream(), false))
            {
                X509CertificateCollection certCollection = null;
                if (!String.IsNullOrWhiteSpace(opts.CertificatePath) && !String.IsNullOrWhiteSpace(opts.CertificatePassword))
                {
                    X509Certificate2 certificate = new X509Certificate2(opts.CertificatePath, opts.CertificatePassword);
                    certCollection = new X509CertificateCollection { certificate };
                }

                if (desiredTlsVersion != SslProtocols.None)
                {
                    sslStream.AuthenticateAsClient(opts.TargetHost, certCollection, desiredTlsVersion, false);
                }
                else
                {
                    sslStream.AuthenticateAsClient(opts.TargetHost, certCollection, false);
                }
                Console.WriteLine("Values being used:");
#if NET5_0_OR_GREATER
                Console.WriteLine($"Negotiated Cipher Suite: {sslStream.NegotiatedCipherSuite}");
#endif
                Console.WriteLine($"Cipher: {sslStream.CipherAlgorithm}");
                Console.WriteLine($"Cipher strength: {sslStream.CipherStrength}");
                Console.WriteLine($"Hash Algorithm: {sslStream.HashAlgorithm}");
                Console.WriteLine($"Key Exchange Algorithm: {sslStream.KeyExchangeAlgorithm}");
                Console.WriteLine($"SSL/TLS Protocol version: {sslStream.SslProtocol}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error establishing SSL/TLS connection using TcpClient:\r\n {ex}");
        }
        return 0;
    }

    static void Main(string[] args)
    {
        Parser.Default.ParseArguments<UseTcpClient>(args)
            .MapResult(
              (UseTcpClient opts) => ConectUsingTcpClient(opts),
              errs => 1);
    }
}
