using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Configuration;
using System.Net.Security;
using System.Security.Authentication;
using System.Text.RegularExpressions;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Net.Http;


public class Proxyserver {

    private static readonly int BUFFER_SIZE = 8192;
    private static readonly char[] semiSplit = new char[] { ';' };
    private static readonly char[] equalSplit = new char[] { '=' };
    private static readonly String[] colonSpaceSplit = new string[] { ": " };
    private static readonly char[] spaceSplit = new char[] { ' ' };
    private static readonly char[] commaSplit = new char[] { ',' };
    private static readonly Regex cookieSplitRegEx = new Regex(@",(?! )");
    private static X509Certificate2 _certificate;
    private static object _outputLockObj = new object();

    static void process_client_request(object arg) {
        TcpClient client = (TcpClient)arg;

        try
        {
            /*StreamReader reader = new StreamReader(client.GetStream());
            StreamWriter writer = new StreamWriter(client.GetStream());
            string s = String.Empty;
            while (!(s = reader.ReadLine()).Equals("Exit") || (s == null))
            {
                Console.WriteLine(s);
                writer.Flush();
            }
            reader.Close();
            writer.Close();*/

            DoHttpProcessing(client);

            client.Close();
            //Console.WriteLine("Closing connection");
        }
        catch (IOException)
        {
            Console.WriteLine("Problem with client connection");
        }

        finally
        {
            if (client != null)
            {
                client.Close();
            }
        }
    }

    public static bool ValidateServerCertificate(
              object sender,
              X509Certificate certificate,
              X509Chain chain,
              SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;
            return false;
        }

    static void DoHttpProcessing(TcpClient client) {
        
		Stream clientStream = client.GetStream();
        Stream outStream = clientStream;
        SslStream sslStream = null;

        StreamReader clientStreamReader = new StreamReader(clientStream);

        try
        {
            //read the first line HTTP command
            String httpCmd = clientStreamReader.ReadLine();
            if (String.IsNullOrEmpty(httpCmd))
            {
                clientStreamReader.Close();
                clientStream.Close();
                return;
            }

            //break up the line into three components
            String[] splitBuffer = httpCmd.Split(new char[] { ' ' }, 3);

            String method = splitBuffer[0];
            String remoteUri = splitBuffer[1];
            Version version = new Version(1, 0);

            //if (splitBuffer[2].Cont[[ains("1.0")) {
            //    version = new Version(1, 0);
            //}
            //else {
            //    version = new Version(1, 1);
            //}
            
            int BUFFER_SIZE = 10240;

            HttpWebRequest webReq;
            HttpWebResponse response = null;

            if (splitBuffer[0].ToUpper() == "CONNECT")
            {
                //Browser wants to create a secure tunnel
                //instead = we are going to perform a man in the middle "attack"
                //the user's browser should warn them of the certification errors however.
                //Please note: THIS IS ONLY FOR TESTING PURPOSES - you are responsible for the use of this code
                remoteUri = "https://" + splitBuffer[1];
                while (!String.IsNullOrEmpty(clientStreamReader.ReadLine())) ;
                StreamWriter connectStreamWriter = new StreamWriter(clientStream);
                connectStreamWriter.WriteLine("HTTP/1.0 200 Connection established");
                connectStreamWriter.WriteLine(String.Format("Timestamp: {0}", DateTime.Now.ToString()));
                connectStreamWriter.WriteLine("Proxy-agent: myc");
                connectStreamWriter.WriteLine();
                connectStreamWriter.Flush();

                //String certFilePath = @"mycert.pfx";



                string filename = "myc.pfx";

                string fullpath = Path.GetFullPath(filename);

                fullpath = fullpath.Replace("\\", "/");



                X509Certificate2 _certificate = new X509Certificate2(fullpath, "vardhan");


                //if (ConfigurationManager.AppSettings[certFilePath] != null)
                //    certFilePath = ConfigurationManager.AppSettings["CertificateFile"];


                //if (true/*ConfigurationManager.AppSettings["C:/Users/Chandu-Budati/cert.cer"] != null*/) {
                //    certFilePath = ConfigurationManager.AppSettings["mycert.pfx"];
                //    _certificate = new X509Certificate2(certFilePath);
                //}

                //ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                sslStream = new SslStream(clientStream, false, null);

                try
                {
                    sslStream.AuthenticateAsServer(_certificate, false, SslProtocols.Tls | SslProtocols.Ssl3 | SslProtocols.Ssl2, true);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    sslStream.Close();
                    clientStreamReader.Close();
                    connectStreamWriter.Close();
                    clientStream.Close();
                    return;
                }

                //HTTPS server created - we can now decrypt the client's traffic
                clientStream = sslStream;
                clientStreamReader = new StreamReader(sslStream);
                outStream = sslStream;
                //read the new http command.
                httpCmd = clientStreamReader.ReadLine();
                if (String.IsNullOrEmpty(httpCmd))
                {
                    clientStreamReader.Close();
                    clientStream.Close();
                    sslStream.Close();
                    return;
                }
                splitBuffer = httpCmd.Split(spaceSplit, 3);
                method = splitBuffer[0];
                remoteUri = remoteUri + splitBuffer[1];
            }


            //construct the web request that we are going to issue on behalf of the client.
            webReq = (HttpWebRequest)HttpWebRequest.Create(remoteUri);
            webReq.Method = method;
            webReq.ProtocolVersion = version;

            //read the request headers from the client and copy them to our request
            int contentLen = ReadRequestHeaders(clientStreamReader, webReq);

            webReq.Proxy = null;
            webReq.KeepAlive = false;
            webReq.AllowAutoRedirect = false;
            webReq.AutomaticDecompression = DecompressionMethods.None;
            

            
            webReq.Timeout = 15000;

            try
            {
                response = (HttpWebResponse)webReq.GetResponse();
            }
            catch (WebException webEx)
            {
                response = webEx.Response as HttpWebResponse;
            }
            if (response != null)
            {
                List<Tuple<String, String>> responseHeaders = ProcessResponse(response);
                StreamWriter myResponseWriter = new StreamWriter(outStream);
                Stream responseStream = response.GetResponseStream();
                try
                {
                    //send the response status and response headers
                    //if (splitBuffer[2].Contains("1.0"))
                    //{
                    //    myResponseWriter.WriteLine(String.Format("HTTP/1.0 {0} {1}", (Int32)response.StatusCode, response.StatusDescription));
                    //}
                    //else
                    //{
                    //    myResponseWriter.WriteLine(String.Format("HTTP/1.1 {0} {1}", (Int32)response.StatusCode, response.StatusDescription));
                    //}
                    myResponseWriter.WriteLine(String.Format("HTTP/1.0 {0} {1}", (Int32)response.StatusCode, response.StatusDescription));

                    if (responseHeaders != null)
                    {
                        foreach (Tuple<String, String> header in responseHeaders)
                            myResponseWriter.WriteLine(String.Format("{0}: {1}", header.Item1, header.Item2));
                    }
                    myResponseWriter.WriteLine();
                    myResponseWriter.Flush();

                    Byte[] buffer;
                    if (response.ContentLength > 0)
                        buffer = new Byte[response.ContentLength];
                    else
                        buffer = new Byte[BUFFER_SIZE];

                    int bytesRead;

                    while ((bytesRead = responseStream.Read(buffer, 0, buffer.Length)) > 0)
                    {

                        outStream.Write(buffer, 0, bytesRead);

                    }

                    responseStream.Close();


                    outStream.Flush();

                }
                catch (Exception ex)
                { }
                finally
                {
                    responseStream.Close();
                    response.Close();
                    myResponseWriter.Close();
                }
            }

            //Write the header to console
            if (webReq.Method == "GET")
            {
                Console.WriteLine(String.Format("{0} {1} HTTP/{2}", webReq.Method, webReq.RequestUri.AbsoluteUri, webReq.ProtocolVersion));
                ShowHeader(webReq.Headers);
            }

        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
        finally
        {
            clientStreamReader.Close();
            clientStream.Close();
            outStream.Close();
        }

    }


    static List<Tuple<String, String>> ProcessResponse(HttpWebResponse response) {

        List<Tuple<String, String>> returnHeaders = new List<Tuple<String, String>>();
        foreach (String s in response.Headers.Keys)
        {
            returnHeaders.Add(new Tuple<String, String>(s, response.Headers[s]));
        }
        return returnHeaders;
    }


    static int ReadRequestHeaders(StreamReader sr, HttpWebRequest webReq) {
        String httpCmd;
        int contentLen = 0;
        do
        {
            httpCmd = sr.ReadLine();
            if (String.IsNullOrEmpty(httpCmd))
                return contentLen;
            String[] header = httpCmd.Split(new string[] { ": " }, 2, StringSplitOptions.None);
            switch (header[0].ToLower())
            {
                case "host":
                    webReq.Host = header[1];
                    break;
                case "user-agent":
                    webReq.UserAgent = header[1];
                    break;
                case "accept":
                    webReq.Accept = header[1];
                    break;
                case "referer":
                    webReq.Referer = header[1];
                    break;
                case "cookie":
                    webReq.Headers["Cookie"] = header[1];
                    break;
                case "proxy-connection":
                case "connection":
                case "keep-alive":
                    //ignoring these
                    break;
                case "content-length":
                    int.TryParse(header[1], out contentLen);
                    break;
                case "content-type":
                    webReq.ContentType = header[1];
                    break;
                case "if-modified-since":
                    String[] sb = header[1].Trim().Split(new char[] { ';' });
                    DateTime d;
                    if (DateTime.TryParse(sb[0], out d))
                        webReq.IfModifiedSince = d;
                    break;
                default:
                    try
                    {
                        webReq.Headers.Add(header[0], header[1]);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(String.Format("Could not add header {0}.  Exception message:{1}", header[0], ex.Message));
                    }
                    break;
            }
        } while (!String.IsNullOrWhiteSpace(httpCmd));
        return contentLen;
    }

    static void ShowHeader(WebHeaderCollection headers) {
        Console.WriteLine();
        int i = 0;
        foreach (String s in headers.AllKeys) {
            if (i < 7) {
                Console.WriteLine(String.Format("{0}: {1}", s, headers[s]));
                i++;
            }
        }
        Console.WriteLine();
    }

    static void Main() {


        Console.WriteLine("Enter a port number(default is 8080) : ");
        string s = Console.ReadLine();
        IPEndPoint ipep;

        if (s.Length == 0) {
            ipep = new IPEndPoint(IPAddress.Any, 8080);

        }

        else {
            ipep = new IPEndPoint(IPAddress.Any, Int32.Parse(s));
        }
        TcpListener listener = new TcpListener(ipep);

        string uri = string.Format("http://{0}:{1}/", Environment.MachineName.ToLower(), Int32.Parse(s));
        //HttpListener listener1 = new HttpListener();
        //listener1.Prefixes.Add(uri);


        try
        {
            listener.Start();
            //listener1.Start();
            Console.WriteLine("Server started ..");
            Console.WriteLine("waiting for incoming connections");

            while (true)
            {
                //Console.WriteLine("waiting for incoming connections");
                TcpClient client = listener.AcceptTcpClient();
               // HttpClient client1 = listener1.A
                //Console.WriteLine("Accepted new client connection ..");
                Thread clientthread = new Thread(process_client_request);
                clientthread.Start(client);
                //process_client_request(client);
            }
        }
        catch (Exception er) {
            Console.WriteLine(er);
        }
        finally {
            if(listener != null) {
                listener.Stop();
            }
        }
    }
}