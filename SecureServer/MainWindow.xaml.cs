using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace SecureServer
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    /// 
    public class StateObject
    {
        public SslStream sslStream = null;
        public TcpClient workSocket = null;
        public const int BufferSize = 1024;
        public byte[] buffer = new byte[BufferSize];
        public StringBuilder sb = new StringBuilder();
        public ManualResetEventSlim readwriteSync = new ManualResetEventSlim(false);
    }

    public partial class MainWindow : Window
    {

        //certificate file
        static string ServerCertificateFile = @"C:\Users\achindra\OneDrive\Signing\Gigabits.cer";
        static X509Certificate2 serverCertificate = null;
        public static ManualResetEvent allDone = new ManualResetEvent(false);
        public static Task SocketTask;
        public static TcpListener listener;
        public CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
        static int ActiveConnectionCount = 0;

        public MainWindow()
        {
            InitializeComponent();
        }

        private static bool App_CertificateValidation(Object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None) { return true; }
            if (sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors) { return true; } //we don't have a proper certificate tree

            try
            {
                X509Certificate2 ca = new X509Certificate2(ServerCertificateFile);

                X509Chain chain2 = new X509Chain();
                chain2.ChainPolicy.ExtraStore.Add(ca);

                // Check all properties
                chain2.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

                // This setup does not have revocation information
                chain2.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

                // Build the chain
                chain2.Build(new X509Certificate2(certificate));

                // Are there any failures from building the chain?
                if (chain2.ChainStatus.Length == 0)
                    return true;

                // If there is a status, verify the status is NoError
                bool result = chain2.ChainStatus[0].Status == X509ChainStatusFlags.NoError;
                //Assert(result == true);

                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }

            return false;
        }

        private void BtnStart_Click(object sender, RoutedEventArgs e)
        {
            serverCertificate = new X509Certificate2(ServerCertificateFile);

            listener = new TcpListener(IPAddress.Any, int.Parse(txtPort.Text));
            listener.Start();

            circle.Fill = Brushes.Green;
            btnStop.IsEnabled = true;
            btnStart.IsEnabled = false;

            SocketTask = new Task(() =>
            {
                while (true)
                {
                    allDone.Reset();
                    listener.BeginAcceptTcpClient(new AsyncCallback(AcceptCallback), listener);
                    allDone.WaitOne();
                    //lblActiveConnections.Content = ActiveConnectionCount.ToString();
                }
            }, cancellationTokenSource.Token);

            SocketTask.Start();
        }
        
        public static void AcceptCallback(IAsyncResult ar)
        {
            TcpListener listener = (TcpListener)ar.AsyncState;
            TcpClient client = listener.EndAcceptTcpClient(ar);
            ActiveConnectionCount++;

            allDone.Set();

            SslStream sslStream = new SslStream(client.GetStream(), false, App_CertificateValidation);
            StateObject state = new StateObject
            {
                workSocket = client,
                sslStream = sslStream
            };
            state.readwriteSync.Reset();
            sslStream.BeginAuthenticateAsServer(serverCertificate, false, SslProtocols.Tls12, false,
                                                new AsyncCallback(SslStreamBeginAuthenticateAsServer), state);
        }

        private static void SslStreamBeginAuthenticateAsServer(IAsyncResult ar)
        {
            StateObject state = (StateObject)ar.AsyncState;
            state.sslStream.EndAuthenticateAsServer(ar);

            state.sslStream.BeginRead(state.buffer, 0, StateObject.BufferSize,
                                      new AsyncCallback(SslStreamBeginRead), state);
        }

        private static void SslStreamBeginRead(IAsyncResult ar)
        {
            StateObject state = (StateObject)ar.AsyncState;
            int readData = state.sslStream.EndRead(ar);

            state.readwriteSync.Reset();

            if (readData > 0)
            {
                //Echo!
                state.sslStream.BeginWrite(state.buffer, 0, StateObject.BufferSize,
                                      new AsyncCallback(SslStreamBeginWrite), state);
                state.readwriteSync.Wait();
            }

            state.sslStream.BeginRead(state.buffer, 0, StateObject.BufferSize,
                                      new AsyncCallback(SslStreamBeginRead), state);
        }

        private static void SslStreamBeginWrite(IAsyncResult ar)
        {
            StateObject state = (StateObject)ar.AsyncState;
            state.sslStream.EndWrite(ar);
            state.readwriteSync.Set();
        }

        private void BtnStop_Click(object sender, RoutedEventArgs e)
        {
            cancellationTokenSource.Cancel();
            Thread.Sleep(1000);
            listener.Stop();
            circle.Fill = Brushes.Gray;
            btnStart.IsEnabled = true;
            btnStop.IsEnabled = false;
        }
    }
}
