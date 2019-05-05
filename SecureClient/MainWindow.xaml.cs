using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
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

namespace SecureClient
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
        //public ManualResetEventSlim readwriteSync = new ManualResetEventSlim(false);
    }

    public partial class MainWindow : Window
    {
        static CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
        static string ServerCertificateFile = @"C:\Users\achindra\OneDrive\Signing\Gigabits.cer";
        static X509Certificate2 serverCertificate = null;
        static TcpClient client = null;
        static StateObject state = null;

        public MainWindow()
        {
            InitializeComponent();
        }

        private void BtnConnect_Click(object sender, RoutedEventArgs e)
        {
            serverCertificate = new X509Certificate2(ServerCertificateFile);

            client = new TcpClient(txtIP.Text, int.Parse(txtPort.Text));
            circle.Fill = Brushes.Green;
            btnDisconnect.IsEnabled = true;
            BtnSend.IsEnabled = true;
            btnConnect.IsEnabled = false;

            X509Store store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            X509Certificate2 certificate1;
            try
            {
                certificate1 = new X509Certificate2(ServerCertificateFile);
            }
            catch (Exception)
            {
                throw new Exception("Error loading SSL certificate file." + Environment.NewLine + ServerCertificateFile);
            }

            store.Add(certificate1);
            store.Close();

            SslStream sslStream = new SslStream(client.GetStream(), false, App_CertificateValidation);
            state = new StateObject
            {
                workSocket = client,
                sslStream = sslStream
            };
            sslStream.BeginAuthenticateAsClient("ACHINDRA BHATNAGAR", new AsyncCallback(sslStreamAuthAsClientCallback), state);
        }

        private void sslStreamAuthAsClientCallback(IAsyncResult ar)
        {
            StateObject state = (StateObject)ar.AsyncState;
            state.sslStream.EndAuthenticateAsClient(ar);

            Task SocketTask = new Task(() =>
            {
                state.sslStream.BeginRead(state.buffer, 0, StateObject.BufferSize,
                                          new AsyncCallback(SslStreamBeginRead), state);

            }, cancellationTokenSource.Token);
            SocketTask.Start();
        }

        private void SslStreamBeginRead(IAsyncResult ar)
        {
            StateObject state = (StateObject)ar.AsyncState;
            int readData = state.sslStream.EndRead(ar);

            if (readData > 0)
            {
                //Echo!
                TxtChatBlock.Text = readData + "\n" + TxtChatBlock.Text;
            }

            state.sslStream.BeginRead(state.buffer, 0, StateObject.BufferSize,
                                      new AsyncCallback(SslStreamBeginRead), state);
        }

        private bool App_CertificateValidation(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
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

        private void BtnDisconnect_Click(object sender, RoutedEventArgs e)
        {
            cancellationTokenSource.Cancel();
            Thread.Sleep(1000);
            client.Close();
            circle.Fill = Brushes.Gray;
            btnConnect.IsEnabled = true;
            BtnSend.IsEnabled = false;
            btnDisconnect.IsEnabled = false;
        }

        private void BtnSend_Click(object sender, RoutedEventArgs e)
        {
            state.sslStream.Write(Encoding.UTF8.GetBytes(TxtMessage.Text));
            TxtMessage.Text = "";
        }
    }
}
