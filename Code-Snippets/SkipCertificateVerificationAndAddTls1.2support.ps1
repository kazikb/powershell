# Pominięcie weryfikacji certyfikatu serwera
add-type @'
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    using System.Net.Security;
    public class TrustAllCerts {
      public static bool ValidateServerCertificate(
        object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors)
      {
        return true;
      }

      public static RemoteCertificateValidationCallback TrustAllCertsCallback = new RemoteCertificateValidationCallback(ValidateServerCertificate);
    }
'@
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = [TrustAllCerts]::TrustAllCertsCallback

# TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
