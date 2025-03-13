using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace TcpTlsProxy
{
    /// <summary>
    /// Configuration class for the TCP/TLS proxy
    /// </summary>
    public class ProxyConfig
    {
        /// <summary>
        /// Listener address (e.g. "0.0.0.0:8080")
        /// </summary>
        public string ListenerAddress { get; set; } = "0.0.0.0:8080";
        
        /// <summary>
        /// Target address (e.g. "example.com:443")
        /// </summary>
        public string TargetAddress { get; set; } = "www.google.com:443";
        
        /// <summary>
        /// Enable TLS for client-to-proxy connection
        /// </summary>
        public bool ClientTls { get; set; } = false;
        
        /// <summary>
        /// Server certificate subject name to use from Windows certificate store
        /// </summary>
        public string ServerCertSubject { get; set; } = "";
        
        /// <summary>
        /// Windows certificate store location for server certificate
        /// </summary>
        public StoreLocation ServerCertStoreLocation { get; set; } = StoreLocation.CurrentUser;
        
        /// <summary>
        /// Windows certificate store name for server certificate
        /// </summary>
        public StoreName ServerCertStoreName { get; set; } = StoreName.My;
        
        /// <summary>
        /// Enable client authentication
        /// </summary>
        public bool ClientAuth { get; set; } = false;
        
        /// <summary>
        /// CA certificate subject name to use from Windows certificate store
        /// </summary>
        public string CACertSubject { get; set; } = "";
        
        /// <summary>
        /// Windows certificate store location for CA certificate
        /// </summary>
        public StoreLocation CACertStoreLocation { get; set; } = StoreLocation.CurrentUser;
        
        /// <summary>
        /// Windows certificate store name for CA certificate
        /// </summary>
        public StoreName CACertStoreName { get; set; } = StoreName.Root;
        
        /// <summary>
        /// Enable TLS for proxy-to-target connection
        /// </summary>
        public bool TargetTls { get; set; } = true;
        
        /// <summary>
        /// Client certificate subject name to use from Windows certificate store
        /// </summary>
        public string ClientCertSubject { get; set; } = "";
        
        /// <summary>
        /// Windows certificate store location for client certificate
        /// </summary>
        public StoreLocation ClientCertStoreLocation { get; set; } = StoreLocation.CurrentUser;
        
        /// <summary>
        /// Windows certificate store name for client certificate
        /// </summary>
        public StoreName ClientCertStoreName { get; set; } = StoreName.My;
        
        /// <summary>
        /// Skip verification of target server TLS certificates
        /// </summary>
        public bool InsecureSkipVerify { get; set; } = true;
        
        /// <summary>
        /// Timeout for establishing connection to target (milliseconds)
        /// </summary>
        public int DialTimeout { get; set; } = 30000;
        
        /// <summary>
        /// For HTTP CONNECT proxy: override target with the one in CONNECT
        /// </summary>
        public bool OverrideTargetForCONNECT { get; set; } = false;
        
        /// <summary>
        /// Cache for client-side TLS certificate
        /// </summary>
        internal X509Certificate2? ServerCertificate { get; set; }
        
        /// <summary>
        /// Cache for target-side client certificate
        /// </summary>
        internal X509Certificate2? ClientCertificate { get; set; }
        
        /// <summary>
        /// Cache for CA certificate
        /// </summary>
        internal X509Certificate2? CACertificate { get; set; }
        
        /// <summary>
        /// Validation callback for client certificates
        /// </summary>
        internal RemoteCertificateValidationCallback? ClientCertValidationCallback { get; set; }
        
        /// <summary>
        /// Validation callback for target server certificates
        /// </summary>
        internal RemoteCertificateValidationCallback? ServerCertValidationCallback { get; set; }
    }
} 