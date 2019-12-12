using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;

namespace CertEncryptDecryptApi.Controllers
{
    [RoutePrefix("api")]
    public class DefaultController : ApiController
    {
        [Route("Encrypt/{data}")]
        [HttpGet]
        public Task<HttpResponseMessage> Encrypt([FromUri]string data)
        {
            //Encrypt / Decrypt in C# using Certificate

            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindBySerialNumber, "5d d3 c3 82", false);
            X509Certificate2 cert = certs[0];


            using (RSA rsa = cert.GetRSAPublicKey())
            {
                // OAEP allows for multiple hashing algorithms, what was formermly just "OAEP" is
                // now OAEP-SHA1.
                byte[] datab = Encoding.UTF8.GetBytes(data);
                var result = rsa.Encrypt(datab, RSAEncryptionPadding.OaepSHA1);
                return Task.FromResult<HttpResponseMessage>(Request.CreateResponse(HttpStatusCode.OK, Convert.ToBase64String(result)));
            }


        }

        [Route("Decrypt")]
        [HttpPost]
        public Task<HttpResponseMessage> Decrypt(dynamic data)
        {
            //Encrypt / Decrypt in C# using Certificate

            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindBySerialNumber, "5d d3 c3 82", false);
            X509Certificate2 cert = certs[0];

            using (RSA rsa = cert.GetRSAPrivateKey())
            {
                // OAEP allows for multiple hashing algorithms, what was formermly just "OAEP" is
                // now OAEP-SHA1.
                byte[] datab = Convert.FromBase64String((string)data.data);
                var result = rsa.Decrypt(datab, RSAEncryptionPadding.OaepSHA1);
                return Task.FromResult<HttpResponseMessage>(Request.CreateResponse(HttpStatusCode.OK, Encoding.UTF8.GetString(result)));

            }


        }
    }
}
