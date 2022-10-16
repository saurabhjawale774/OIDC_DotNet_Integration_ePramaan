﻿using System;
using System.Web.Mvc;
using System.Text;
using System.Security.Cryptography;
using IdentityModel;
using RestSharp;
using System.Text.Json;
using System.Security.Cryptography.X509Certificates;

namespace OIDC_DOT_NET_INTEGRATION_PRODUCTION.Controllers
{
    public class EpramaanController : Controller
    {
        public static readonly string scope = "openid";
        public static readonly string response_type = "code";
        public static readonly string code_challenge_method = "S256";
        public static readonly string grant_type = "authorization_code";

        public static readonly string auth_grant_request_uri = "https://epramaan.meripehchaan.gov.in/openid/jwt/processJwtAuthGrantRequest.do";
        public static readonly string token_request_uri = "https://epramaan.meripehchaan.gov.in/openid/jwt/processJwtTokenRequest.do";

        public static readonly string client_id = "100001050";
        public static readonly string aeskey = "cb3a59f6-0617-4898-b859-8bb02fee91b3";
        public static readonly string redirect_uri = "http://localhost:44355/Epramaan/ProcessAuthCodeAndGetToken";
        public static readonly string Certificate = "D:/CDAC_MUMBAI_code/ePramaanIntegration_DotNet/OidcDotNetProductionEPramaan/OidcDotNetProduction/epramaanprod2016.cer";

        public static string codeVerifier;
        public static string stateID;
        public static string nonce;

        public ActionResult LoginUsingEpramaan()
        {
            stateID = Guid.NewGuid().ToString();                //Must be unique and create new for each request
            nonce = CryptoRandom.CreateUniqueId(16);            //Create new randomly generated 16 characters string for every request
            codeVerifier = CryptoRandom.CreateUniqueId(64);     //Create new randomly generated 64 characters string for every request

            //Create new Code Challenge with the code Verifier for every request
            string code_challenge;
            using (var sha256 = SHA256.Create())
            {
                var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                code_challenge = IdentityModel.Base64Url.Encode(challengeBytes);
            }

            string inputvalue = client_id + aeskey + stateID + nonce + redirect_uri + scope + code_challenge;

            //HMAC SHA256 of queryString 
            string apiHmac = hashHMACHex(inputvalue, aeskey);
            ViewBag.finalUrl = auth_grant_request_uri + "?&scope=" + scope + "&response_type=" + response_type + "&redirect_uri=" + redirect_uri + "&state=" + stateID + "&code_challenge_method=" + code_challenge_method + "&nonce=" + nonce + "&client_id=" + client_id + "&code_challenge=" + code_challenge + "&request_uri=" + auth_grant_request_uri + "&apiHmac=" + apiHmac;
            return View();
        }
        private string hashHMACHex(string message, string secret)
        {
            secret = secret ?? "";
            var encoding = new System.Text.ASCIIEncoding();
            byte[] keyByte = encoding.GetBytes(secret);
            byte[] messageBytes = encoding.GetBytes(message);
            using (var hmacsha256 = new HMACSHA256(keyByte))
            {
                byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
                return Convert.ToBase64String(hashmessage);
            }
        }

        [HttpPost]
        public ActionResult ProcessAuthCodeAndGetToken(string code, string state)
        {
            string authCode = code;
            var client = new RestClient(token_request_uri);         //install NuGet package "RestSharp", version must be <=106.0.0
            var request = new RestSharp.RestRequest(Method.POST);
            request.AddHeader("Content-Type", "application/json");
            var body = "{\"code\":[\"" + authCode + "\"],\"grant_type\":[\"" + grant_type + "\"],\"scope\":[\"" + scope + "\"],\"redirect_uri\":[\"" + auth_grant_request_uri + "\"],\"request_uri\":[\"" + redirect_uri + "\"],\"code_verifier\":[\"" + codeVerifier + "\"],\"client_id\":[\"" + client_id + "\"]}";
            request.AddParameter("application/json", body, ParameterType.RequestBody);
            IRestResponse response = client.Execute(request);
            string jwtToken = response.Content;

            //Create secretKey_byte using user defined generateAES256Key methode
            byte[] secretKey_byte = generateAES256Key(nonce);
            var decryptedToken = Jose.JWT.Decode(jwtToken, secretKey_byte);         //install Nuget Package "jose-jwt"
            X509Certificate2 cert = new X509Certificate2(Certificate);
            RSACryptoServiceProvider csp = (RSACryptoServiceProvider)cert.PublicKey.Key;
            string json = Jose.JWT.Decode(decryptedToken, csp);
            ViewBag.json = json;

            JsonDocument jsonDocument = JsonDocument.Parse(json);
            JsonElement root = jsonDocument.RootElement;
            ViewBag.name = root.GetProperty("name");
            ViewBag.username = root.GetProperty("username");
            ViewBag.mobile_number = root.GetProperty("mobile_number");

            try
            {
                ViewBag.aadhaar_ref_no = root.GetProperty("aadhaar_ref_no");
                ViewBag.state = root.GetProperty("state");
            }
            catch (Exception e)
            {
                ViewBag.aadhaar_ref_no = "Aadhar number is not verified";
                ViewBag.state = "Complete your KYC to get address";
            }

            return View();
        }

        public byte[] generateAES256Key(string seed)
        {
            SHA256 sha256 = SHA256CryptoServiceProvider.Create();
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(seed));
        }


    }
}