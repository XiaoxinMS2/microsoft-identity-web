// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Identity.Abstractions;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web.Test.Common.Mocks;
using Microsoft.Identity.Web.TestOnly;
using Xunit;

namespace Microsoft.Identity.Web.Test
{
    /// <summary>
    /// Unit tests for vanilla dSTS (Dedicated Security Token Service) scenarios in Microsoft.Identity.Web.
    ///
    /// Vanilla dSTS uses a different authority format than AAD/Entra ID (eSTS), and must:
    ///   1. Skip the AAD instance discovery call (login.microsoftonline.com/common/discovery/instance).
    ///   2. POST the client credentials grant directly to the dSTS token endpoint:
    ///      https://{host}/dstsv2/{tenantGuid}/oauth2/v2.0/token
    ///   3. Send <c>x5c</c> in the client_assertion JWT header when <c>SendX5C=true</c>
    ///      (required for dSTS certificate-based authentication).
    ///
    /// These tests use the existing <see cref="MockHttpClientFactory"/> infrastructure to mock
    /// the dSTS token endpoint, so no network/Key Vault/real certificate is required and the
    /// tests can run in any CI environment.
    /// </summary>
    [Collection(nameof(TokenAcquirerFactorySingletonProtection))]
    public class DstsTokenAcquisitionTests
    {
        // Vanilla dSTS authority format: https://{host}/dstsv2/{tenantGuid}
        private const string DstsHost = "co2agg04-passive-dsts.dsts.core.azure-test.net";
        private const string DstsTenantId = "7a433bfc-2514-4697-b467-e0933190487f";
        private const string DstsAuthority = "https://" + DstsHost + "/dstsv2/" + DstsTenantId;
        private const string DstsTokenEndpoint = DstsAuthority + "/oauth2/v2.0/token";
        private const string DstsClientId = "8af3ec05-4d5b-4c0f-9c9a-3c6d3a3b2a6e";
        private const string DstsScope = "https://dsts.core.azure-test.net/.default";

        /// <summary>
        /// Verifies that for a vanilla dSTS authority Id.Web/MSAL POSTs the client_credentials
        /// grant to the dSTS token endpoint (and not to the AAD eSTS endpoint).
        /// Uses <see cref="MockHttpMessageHandler.ExpectedUrl"/> to lock the endpoint.
        /// </summary>
        [Fact]
        public async Task GetAccessTokenForApp_DstsAuthority_PostsToDstsTokenEndpointAsync()
        {
            // Arrange
            var tokenAcquirerFactory = InitDstsTokenAcquirerFactoryWithSecret();
            IServiceProvider serviceProvider = tokenAcquirerFactory.Build();
            var mockHttpClient = serviceProvider.GetRequiredService<IMsalHttpClientFactory>() as MockHttpClientFactory;

            var tokenHandler = MockHttpCreator.CreateClientCredentialTokenHandler();
            tokenHandler.ExpectedUrl = DstsTokenEndpoint;
            mockHttpClient!.AddMockHandler(tokenHandler);

            IAuthorizationHeaderProvider authorizationHeaderProvider =
                serviceProvider.GetRequiredService<IAuthorizationHeaderProvider>();

            // Act
            string result = await authorizationHeaderProvider.CreateAuthorizationHeaderForAppAsync(DstsScope);

            // Assert
            Assert.Equal("Bearer header.payload.signature", result);
            Assert.NotNull(tokenHandler.ActualRequestMessage);
            Assert.Equal(HttpMethod.Post, tokenHandler.ActualRequestMessage.Method);
            Assert.NotNull(tokenHandler.ActualRequestMessage.RequestUri);
            Assert.Equal(DstsTokenEndpoint, tokenHandler.ActualRequestMessage.RequestUri!.GetLeftPart(UriPartial.Path));
        }

        /// <summary>
        /// Verifies that the client_credentials grant body sent to dSTS contains the expected
        /// parameters (grant_type, scope, client_id, client_secret).
        /// </summary>
        [Fact]
        public async Task GetAccessTokenForApp_DstsAuthority_SendsClientCredentialsGrantAsync()
        {
            // Arrange
            var tokenAcquirerFactory = InitDstsTokenAcquirerFactoryWithSecret();
            IServiceProvider serviceProvider = tokenAcquirerFactory.Build();
            var mockHttpClient = serviceProvider.GetRequiredService<IMsalHttpClientFactory>() as MockHttpClientFactory;

            mockHttpClient!.AddMockHandler(MockHttpCreator.CreateHandlerToValidatePostData(
                HttpMethod.Post,
                new Dictionary<string, string>
                {
                    { "grant_type", "client_credentials" },
                    { "scope", DstsScope },
                    { "client_id", DstsClientId },
                    { "client_secret", "someSecret" },
                }));

            IAuthorizationHeaderProvider authorizationHeaderProvider =
                serviceProvider.GetRequiredService<IAuthorizationHeaderProvider>();

            // Act
            string result = await authorizationHeaderProvider.CreateAuthorizationHeaderForAppAsync(DstsScope);

            // Assert - if any expected POST field were missing or different, MockHttpMessageHandler
            // would have failed inside SendAsync via Assert.Equal/Assert.True.
            Assert.Equal("Bearer header.payload.signature", result);
        }

        /// <summary>
        /// Verifies that two consecutive token acquisitions for the same dSTS scope only hit the
        /// dSTS token endpoint once (i.e. the second call is served from MSAL's app token cache).
        /// We register exactly one mock handler — if MSAL tried to call dSTS a second time, the
        /// queue would be empty and the request would throw.
        /// </summary>
        [Fact]
        public async Task GetAccessTokenForApp_DstsAuthority_SecondCallUsesCacheAsync()
        {
            // Arrange
            var tokenAcquirerFactory = InitDstsTokenAcquirerFactoryWithSecret();
            IServiceProvider serviceProvider = tokenAcquirerFactory.Build();
            var mockHttpClient = serviceProvider.GetRequiredService<IMsalHttpClientFactory>() as MockHttpClientFactory;

            // Register exactly ONE token-endpoint handler.
            mockHttpClient!.AddMockHandler(MockHttpCreator.CreateClientCredentialTokenHandler());

            IAuthorizationHeaderProvider authorizationHeaderProvider =
                serviceProvider.GetRequiredService<IAuthorizationHeaderProvider>();

            // Act - first call hits dSTS, second call should be a cache hit.
            string first = await authorizationHeaderProvider.CreateAuthorizationHeaderForAppAsync(DstsScope);
            string second = await authorizationHeaderProvider.CreateAuthorizationHeaderForAppAsync(DstsScope);

            // Assert
            Assert.Equal("Bearer header.payload.signature", first);
            Assert.Equal(first, second);
            // MockHttpClientFactory.Dispose asserts the queue is empty — i.e. the single handler
            // was consumed exactly once, proving the second call did not hit the network.
        }

        /// <summary>
        /// Verifies that when the dSTS token endpoint returns an OAuth2 error, Id.Web surfaces it
        /// as <see cref="MsalServiceException"/>.
        /// </summary>
        [Fact]
        public async Task GetAccessTokenForApp_DstsAuthority_TokenEndpointError_ThrowsMsalServiceExceptionAsync()
        {
            // Arrange
            var tokenAcquirerFactory = InitDstsTokenAcquirerFactoryWithSecret();
            IServiceProvider serviceProvider = tokenAcquirerFactory.Build();
            var mockHttpClient = serviceProvider.GetRequiredService<IMsalHttpClientFactory>() as MockHttpClientFactory;

            const string errorBody =
                "{\"error\":\"invalid_scope\"," +
                "\"error_description\":\"The scope is not valid for the dSTS resource.\"}";

            mockHttpClient!.AddMockHandler(new MockHttpMessageHandler
            {
                ExpectedMethod = HttpMethod.Post,
                ResponseMessage = new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent(errorBody),
                },
            });

            IAuthorizationHeaderProvider authorizationHeaderProvider =
                serviceProvider.GetRequiredService<IAuthorizationHeaderProvider>();

            // Act & Assert
            var ex = await Assert.ThrowsAsync<MsalServiceException>(
                async () => await authorizationHeaderProvider.CreateAuthorizationHeaderForAppAsync(DstsScope));

            Assert.Equal("invalid_scope", ex.ErrorCode);
        }

        /// <summary>
        /// Verifies that when a dSTS app is configured with a certificate credential and
        /// <see cref="MicrosoftIdentityApplicationOptions.SendX5C"/> is true, the JWT client_assertion
        /// header sent to the dSTS token endpoint includes the <c>x5c</c> claim. This is required
        /// for dSTS to validate the certificate chain.
        /// </summary>
        [Fact]
        public async Task GetAccessTokenForApp_DstsAuthority_WithCertificateAndSendX5C_IncludesX5CHeaderAsync()
        {
            // Arrange
            var tokenAcquirerFactory = InitDstsTokenAcquirerFactoryWithCertificate(sendX5C: true);
            IServiceProvider serviceProvider = tokenAcquirerFactory.Build();
            var mockHttpClient = serviceProvider.GetRequiredService<IMsalHttpClientFactory>() as MockHttpClientFactory;

            var tokenHandler = MockHttpCreator.CreateClientCredentialTokenHandler();
            mockHttpClient!.AddMockHandler(tokenHandler);

            IAuthorizationHeaderProvider authorizationHeaderProvider =
                serviceProvider.GetRequiredService<IAuthorizationHeaderProvider>();

            // Act
            string result = await authorizationHeaderProvider.CreateAuthorizationHeaderForAppAsync(DstsScope);

            // Assert
            Assert.Equal("Bearer header.payload.signature", result);
            Assert.NotNull(tokenHandler.ActualRequestPostData);

            // dSTS certificate auth uses client_assertion (JWT signed by the cert).
            Assert.True(tokenHandler.ActualRequestPostData.ContainsKey("client_assertion"),
                "Expected client_assertion in the POST body for certificate-based dSTS auth.");
            Assert.Equal(
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                tokenHandler.ActualRequestPostData["client_assertion_type"]);

            string clientAssertion = tokenHandler.ActualRequestPostData["client_assertion"];
            string jwtHeader = DecodeJwtHeader(clientAssertion);

            // SendX5C=true must propagate the x5c chain into the JWT header.
            Assert.Contains("\"x5c\"", jwtHeader, StringComparison.Ordinal);
        }

        /// <summary>
        /// Negative counterpart to the previous test: when SendX5C=false, the JWT header
        /// must NOT contain the x5c chain (only x5t/kid).
        /// </summary>
        [Fact]
        public async Task GetAccessTokenForApp_DstsAuthority_WithCertificateAndNoSendX5C_OmitsX5CHeaderAsync()
        {
            // Arrange
            var tokenAcquirerFactory = InitDstsTokenAcquirerFactoryWithCertificate(sendX5C: false);
            IServiceProvider serviceProvider = tokenAcquirerFactory.Build();
            var mockHttpClient = serviceProvider.GetRequiredService<IMsalHttpClientFactory>() as MockHttpClientFactory;

            var tokenHandler = MockHttpCreator.CreateClientCredentialTokenHandler();
            mockHttpClient!.AddMockHandler(tokenHandler);

            IAuthorizationHeaderProvider authorizationHeaderProvider =
                serviceProvider.GetRequiredService<IAuthorizationHeaderProvider>();

            // Act
            string result = await authorizationHeaderProvider.CreateAuthorizationHeaderForAppAsync(DstsScope);

            // Assert
            Assert.Equal("Bearer header.payload.signature", result);
            Assert.NotNull(tokenHandler.ActualRequestPostData);
            Assert.True(tokenHandler.ActualRequestPostData.ContainsKey("client_assertion"));

            string clientAssertion = tokenHandler.ActualRequestPostData["client_assertion"];
            string jwtHeader = DecodeJwtHeader(clientAssertion);

            Assert.DoesNotContain("\"x5c\"", jwtHeader, StringComparison.Ordinal);
        }

        // ---- helpers ----

        /// <summary>
        /// Builds a <see cref="TokenAcquirerFactory"/> configured for vanilla dSTS, using the
        /// full dSTS Authority (no Instance/TenantId split since dSTS authorities don't follow
        /// the AAD <c>Instance + TenantId</c> convention) and a client secret.
        /// </summary>
        private static TokenAcquirerFactory InitDstsTokenAcquirerFactoryWithSecret()
        {
            TokenAcquirerFactoryTesting.ResetTokenAcquirerFactoryInTest();
            TokenAcquirerFactory tokenAcquirerFactory = TokenAcquirerFactory.GetDefaultInstance();
            tokenAcquirerFactory.Services.Configure<MicrosoftIdentityApplicationOptions>(options =>
            {
                options.Authority = DstsAuthority;
                options.ClientId = DstsClientId;
                options.ClientCredentials = new[]
                {
                    new CredentialDescription
                    {
                        SourceType = CredentialSource.ClientSecret,
                        ClientSecret = "someSecret",
                    },
                };
            });

            tokenAcquirerFactory.Services.AddSingleton<IMsalHttpClientFactory, MockHttpClientFactory>();

            return tokenAcquirerFactory;
        }

        /// <summary>
        /// Builds a <see cref="TokenAcquirerFactory"/> configured for vanilla dSTS with a
        /// (self-signed) certificate credential. The mock HTTP handler does not validate the
        /// certificate, so a self-signed cert is sufficient for unit tests.
        /// </summary>
        private static TokenAcquirerFactory InitDstsTokenAcquirerFactoryWithCertificate(bool sendX5C)
        {
            TokenAcquirerFactoryTesting.ResetTokenAcquirerFactoryInTest();
            TokenAcquirerFactory tokenAcquirerFactory = TokenAcquirerFactory.GetDefaultInstance();
            tokenAcquirerFactory.Services.Configure<MicrosoftIdentityApplicationOptions>(options =>
            {
                options.Authority = DstsAuthority;
                options.ClientId = DstsClientId;
                options.SendX5C = sendX5C;
                options.ClientCredentials = new[]
                {
                    CertificateDescription.FromCertificate(CreateTestCertificate()),
                };
            });

            tokenAcquirerFactory.Services.AddSingleton<IMsalHttpClientFactory, MockHttpClientFactory>();

            return tokenAcquirerFactory;
        }

        /// <summary>
        /// Creates a transient self-signed certificate for unit tests. The mock HTTP handler does
        /// not perform any cryptographic validation against dSTS, so a throwaway cert is fine.
        /// </summary>
        private static X509Certificate2 CreateTestCertificate()
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest(
                "CN=DstsUnitTest",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            return request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(365));
        }

        /// <summary>
        /// Decodes the (base64url-encoded) header of a JWT and returns it as a UTF-8 JSON string.
        /// </summary>
        private static string DecodeJwtHeader(string jwt)
        {
            var parts = jwt.Split('.');
            if (parts.Length < 2)
            {
                return string.Empty;
            }

            string base64 = parts[0].Replace('-', '+').Replace('_', '/');
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }

            return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(base64));
        }
    }
}