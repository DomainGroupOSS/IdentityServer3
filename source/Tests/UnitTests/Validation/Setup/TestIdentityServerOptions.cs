﻿/*
 * Copyright 2014, 2015 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using IdentityServer3.Core.Configuration;

namespace IdentityServer3.Tests.Validation
{
    class TestIdentityServerOptions
    {
        public static IdentityServerOptions Create()
        {
            var options = new IdentityServerOptions
            {
                IssuerUri = "https://idsrv3.com",
                SiteName = "IdentityServer3 - test",
                DataProtector = new NoDataProtector(),
            };

            options.SigningCertificate = TestCert.Load();

            options.AuthenticationOptions.CookieOptions.TwoFactorSessionKey =
                    "9F797F9585E55F2DBE7B5C5F77C6D23216AD8E1679EB38F17E7B83330BCF0452BBE29C6D2F8EC97747057DA4207D33240592E65EBAA8EB9DC4A6736137D9C0C7";

            return options;
        }
    }
}