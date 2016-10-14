/*
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

using System;

namespace IdentityServer3.Core.Models
{
    /// <summary>
    /// Class describing the context of the local authentication
    /// </summary>
    public class PasswordlessAuthenticationContext
    {
        /// <summary>
        /// Gets or sets the passworless connect code.
        /// </summary>
        /// <value>
        /// The passworless connect code.
        /// </value>
        public string PasswordlessConnectCode { get; set; }

        /// <summary>
        /// Gets or sets the type of the passwordless connect.
        /// </summary>
        /// <value>
        /// The type of the passwordless connect.
        /// </value>
        public string PasswordlessConnectType { get; set; }

        /// <summary>
        /// Gets or sets the passwordless session code.
        /// </summary>
        /// <value>
        /// The passwordless session code.
        /// </value>
        public string PasswordlessSessionCode { get; set; }

        /// <summary>
        /// Gets or sets the subjecte.
        /// </summary>
        /// <value>
        /// The subject.
        /// </value>
        public string Subject { get; set; }

        /// <summary>
        /// Gets or sets the redirect url.
        /// </summary>
        /// <value>
        /// the redirect url.
        /// </value>
        public string RedirectUrl { get; set; }
    }
}