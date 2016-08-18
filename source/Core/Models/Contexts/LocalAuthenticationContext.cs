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

using IdentityServer3.Core.Extensions;

namespace IdentityServer3.Core.Models
{
    /// <summary>
    /// Class describing the context of the local authentication
    /// </summary>
    public class LocalAuthenticationContext
    {
        /// <summary>
        /// Gets or sets the name of the user.
        /// </summary>
        /// <value>
        /// The name of the user.
        /// </value>
        public string UserName { get; set; }

        /// <summary>
        /// Gets or sets the password.
        /// </summary>
        /// <value>
        /// The password.
        /// </value>
        public string Password { get; set; }

        /// <summary>
        /// Gets or sets the sign in message.
        /// </summary>
        /// <value>
        /// The sign in message.
        /// </value>
        public SignInMessage SignInMessage { get; set; }

        /// <summary>
        /// Gets or sets the authenticate result.
        /// </summary>
        /// <value>
        /// The authenticate result.
        /// </value>
        public AuthenticateResult AuthenticateResult { get; set; }

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
        /// Gets a value indicating whether this instance is passwordless.
        /// </summary>
        /// <value>
        /// <c>true</c> if this instance is passwordless; otherwise, <c>false</c>.
        /// </value>
        public bool IsPasswordless
        {
            get
            {
                return Password.IsMissing() && UserName.IsMissing() && 
                    PasswordlessConnectType.IsPresent();
            }
        }
    }
}