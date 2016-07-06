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

namespace IdentityServer3.Core.Events
{
    /// <summary>
    /// Contextual information included with every event.
    /// </summary>
    public class EventContext
    {
        /// <summary>
        /// Gets or sets the per-request activity identifier.
        /// </summary>
        /// <value>
        /// The activity identifier.
        /// </value>
        public string ActivityId { get; set; }
        
        /// <summary>
        /// Gets or sets the time stamp when the event was raised.
        /// </summary>
        /// <value>
        /// The time stamp.
        /// </value>
        public DateTimeOffset TimeStamp { get; set; }
        
        /// <summary>
        /// Gets or sets the server process identifier.
        /// </summary>
        /// <value>
        /// The process identifier.
        /// </value>
        public int ProcessId { get; set; }
        
        /// <summary>
        /// Gets or sets the name of the server machine.
        /// </summary>
        /// <value>
        /// The name of the machine.
        /// </value>
        public string MachineName { get; set; }
        
        /// <summary>
        /// Gets or sets the remote ip address of the current request.
        /// </summary>
        /// <value>
        /// The remote ip address.
        /// </value>
        public string RemoteIpAddress { get; set; }

        /// <summary>
        /// Gets or sets the subject identifier of the current user (if available).
        /// </summary>
        /// <value>
        /// The subject identifier.
        /// </value>
        public string SubjectId { get; set; }

        /// <summary>
        /// Gets or sets the browser (if any) which was used to make the request by looking at the UserAgent header
        /// </summary>
        /// <value>The browser.</value>
        public string Browser { get; set; }

        /// <summary>
        /// Gets or sets the device (if any) which was used to make the request by looking at the UserAgent header
        /// </summary>
        /// <value>The device.</value>
        public string Device { get; set; }

        /// <summary>
        /// Gets or sets the operating system which was used to make the request by looking at the UserAgent header
        /// </summary>
        /// <value>The device.</value>
        public string OperatingSystem { get; set; }
    }
}