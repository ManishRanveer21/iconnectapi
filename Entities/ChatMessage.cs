using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BackEnd.Entities
{
    public class ChatMessage
    {

        [JsonProperty(PropertyName = "messageId")]
        public string messageId { get; set; }

        [JsonProperty(PropertyName = "fromuserId")]
        public string fromuserId { get; set; }

        [JsonProperty(PropertyName = "touserId")]
        public string touserId { get; set; }

        [JsonProperty(PropertyName = "message")]
        public string message { get; set; }

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this);
        }
    }
}
