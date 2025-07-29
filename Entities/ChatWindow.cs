using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BackEnd.Entities
{
    public class ChatWindow
    {
        [JsonProperty(PropertyName = "id")]
        public string Id
        {
            get
            {
                return chatId;
            }
        }

        [JsonProperty(PropertyName = "chatId")]
        public string chatId { get; set; }

        [JsonProperty(PropertyName = "message")]
        public string message { get; set; }

        [JsonProperty(PropertyName = "msgtime")]
        public string msgtime { get; set; }


        [JsonProperty(PropertyName = "type")]
        public string type { get; set; }

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this);
        }
    }
}
