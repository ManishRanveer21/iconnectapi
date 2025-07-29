using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BackEnd.Entities
{
    public class Chats
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

        [JsonProperty(PropertyName = "chatMessage")]
        public ChatMessage[] chatMessage { get; set; }


        public override string ToString()
        {
            return JsonConvert.SerializeObject(this);
        }
    }
}
