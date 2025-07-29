using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BackEnd.Entities
{
    public class ChatList
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

        [JsonProperty(PropertyName = "toUserId")]
        public string toUserId { get; set; }

        [JsonProperty(PropertyName = "toUserName")]
        public string toUserName { get; set; }

        [JsonProperty(PropertyName = "toUserProfilePic")]
        public string toUserProfilePic { get; set; }

        [JsonProperty(PropertyName = "chatWindow")]
        public List<ChatWindow> chatWindow { get; set; }


        public override string ToString()
        {
            return JsonConvert.SerializeObject(this);
        }
    }
}
