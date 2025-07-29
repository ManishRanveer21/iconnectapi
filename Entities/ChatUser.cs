using Newtonsoft.Json;

namespace BackEnd.Entities
{
    public class ChatUser
    {
        [JsonProperty(PropertyName = "userId")]
        public string UserId { get; set; }

        [JsonProperty(PropertyName = "email")]
        public string Email { get; set; }

        [JsonProperty(PropertyName = "profilePicUrl")]
        public string ProfilePicUrl { get; set; }

        [JsonProperty(PropertyName = "username")]
        public string Username { get; set; }

        [JsonProperty(PropertyName = "chatId")]
        public string ChatId { get; set; }
        public DateTime TimeStamp { get; set; }
    }
}
