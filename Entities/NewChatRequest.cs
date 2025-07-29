using Newtonsoft.Json;

namespace BackEnd.Entities
{
    public class NewChatRequest
    {
        [JsonProperty("senderId")]
        public string SenderId { get; set; }

        [JsonProperty("recipientId")]
        public string RecipientId { get; set; }

        [JsonProperty("content")]
        public string Content { get; set; }
    }
}
