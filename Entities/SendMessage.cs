using Newtonsoft.Json;

namespace BackEnd.Entities
{
    public class SendMessage
    {
        [JsonProperty("chatId")]
        public string? ChatId { get; set; }

        [JsonProperty("senderId")]
        public string SenderId { get; set; }

        [JsonProperty("recipientId")]
        public string RecipientId { get; set; }

        [JsonProperty("content")]
        public string Content { get; set; }
    }
}
