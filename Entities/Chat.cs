using Newtonsoft.Json;

namespace BackEnd.Entities
{
    public class Chat
    {
        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("senderId")]
        public string SenderId { get; set; }

        [JsonProperty("recipientId")]
        public string RecipientId { get; set; }

        [JsonProperty("timestamp")]
        public DateTime Timestamp { get; set; }
    }
}
