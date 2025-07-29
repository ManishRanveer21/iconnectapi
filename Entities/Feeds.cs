using System.Text.Json.Serialization;

namespace BackEnd.Entities
{
    public class Feed
    {
        [JsonPropertyName("id")]
        public string id { get; set; } = string.Empty;

        [JsonPropertyName("userId")]
        public string UserId { get; set; } = string.Empty;

        [JsonPropertyName("profilePic")]
        public string ProfilePic { get; set; } = string.Empty;

        [JsonPropertyName("feedUrl")]
        public string FeedUrl { get; set; } = string.Empty;

        [JsonPropertyName("description")]
        public string Description { get; set; } = string.Empty;

        [JsonPropertyName("contentType")]
        public string ContentType { get; set; } = string.Empty;

        [JsonPropertyName("fileSize")]
        public long FileSize { get; set; }

        [JsonPropertyName("uploadDate")]
        public DateTime UploadDate { get; set; }
    }
}
