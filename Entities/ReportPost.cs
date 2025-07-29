using Newtonsoft.Json;

namespace BackEnd.Entities
{
    public class ReportPost
    {
        [JsonProperty(PropertyName = "postId")]
        public string PostId { get; set; }

        [JsonProperty(PropertyName = "reportedUserId")]
        public string ReportedUserId { get; set; }

        [JsonProperty(PropertyName = "reason")]
        public string Reason { get; set; }
    }
}
