using Newtonsoft.Json;

namespace BackEnd.Entities
{
    public class ReportedPost
    {
        [JsonProperty(PropertyName = "id")]
        public string Id { get; set; }

        [JsonProperty(PropertyName = "type")]
        public string Type
        {
            get
            {
                return "reported post";
            }
        }

        [JsonProperty(PropertyName = "postId")]
        public string PostId { get; set; }

        [JsonProperty(PropertyName = "reportedUserId")]
        public string ReportedUserId { get; set; }

        [JsonProperty(PropertyName = "reason")]
        public string Reason { get; set; }

        [JsonProperty(PropertyName = "reportedOn")]
        public DateTime ReportedOn { get; set; }
    }
}
