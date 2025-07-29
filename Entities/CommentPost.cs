using Newtonsoft.Json;

namespace BackEnd.Entities
{
    public class CommentPost
    {

        [JsonProperty(PropertyName = "postId")]
        public string PostId { get; set; }


        [JsonProperty(PropertyName = "userId")]
        public string CommentAuthorId { get; set; }

        [JsonProperty(PropertyName = "userUsername")]
        public string CommentAuthorUsername { get; set; }

        [JsonProperty(PropertyName = "userProfileUrl")]
        public string UserProfileUrl { get; set; }


        [JsonProperty(PropertyName = "content")]
        public string CommentContent { get; set; }

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this);
        }
    }
}
