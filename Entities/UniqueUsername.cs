using Newtonsoft.Json;

namespace BackEnd.Entities
{
    public class UniqueUsername
    {

        [JsonProperty(PropertyName = "id")]
        public string Id => System.Guid.NewGuid().ToString();

        [JsonProperty(PropertyName = "userId")]
        public string UserId => "unique_username";

        [JsonProperty(PropertyName = "type")]
        public string Type => "unique_username";

        [JsonProperty(PropertyName = "username")]
        public string Username { get; set; }


    }
}
