using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BackEnd.Entities
{
    public class LikePost
    {

        [JsonProperty(PropertyName = "postId")]
        public string PostId { get; set; }


        [JsonProperty(PropertyName = "userId")]
        public string LikeAuthorId { get; set; }

        [JsonProperty(PropertyName = "userUsername")]
        public string LikeAuthorUsername { get; set; }

        [JsonProperty(PropertyName = "userProfileUrl")]
        public string UserProfileUrl { get; set; }

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this);
        }


    }
}
