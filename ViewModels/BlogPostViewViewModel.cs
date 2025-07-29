using BackEnd.Entities;
using System.Collections.Generic;

namespace BackEnd.ViewModels
{
    public class BlogPostViewViewModel
    {
        public string PostId { get; set; }

        public string Title { get; set; }

        public string Content { get; set; }

        public int CommentCount { get; set; }

        public bool UserLikedPost { get; set; }
        public int LikeCount { get; set; }

        public string AuthorId { get; set; }
        public string AuthorUsername { get; set; }

        public List<UserPostComment> Comments { get; set; }

    }
}
