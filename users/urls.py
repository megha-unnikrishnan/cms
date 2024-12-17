# from django.urls import path
# from .import views

# urlpatterns=[
  
#     path('register/',views.register,name='register'),
#     path('login/', views.user_login, name='login'),
#     path('dashboard/',views.user_dashboard,name='user_dashboard')
# ]

from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import like_post,LikePostView,logout_view,comments,deletepost,update_post,PostDeleteView,post_edit_delete,fetch_posts,post_detail,PostUpdateView,CustomTokenObtainPairView, RegisterView, AdminOnlyView,LogoutView,PostListView,PostCreateView,PostDetailView,PostCommentListView,blog,register_view,login_view,admin_dashboard_view,user_dashboard_view,createpost

urlpatterns = [
    path('api/token/', CustomTokenObtainPairView.as_view(), name='get_token'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('register/', register_view, name='register_users'),
    path('login/', login_view, name='login'),
    path('admin_dashboard/',admin_dashboard_view,name='admin_dashboard_view'),
    path('user_dashboard/',user_dashboard_view,name='user_dashboard_view'),

    path('api/register/', RegisterView.as_view(), name='register'),
    path('admin-only/', AdminOnlyView.as_view(), name='admin_only'),

    path('blog/',blog,name='blog'),
    path('posts/', PostListView.as_view(), name='post-list'),
    path('posts/create/', PostCreateView.as_view(), name='post-create'),
    path('api/posts/<int:pk>/', PostDetailView.as_view(), name='post-detail'),
    # path('posts/<int:pk>/like/', PostLikeView.as_view(), name='post-like'),
    # path('posts/<int:pk>/unlike/', PostUnlikeView.as_view(), name='post-unlike'),
    path('posts/<int:pk>/comments/', PostCommentListView.as_view(), name='post-comments'),
    path('auth/logout/', LogoutView.as_view(), name='logouts'),

    path('posts/<int:id>/',post_detail, name='post_detail'),


    path('create_post/', createpost, name='postcreate'),


    path('postsblog/', fetch_posts, name='fetch_all_posts'),

    path('posts/<int:pk>/update/',PostUpdateView.as_view(),name='updateapi'),
    path('posts/<int:pk>/delete/', PostDeleteView.as_view(), name='post-delete'),

    path('updatepost/<int:pk>/', update_post, name='editpost'),

    path('delete_post/<int:pk>/', deletepost, name='delete_post'),


     path('editdelete/<int:post_id>/', post_edit_delete, name='post_edit_delete'),




     path('posts/<int:pk>/comments/', PostCommentListView.as_view(), name='post-comments'),
     path('logout/', logout_view, name='logout'), 
      path('comments/<int:pk>/', comments, name='comments'),

      path('posts/<int:post_id>/likes/', LikePostView.as_view(), name='like-post'),

      path('posts/<int:pk>/like_unlike/', like_post, name='like_unlike_post'),
]
