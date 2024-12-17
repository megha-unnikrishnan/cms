from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from users.models import CustomUser
from .serializers import RegularUserSerializer,UserEditSerializer
import requests
from django.shortcuts import render, redirect
from rest_framework import status
from rest_framework.permissions import IsAdminUser 
from django.shortcuts import get_object_or_404
from django.contrib import messages

class RegularUserListView(APIView):
    permission_classes = [IsAuthenticated] 
    def get(self, request):
        regular_users = CustomUser.objects.filter(is_staff=False)
        serializer = RegularUserSerializer(regular_users, many=True)     
        return Response(serializer.data)




def regular_users_view(request):
    api_url = "https://cmsblogpos-50c60a279bb0.herokuapp.com/admin_view/regular-users/"
    access_token = request.session.get("access_token")
    if not access_token:
        return redirect("login_view") 
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    try:
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200: 
            users = response.json() 
            print("userslist",users)
            return render(request, "admin/userslistadmin.html", {"users": users})
        else:
            errors = response.json()
            return render(request, "admin/userslistadmin.html", {"errors": errors})
    except requests.exceptions.RequestException as e:
        print("API request failed:", e)
        return render(request, "adminv/userslistadmin.html", {"errors": {"non_field_errors": ["Something went wrong."]}})
    



class EditUserView(APIView):
    permission_classes = [IsAuthenticated]
    def get_object(self, pk):
        try:
            return CustomUser.objects.get(pk=pk)
        except CustomUser.DoesNotExist:
            return None

    def get(self, request, pk):
        user = self.get_object(pk)
        if user is None:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = UserEditSerializer(user)
        return Response(serializer.data)

    def put(self, request, pk):
        user = self.get_object(pk)
        if user is None:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        serializer = UserEditSerializer(user, data=request.data, partial=False)  # Use `partial=True` for partial updates
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        user = self.get_object(pk)
        if user is None:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = UserEditSerializer(user, data=request.data, partial=True)  
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

def edit_user(request, id):
    api_url = f"https://cmsblogpos-50c60a279bb0.herokuapp.com/admin_view/edit-user/{id}/"  
    access_token = request.session.get('access_token')

    if request.method == 'GET':
        headers = {'Authorization': f'Bearer {access_token}'}
        try:
            response = requests.get(api_url, headers=headers)
            if response.status_code == 200:
                user_data = response.json()
                return render(request, 'admin/edit_user.html', {'user': user_data})
            else:
                return redirect('regular_users_view')
        except requests.exceptions.RequestException as e:
            print("API request failed:", e)
            return render(request, 'admin/edit_user.html', {'errors': {"non_field_errors": ["Something went wrong."]}})

    if request.method in ['POST', 'PUT', 'PATCH']:
        headers = {'Authorization': f'Bearer {access_token}'}
        form_data = {
            "full_name": request.POST.get("full_name"),
            "email": request.POST.get("email"),
             "phone": request.POST.get("phone"),
              "profile_picture": request.POST.get("profile_picture"),
        }

        print('formdata', form_data)

        try:
            if request.method == 'POST':
                response = requests.put(api_url, headers=headers, data=form_data, files={'profile_picture': request.FILES.get("profile_picture")})
            else:
                response = requests.patch(api_url, headers=headers, data=form_data, files={'profile_picture': request.FILES.get("profile_picture")})

            if response.status_code == 200:
                return redirect('regular_users_view')
            else:
                print('Error response:', response.json())
                return render(request, 'admin/edit_user.html', {'errors': response.json()})
        except requests.exceptions.RequestException as e:
            print("API request failed:", e)
            return render(request, 'admin/edit_user.html', {'errors': {"non_field_errors": ["Something went wrong."]}})
        



class AdminToggleActiveStatusView(APIView):
    def patch(self, request, id):
        user = get_object_or_404(CustomUser, id=id)
        user.is_active = not user.is_active  # Toggle the status
        user.save()
        return Response({"message": f"User is now {'active' if user.is_active else 'inactive'}."})
    

def admin_toggle_active_status_view(request, user_id):
    """
    View to toggle the active status of a user and render the user list.
    """
    api_url = f"https://cmsblogpos-50c60a279bb0.herokuapp.com/admin_view/toggle-active-status/{user_id}/"
    access_token = request.session.get("access_token")  # Assuming authentication tokens are stored in the session

    if not access_token:
        return redirect("login")  # Redirect to login if not authenticated

    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    try:
        response = requests.patch(api_url, headers=headers)  # Call the API to toggle the user's status
        print("API Response Status:", response.status_code)  # Debugging: Print API response status
        print("API Response Body:", response.json())  # Debugging: Print API response body
        
        if response.status_code == 200:
            message = response.json().get("message", "Status updated successfully.")
        else:
            message = response.json().get("detail", "Failed to update status.")
    except requests.exceptions.RequestException as e:
        print("API request failed:", e)  # Debugging: Print exception details
        message = "An error occurred while processing your request."

    # After toggling, redirect to the user list view
    return redirect("regular_users_view")






def fetch_posts_users_admin(request):
    api_url = "https://cmsblogpos-50c60a279bb0.herokuapp.com/posts/"  # URL to fetch posts
    
    # Fetch the access token from session (if available)
    access_token = request.session.get('access_token')
    print('fetchacces',access_token)

    if not access_token:
        return redirect('login') 
    
    headers = {
        'Authorization': f'Bearer {access_token}'  
    }

    try:
      
        response = requests.get(api_url, headers=headers)
        # print("Response Status Code:", response.status_code)
        # print("Response Content:", response.text)
        
        if response.status_code == 200:
            posts = response.json()  # Parse the JSON response
            
            print("Fetched posts:", posts)
            return render(request, 'admin/postusers.html', {'posts': posts})
        else:
            # Handle error (e.g., unauthorized or bad request)
            errors = response.json()
            return render(request, 'admin/postusers.html', {'errors': errors})

    except requests.exceptions.RequestException as e:
        print("API request failed:", e)
        return render(request, 'admin/postusers.html', {'errors': {'non_field_errors': ['Something went wrong.']}})






from django.shortcuts import render, redirect
from django.contrib import messages


import json


from users.models import Post
from users.serializers import PostSerializer
from rest_framework.exceptions import NotFound


class EditPostUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get_post_or_404(self, pk):
        try:
            return Post.objects.get(pk=pk)
        except Post.DoesNotExist:
            raise NotFound(detail="Post not found.")

    def get(self, request, pk):
        post = self.get_post_or_404(pk)
        if not request.user.is_staff and post.author != request.user:
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        serializer = PostSerializer(post)
        return Response(serializer.data)

    def put(self, request, pk):
        post = get_object_or_404(Post, pk=pk)
        serializer = PostSerializer(post, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        post = self.get_post_or_404(pk)
        if post.author != request.user:
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = PostSerializer(post, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    



from django.contrib import messages

def update_posts_users(request, pk):
    api_url = f"https://cmsblogpos-50c60a279bb0.herokuapp.com/admin_view/posts-users/{pk}/update/"  # API endpoint for editing the post

    access_token = request.session.get('access_token')
    if not access_token:
        return redirect('login')  # Redirect to login if not authenticated

    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    if request.method == "GET":
        try:
            response = requests.get(api_url, headers=headers)
            if response.status_code == 200:
                try:
                    post_data = response.json()
                    return render(request, 'admin/eachpost.html', {'post': post_data})
                except ValueError:
                    return render(request, 'admin/eachpost.html', {"errors": {"detail": "Invalid response from the server."}})
            elif response.status_code == 403:
                return render(request, 'admin/eachpost.html', {"errors": {"detail": "Permission denied."}})
            else:
                try:
                    errors = response.json()
                except ValueError:
                    errors = {"detail": "Unexpected error occurred."}
                return render(request, 'admin/eachpost.html', {"errors": errors})
        except requests.exceptions.RequestException as e:
            print("API request failed:", e)
            return render(request, 'admin/eachpost.html', {"errors": {"non_field_errors": ["Something went wrong."]}})

    elif request.method == "POST":
        form_data = {
            "title": request.POST.get("title"),
            "content": request.POST.get("content"),
        }
        files = {"image": request.FILES.get("image")} if "image" in request.FILES else None

        try:
            response = requests.put(api_url, data=form_data, files=files, headers=headers)
            if response.status_code == 200:
                # Add success message
                messages.success(request, 'Post updated successfully!')
                return redirect('fetch_posts_users_admin')
            else:
                try:
                    errors = response.json()
                except ValueError:
                    errors = {"detail": "Unexpected error occurred."}
                return render(request, "admin/eachpost.html", {"errors": errors, "form_data": form_data})
        except requests.exceptions.RequestException as e:
            print("API request failed:", e)
            return render(request, "admin/eachpost.html", {"errors": {"non_field_errors": ["Something went wrong."]}})

    return render(request, 'admin/eachpost.html')




class PostDeleteUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get_post_or_404(self, pk):
        try:
            return Post.objects.get(pk=pk)
        except Post.DoesNotExist:
            raise NotFound(detail="Post not found.")

    def delete(self, request, pk):
        # Check if the user is an admin or the post author
        post = self.get_post_or_404(pk)
        
        # Allow only admins or the post's author to delete the post
        if not request.user.is_staff and post.author != request.user:
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        
        post.delete()
        return Response({"message": "Post deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

def deletepost(request, pk):
    api_url = f"https://cmsblogpos-50c60a279bb0.herokuapp.com/admin_view/deleteuser/{pk}/"
    access_token = request.session.get('access_token')
    if not access_token:
        return redirect('login') 
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    try:
        response = requests.delete(api_url, headers=headers)
        if response.status_code == 204:
            messages.success(request, "Post deleted successfully.")
        elif response.status_code == 403:
            messages.error(request, "You do not have permission to delete this post.")
        elif response.status_code == 404:
            messages.error(request, "Post not found.")
        else:
            messages.error(request, "An error occurred while deleting the post.")
    except requests.exceptions.RequestException as e:
        messages.error(request, "Something went wrong. Please try again later.")
    return redirect('fetch_posts_users_admin')
