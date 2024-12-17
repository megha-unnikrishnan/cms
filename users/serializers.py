from rest_framework import serializers
from .models import CustomUser,Comment,Post,Like
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from datetime import date


import logging

# Setup logging
logger = logging.getLogger(__name__)

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        # Get the default data from the parent class's validate method
        data = super().validate(attrs)
        
        # Get the user's details
        user_email = self.user.email
        is_admin = self.user.is_staff
        
        # Log or print the details of the regular user (you can choose either approach)
        if not is_admin:  # For regular users
            logger.info(f"Regular User Logged In: {user_email}")  # Log the email of the regular user
            print(f"Regular User Logged In: {user_email}")  # Print the email of the regular user

        # Add custom data to the response
        data['is_admin'] = is_admin
        data['email'] = user_email
        
        return data

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'phone', 'password', 'bio', 'dob', 'profile_picture']
        extra_kwargs = {'password': {'write_only': True}}  # Prevent password from being displayed in responses

    def create(self, validated_data):
        return CustomUser.objects.create_user(**validated_data)





class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'phone','full_name', 'password', 'bio', 'dob', 'profile_picture')
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists")
        return value

    def validate_mobile(self, value):
        if CustomUser.objects.filter(mobile=value).exists():
            raise serializers.ValidationError("User with this mobile number already exists.")
        return value

    def validate_dob(self, value):
        if value > date.today():
            raise serializers.ValidationError("Date of birth cannot be in the future.")
        return value

    def create(self, validated_data):
        user = CustomUser.objects.create_user(**validated_data)
        profile_picture = validated_data.pop('profile_picture', None)
        full_name=validated_data.pop('full_name',None)
        # Ensure the user is active (optional, should be default in most cases)
        if profile_picture:
            user.profile_picture = profile_picture
        user.is_active = True
        user.save()
        return user
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'full_name','profile_picture']  # Include profile_picture in the response


class PostSerializer(serializers.ModelSerializer):
    author = UserSerializer(read_only=True)  # Make it read-only
    likes_count = serializers.IntegerField(read_only=True)
    class Meta:
        model = Post
        fields = ['id', 'title', 'content', 'author', 'created_at', 'updated_at', 'likes_count', 'read_count', 'image']
        read_only_fields = ['id', 'author', 'created_at', 'updated_at', 'likes_count', 'read_count']

class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        fields = ['id', 'author', 'content', 'created_at']


class LikeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Like
        fields = ['post', 'user']