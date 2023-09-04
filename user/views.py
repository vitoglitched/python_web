from django.http import Http404
from django.shortcuts import render
from .middlewares import Middlewares
from .serializers import UserSerializer,UserUpdateSerializer, CustomTokenObtainParirSerializer
from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import UserModel
from .permissions import ValidToken
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import UserSerializer, CustomTokenObtainParirSerializer
from rest_framework import generics
from .models import UserModel
from rest_framework_simplejwt.views import TokenObtainPairView

class CreateUserView(generics.CreateAPIView):
    
    model=UserModel

    serializer_class = UserSerializer


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainParirSerializer
