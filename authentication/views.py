import jwt

from rest_framework import generics, status, views
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from config import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from .serializers import (RegisterSerializer, EmailVerificationSerializer,
                          LoginSerializer, ResetPasswordEmailSerializer,
                          SetNewPasswordSerializer)
from .models import User
from .utils import Util
from .renderers import UserRenderer


class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    renderer_classes = (UserRenderer,)

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])

        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relative_link = reverse('email-verify')

        absurl = 'http://' + current_site + relative_link + '?token=' + str(token)
        email_body = 'Hi ' + user.username + ' Use link below to verify your email\n' + absurl
        data = {
            'email_body': email_body,
            'email_subject': 'Verify your email',
            'email_to': user.email
        }
        Util.send_email(data)

        return Response(user_data, status=status.HTTP_200_OK)


class VerifyEmail(views.APIView):
    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter('token', in_=openapi.IN_QUERY, description='Description',
                                           type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        print(settings.SECRET_KEY)
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()

            return Response({'email': 'Succesfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Activation expired'},
                            status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailSerializer

    def post(self, request):
        data = request.data
        # data['request'] = request
        print(data)
        serializer = self.serializer_class(data=data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        return Response(
            {
                'success': ' We have sent you link to reset your password'
            }, status=status.HTTP_200_OK
        )


class PasswordTokenCheckAPI(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response(
                    {'error': 'Token is already used, please request a new one'},
                    status=status.HTTP_401_UNAUTHORIZED)
            return Response(
                {
                    'success': True,
                    'message': 'Credential valid',
                    'uidb64': uidb64,
                    'token': token
                },
                status=status.HTTP_200_OK
            )
        except DjangoUnicodeDecodeError:
            return Response(
                {
                    'error': 'Token is not valid, please request a new one'
                }
            )


class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(
            {
                'success': True,
                'message': 'Password reset success'
            },
            status=status.HTTP_200_OK
        )
