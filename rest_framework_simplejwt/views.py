##### MODDED #####
from __future__ import unicode_literals

from rest_framework import generics, status
from rest_framework.response import Response

from . import serializers
from .authentication import AUTH_HEADER_TYPES
from .exceptions import InvalidToken, TokenError
from .settings import api_settings
from datetime import datetime


class TokenViewBase(generics.GenericAPIView):
    permission_classes = ()
    authentication_classes = ()

    serializer_class = None

    www_authenticate_realm = 'api'

    def get_authenticate_header(self, request):
        return '{0} realm="{1}"'.format(
            AUTH_HEADER_TYPES[0],
            self.www_authenticate_realm,
        )

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])


        # ORGINAL RETURN STATEMENT
        # return Response(serializer.validated_data, status=status.HTTP_200_OK)
        

        ##### MODDED RETURN STATEMENT #####
        return Response(serializer.validated_data, status=status.HTTP_200_OK), serializer
        ##### ENDS #####

class TokenObtainPairView(TokenViewBase):
    """
    Takes a set of user credentials and returns an access and refresh JSON web
    token pair to prove the authentication of those credentials.
    """
    serializer_class = serializers.TokenObtainPairSerializer

token_obtain_pair = TokenObtainPairView.as_view()


class TokenRefreshView(TokenViewBase):
    """
    Takes a refresh type JSON web token and returns an access type JSON web
    token if the refresh token is valid.
    """
    serializer_class = serializers.TokenRefreshSerializer

token_refresh = TokenRefreshView.as_view()


class TokenObtainSlidingView(TokenViewBase):
    """
    Takes a set of user credentials and returns a sliding JSON web token to
    prove the authentication of those credentials.
    """
    serializer_class = serializers.TokenObtainSlidingSerializer

token_obtain_sliding = TokenObtainSlidingView.as_view()


class TokenRefreshSlidingView(TokenViewBase):
    """
    Takes a sliding JSON web token and returns a new, refreshed version if the
    token's refresh period has not expired.
    """
    serializer_class = serializers.TokenRefreshSlidingSerializer

token_refresh_sliding = TokenRefreshSlidingView.as_view()


class TokenVerifyView(TokenViewBase):
    """
    Takes a token and indicates if it is valid.  This view provides no
    information about a token's fitness for a particular use.
    """
    serializer_class = serializers.TokenVerifySerializer

token_verify = TokenVerifyView.as_view()





##### CUSTOM CLASS #####
# AUTHOR = "Eriz"

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = serializers.CustomTokenObtainPairSerializer


    def post(self, request, *args, **kwargs):
        response, serializer = super(CustomTokenObtainPairView, self).post(request)

        if api_settings.JWT_AUTH_COOKIE:
            expiration = (datetime.utcnow() + api_settings.ACCESS_TOKEN_LIFETIME)
            response.set_cookie(api_settings.JWT_AUTH_COOKIE,
                                serializer.validated_data[api_settings.JWT_AUTH_COOKIE],
                                expires=expiration,
                                httponly=True)
            response.set_cookie('refresh',
                                serializer.validated_data['refresh'],
                                expires=expiration,
                                httponly=True)

        # TODO Save in user_login_summary
        # print(request.META)
        # from user.models import UserLoginSummary
        # user_login = UserLoginSummary()
        # print(request.META['REMOTE_ADDR'])
        # print(request.META['HTTP_USER_AGENT'])
        # user_login.save(update_fields=['ip_address','user_agent'])
        return response
##### MOD ENDS #####
