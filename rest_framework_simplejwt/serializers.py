##### MODDED #####
from __future__ import unicode_literals

from django.contrib.auth import authenticate
from django.utils.six import text_type
from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers

from .settings import api_settings
from .state import User
from .tokens import RefreshToken, SlidingToken, UntypedToken

##### CUSTOM IMPORT
from user.models import Organization, CommonAuth


##### CUSTOM IMPORT ENDs


class PasswordField(serializers.CharField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('style', {})

        kwargs['style']['input_type'] = 'password'
        kwargs['write_only'] = True

        super(PasswordField, self).__init__(*args, **kwargs)


class TokenObtainSerializer(serializers.Serializer):
    username_field = User.USERNAME_FIELD

    def __init__(self, *args, **kwargs):
        super(TokenObtainSerializer, self).__init__(*args, **kwargs)

        self.fields[self.username_field] = serializers.CharField()
        self.fields['password'] = PasswordField()

    def validate(self, attrs):
        self.user = authenticate(**{
            self.username_field: attrs['subdomain'] + '_' + attrs[self.username_field],
            'password': attrs['password'],
        })

        # Prior to Django 1.10, inactive users could be authenticated with the
        # default `ModelBackend`.  As of Django 1.10, the `ModelBackend`
        # prevents inactive users from authenticating.  App designers can still
        # allow inactive users to authenticate by opting for the new
        # `AllowAllUsersModelBackend`.  However, we explicitly prevent inactive
        # users from authenticating to enforce a reasonable policy and provide
        # sensible backwards compatibility with older Django versions.
        if self.user is None or not self.user.is_active:
            raise serializers.ValidationError(
                _('No active account found with the given credentials'),
            )

        return {}

    @classmethod
    def get_token(cls, user):
        raise NotImplemented('Must implement `get_token` method for `TokenObtainSerializer` subclasses')


class TokenObtainPairSerializer(TokenObtainSerializer):
    @classmethod
    def get_token(cls, user):
        return RefreshToken.for_user(user)

    def validate(self, attrs):
        data = super(TokenObtainPairSerializer, self).validate(attrs)

        refresh = self.get_token(self.user)

        data['refresh'] = text_type(refresh)
        data['access'] = text_type(refresh.access_token)

        return data


class TokenObtainSlidingSerializer(TokenObtainSerializer):
    @classmethod
    def get_token(cls, user):
        return SlidingToken.for_user(user)

    def validate(self, attrs):
        data = super(TokenObtainSlidingSerializer, self).validate(attrs)

        token = self.get_token(self.user)

        data['token'] = text_type(token)

        return data


class TokenRefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        refresh = RefreshToken(attrs['refresh'])

        data = {'access': text_type(refresh.access_token)}

        if api_settings.ROTATE_REFRESH_TOKENS:
            if api_settings.BLACKLIST_AFTER_ROTATION:
                try:
                    # Attempt to blacklist the given refresh token
                    refresh.blacklist()
                except AttributeError:
                    # If blacklist app not installed, `blacklist` method will
                    # not be present
                    pass

            refresh.set_jti()
            refresh.set_exp()

            data['refresh'] = text_type(refresh)

        return data


class TokenRefreshSlidingSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate(self, attrs):
        token = SlidingToken(attrs['token'])

        # Check that the timestamp in the "refresh_exp" claim has not
        # passed
        token.check_exp(api_settings.SLIDING_TOKEN_REFRESH_EXP_CLAIM)

        # Update the "exp" claim
        token.set_exp()

        return {'token': text_type(token)}


class TokenVerifySerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate(self, attrs):
        UntypedToken(attrs['token'])

        return {}


##### CUSTOM CLASS #####
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    subdomain = serializers.CharField()

    def validate(self, attrs):
        data = super(CustomTokenObtainPairSerializer, self).validate(attrs)

        ##### ORGANIZATION CHECK #####
        # TODO Try hittind Redis instead of DB
        groups = self.user.groups.values_list('name', flat=True)
        # organization = Organization.objects.get(id=self.user.organization.pk).__dict__
        organization = self.user.organization.__dict__
        if organization['sub_domain'] != attrs.get('subdomain'):
            raise serializers.ValidationError(_('Wrong credentials for this institute'), )
        ##### ORGANIZATION CHECK ENDS #####

        refresh = super(CustomTokenObtainPairSerializer, self).get_token(self.user)

        refresh['subdomain'] = attrs.get('subdomain')
        data['refresh'] = text_type(refresh)
        data['access'] = text_type(refresh.access_token)
        data['user'] = {'active_user': self.user.pk, 'full_name': self.user.name,
                        'username': self.user.username.split(organization['sub_domain'] + '_', 1)[1],
                        'groups': groups,'logo': organization['logo_aws']}

        return data
