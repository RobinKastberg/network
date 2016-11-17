from django.conf.urls import include, url

from . import views

urlpatterns = [
	url(r'^$', views.index, name='index'),
	url(r'^restart$', views.restart, name='restart'),
        url(r'^stage2$', views.stage2, name='stage2'),
	url(r'^validate$', views.validate, name='validate'),
	url(r'^validate2$', views.validate2, name='validate2'),
]
