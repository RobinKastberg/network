from django.conf.urls import include, url


urlpatterns = [
	url(r'^ex/$', include('exercise.urls')),
	url(r'^admin/', admin.site.urls),
]
