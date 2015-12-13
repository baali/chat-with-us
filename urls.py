from django.conf import settings
from django.conf.urls import patterns, url, include

urlpatterns = patterns('',
    # support
    url(r'^support/$', 'zerver.views.support.chat_with_support'),
)

urlpatterns += patterns('zerver.views',
    url(r'^support/json/upload_file$', 'json_upload_file'),
)


