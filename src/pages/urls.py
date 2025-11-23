from django.urls import path
from . import views

urlpatterns = [
    path("", views.index),
    path("register/", views.register_view),
    path("login/", views.login_view),
    path("logout/", views.logout_view),
    path("notes/<int:note_id>/", views.note_detail),
    path("notes/add/", views.add_note),
    path("notes/delete/<int:note_id>/", views.delete_note),
    path("debug-test/", views.debug_test),
]