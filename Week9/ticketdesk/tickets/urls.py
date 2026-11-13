from django.urls import path
from . import views

urlpatterns = [
    path("", views.ticket_list, name="ticket_list"),
    path("tickets/new/", views.ticket_create, name="ticket_create"),
    path("tickets/<int:pk>/", views.ticket_detail, name="ticket_detail"),
    path("tickets/<int:pk>/delete/", views.ticket_delete, name="ticket_delete"),
    path("search/", views.search, name="search"),
    path("export/", views.export_csv, name="export_csv"),
]
