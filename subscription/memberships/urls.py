from django.urls import path

from .views import (
    MembershipSelectView,
    PaymentView,
    UpdateTransactionRecords,
    CancelSubscription,
    RegisterUserView,
    LoginUserView,
    LogoutView,
    MyMembershipView
)

app_name = 'memberships'

urlpatterns = [
    path('', MembershipSelectView.as_view(), name='select'),
    path('payment/', PaymentView.as_view(), name='payment'),
    path('update-transactions/<subscription_id>/', UpdateTransactionRecords.as_view(), name='update-transactions'),
    path('cancel/', CancelSubscription.as_view(), name='cancel'),
    path('register/', RegisterUserView.as_view(), name='register'),
    path('login/', LoginUserView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('my_membership/', MyMembershipView.as_view(), name='my_membership'),
]
