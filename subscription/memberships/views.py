from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout, login, authenticate
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect
from django.http import HttpResponseForbidden, HttpResponse
from django.utils.decorators import method_decorator

from django.views.generic import ListView
from django.urls import reverse
from django.contrib.auth.views import LoginView
from django.urls import reverse_lazy

from django.views.generic import CreateView, View
from .forms import RegisterUserForm, LoginForm

from .models import Membership, UserMembership, Subscription
import stripe


class RegisterUserView(CreateView):
    form_class = RegisterUserForm
    template_name = "memberships/register_1.html"

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return HttpResponseForbidden()

        return super(RegisterUserView, self).dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        user = form.save(commit=False)
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']
        user.set_password(password)
        user.save()
        user = authenticate(username=username, password=password)
        login(self.request, user)
        return HttpResponse('User registered')


class LoginUserView(LoginView):
    form_class = LoginForm
    template_name = "memberships/login.html"
    redirect_authenticated_user = True
    success_url = reverse_lazy('dashboard')


class LogoutView(View):
    def get(self, request):
        logout(request)
        return HttpResponseRedirect(settings.LOGIN_URL)


class MyMembershipView(View):
    template_name = 'memberships/my_membership.html'

    def get(self, request, *args, **kwargs):
        template = self.template_name
        user_membership = get_user_membership(request)
        user_subscription = get_user_subscription(request)
        context = {
            'user_membership': user_membership,
            'user_subscription': user_subscription
        }
        return render(request, template, context)


def get_user_membership(request):
    user_membership_qs = UserMembership.objects.filter(user=request.user)
    if user_membership_qs.exists():
        return user_membership_qs.first()
    return None


def get_user_subscription(request):
    user_subscription_qs = Subscription.objects.filter(
        user_membership=get_user_membership(request))  # FK on Subscription
    if user_subscription_qs.exists():
        user_subscription = user_subscription_qs.first()
        return user_subscription
    return None


def get_selected_membership(request):
    membership_type = request.session['selected_membership_type']
    selected_membership_qs = Membership.objects.filter(
        membership_type=membership_type)
    if selected_membership_qs.exists():
        return selected_membership_qs.first()
    return None


@method_decorator(login_required, name='dispatch')
class MembershipSelectView(ListView):
    model = Membership

    def dispatch(self, request, *args, **kwargs):
        return super(MembershipSelectView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        current_membership = get_user_membership(self.request)
        context['current_membership'] = str(current_membership.membership)
        return context

    def post(self, request, **kwargs):
        user_membership = get_user_membership(request)
        user_subscription = get_user_subscription(request)

        selected_membership_type = request.POST.get('membership_type')

        selected_membership_qs = Membership.objects.filter(
            membership_type=selected_membership_type)
        print(selected_membership_qs)
        selected_membership = selected_membership_qs.first()
        print(selected_membership)
        '''
		==========
		VALIDATION
		==========
		'''

        if user_membership.membership == selected_membership:
            if user_subscription != None:
                messages.info(request, "You already have this membership. Your \
					next payment is due {}".format('get this value from stripe'))
                return HttpResponseRedirect(request.META.get('HTTP_REFERER'))

        # assign to the session
        # Membership field
        request.session['selected_membership_type'] = selected_membership.membership_type

        return HttpResponseRedirect(reverse('memberships:payment'))


class PaymentView(View):
    template_name = 'memberships/membership_payment.html'

    def get(self, request, *args, **kwargs):
        template = self.template_name
        context = {
            'publishKey': settings.STRIPE_PUBLISHABLE_KEY,
            'selected_membership': get_user_membership(request)
        }
        return render(request, template, context)

    def post(self, request, **kwargs):
        user_membership = get_user_membership(request)
        selected_membership = get_selected_membership(request)
        try:
            token = request.POST['stripeToken']
            subscription = stripe.Subscription.create(
                customer=user_membership.stripe_customer_id,  # id on User Membership Model
                items=[
                    {
                        "plan": selected_membership.stripe_plan_id,
                    },
                ],
                trial_period_days=100

            )

            return redirect(reverse('memberships:update-transactions',
                                    kwargs={
                                        'subscription_id': subscription.id
                                    }))

        except stripe.error.CardError as e:
            messages.info(request, "Your card has been declined")


class UpdateTransactionRecords(View):

    def get(self, request, *args, **kwargs):
        subscription_id = self.kwargs['subscription_id']
        user_membership = get_user_membership(request)
        selected_membership = get_selected_membership(request)

        user_membership.membership = selected_membership
        user_membership.save()

        sub, created = Subscription.objects.get_or_create(
            user_membership=user_membership)
        sub.stripe_subscription_id = subscription_id
        sub.active = True
        sub.save()

        try:
            del request.session['selected_membership_type']
        except:
            pass

        messages.info(request, 'Successfully created {} membership'.format(
            selected_membership))
        return redirect('/memberships')


class CancelSubscription(View):
    def get(self, request, *args, **kwargs):
        user_sub = get_user_subscription(request)

        if user_sub.active == False:
            messages.info(request, "You dont have an active membership")
            return HttpResponseRedirect(request.META.get('HTTP_REFERER'))

        sub = stripe.Subscription.retrieve(user_sub.stripe_subscription_id)
        sub.delete()

        user_sub.active = False
        user_sub.save()

        free_membership = Membership.objects.filter(membership_type='Free').first()
        user_membership = get_user_membership(request)
        user_membership.membership = free_membership
        user_membership.save()

        messages.info(request, "Successfully cancelled membership. We have sent an email")
        # sending an email here

        return redirect('/memberships')
