from django.conf import settings
from django.contrib.auth import login, authenticate
from django.shortcuts import render_to_response, redirect
from django.utils.cache import patch_cache_control
from django.template import RequestContext
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect

from zerver.decorator import get_user_profile_by_email, JsonableError
from zerver.lib.push_notifications import num_push_devices_for_user
from zerver.lib.avatar import avatar_url, get_avatar_url
from zerver.models import Message, UserProfile, Stream, Subscription, \
    email_to_username, get_client, bulk_get_streams, valid_stream_name, \
    UserMessage, Recipient, get_recipient, get_realm, UserPresence
from zerver.lib.create_user import create_user
from zerver.lib.actions import do_get_streams, bulk_remove_subscriptions, \
    bulk_add_subscriptions, do_events_register, create_stream_if_needed, \
    gather_subscriptions_helper, do_change_is_admin, do_add_subscription
from zproject.backends import password_auth_enabled
from zerver.lib.utils import statsd
from zerver.lib.initial_password import initial_password

from datetime import date, datetime, timedelta
import logging
import calendar
import time
import ujson
import simplejson

from zerver.forms import HomepageForm
from support_staff import support_ids

def is_buggy_ua(agent):
    """Discrimiate CSS served to clients based on User Agent

    Due to QTBUG-3467, @font-face is not supported in QtWebKit.
    This may get fixed in the future, but for right now we can
    just serve the more conservative CSS to all our desktop apps.
    """
    return ("Humbug Desktop/" in agent or "Zulip Desktop/" in agent or "ZulipDesktop/" in agent) and \
        not "Mac" in agent

def approximate_unread_count(user_profile):
    not_in_home_view_recipients = [sub.recipient.id for sub in \
                                       Subscription.objects.filter(
            user_profile=user_profile, in_home_view=False)]

    muted_topics = ujson.loads(user_profile.muted_topics)
    # If muted_topics is empty, it looks like []. If it is non-empty, it look
    # like [[u'devel', u'test']]. We should switch to a consistent envelope, but
    # until we do we still have both in the database.
    if muted_topics:
        muted_topics = muted_topics[0]

    return UserMessage.objects.filter(
        user_profile=user_profile, message_id__gt=user_profile.pointer).exclude(
        message__recipient__type=Recipient.STREAM,
        message__recipient__id__in=not_in_home_view_recipients).exclude(
        message__subject__in=muted_topics).exclude(
        flags=UserMessage.flags.read).count()

def create_homepage_form(request, user_info=None):
    if user_info:
        return HomepageForm(user_info, domain=request.session.get("domain"))
    # An empty fields dict is not treated the same way as not
    # providing it.
    return HomepageForm(domain=request.session.get("domain"))

def list_to_streams(streams_raw, user_profile, autocreate=False, invite_only=False):
    """Converts plaintext stream names to a list of Streams, validating input in the process

    For each stream name, we validate it to ensure it meets our
    requirements for a proper stream name: that is, that it is shorter
    than Stream.MAX_NAME_LENGTH characters and passes
    valid_stream_name.

    This function in autocreate mode should be atomic: either an exception will be raised
    during a precheck, or all the streams specified will have been created if applicable.

    @param streams_raw The list of stream names to process
    @param user_profile The user for whom we are retreiving the streams
    @param autocreate Whether we should create streams if they don't already exist
    @param invite_only Whether newly created streams should have the invite_only bit set
    """
    existing_streams = []
    created_streams = []
    # Validate all streams, getting extant ones, then get-or-creating the rest.
    stream_set = set(stream_name.strip() for stream_name in streams_raw)
    rejects = []
    for stream_name in stream_set:
        if len(stream_name) > Stream.MAX_NAME_LENGTH:
            raise JsonableError("Stream name (%s) too long." % (stream_name,))
        if not valid_stream_name(stream_name):
            raise JsonableError("Invalid stream name (%s)." % (stream_name,))

    existing_stream_map = bulk_get_streams(user_profile.realm, stream_set)

    for stream_name in stream_set:
        stream = existing_stream_map.get(stream_name.lower())
        if stream is None:
            rejects.append(stream_name)
        else:
            existing_streams.append(stream)
    if autocreate:
        for stream_name in rejects:
            stream, created = create_stream_if_needed(user_profile.realm,
                                                      stream_name,
                                                      invite_only=invite_only)
            if created:
                created_streams.append(stream)
            else:
                existing_streams.append(stream)
    elif rejects:
        raise JsonableError("Stream(s) (%s) do not exist" % ", ".join(rejects))

    return existing_streams, created_streams

def name_changes_disabled(realm):
    return settings.NAME_CHANGES_DISABLED or realm.name_changes_disabled

def sent_time_in_epoch_seconds(user_message):
    # user_message is a UserMessage object.
    if not user_message:
        return None
    # We have USE_TZ = True, so our datetime objects are timezone-aware.
    # Return the epoch seconds in UTC.
    return calendar.timegm(user_message.message.pub_date.utctimetuple())

def get_support(user_profile, available_sp):
    support_profile = None
    if user_profile:
        last_msg = user_profile.message_set.last()
        if last_msg:
            stream = Stream.objects.get(id=last_msg.recipient.type_id)
            if Subscription.objects.filter(recipient__type=Recipient.STREAM,
                                           recipient__type_id=stream.id,
                                           user_profile__is_active=True,
                                           active=True).exclude(user_profile=user_profile).exists():
                support_profile = Subscription.objects.filter(recipient__type=Recipient.STREAM,
                                                              recipient__type_id=stream.id,
                                                              user_profile__is_active=True,
                                                              active=True).exclude(user_profile=user_profile).first().user_profile
                if support_profile.email not in support_ids:
                    #  To make sure we return Support ids which are
                    #  part of support_id list
                    support_profile = None
    if not support_profile:
        import random
        support = random.choice(available_sp)
        support_profile = get_user_profile_by_email(support)
    return support_profile
    
def chat_with_support(request):
    # Get recently "active" SPs
    time_threshold = datetime.now() - timedelta(minutes=1)
    available_sp = [user_p.user_profile.email for user_p in UserPresence.objects.filter(timestamp__gte=time_threshold) if user_p.user_profile.email in support_ids]
    if request.method == 'POST' and bool(available_sp):
        email = request.POST['email']
        try:
            user_profile = get_user_profile_by_email(email)
            # One Admin account which has access to all streams
            admin_profile = get_user_profile_by_email("admin@domain.com")
            support_profile = get_support(user_profile, available_sp)
        except UserProfile.DoesNotExist:
            support_profile = get_support(None, available_sp)
            password = initial_password(email)
            short_name = email_to_username(email)
            # both customer and Support staff have to belong to same
            # realm
            user_profile = create_user(email, password, 
                                       support_profile.realm, 
                                       short_name, short_name)

        try:
            sp_presence = UserPresence.objects.get(user_profile=support_profile)
            from django.utils import timezone
            now_aware = timezone.now()
            # Support user has been offline since more than an 15 minutes
            if (now_aware - sp_presence.timestamp).seconds > 900:
                sp_online = False
            else:
                sp_online = True
        except UserPresence.DoesNotExist:
            sp_online = False

        if user_profile.email in support_ids:
            logging.info("%s Logging in support user" % (user_profile.email))
            return HttpResponseRedirect(reverse('zerver.views.home'))
        if user_profile.realm != support_profile.realm:
            logging.warning("%s user belonging to different real tried to access support interface" % (user_profile.email))
            return HttpResponseRedirect(reverse('zerver.views.home'))

        login(request, authenticate(username=user_profile.email, use_dummy_backend=True))
        request.session.modified = True
        request._email = email
        request.client = get_client("website")
        # current streams and unsubscribing user from it
        narrow = []
        narrow_stream = None
        narrow_topic = date.today().strftime('%d-%m-%Y')
        stream = email+' on '+datetime.now().strftime('%d-%m-%Y-%H')
        for stream_sub in do_get_streams(user_profile):
            if stream_sub['name'] == stream:
                # skipping most recent stream customer has used
                continue
            streams, _ = list_to_streams([stream_sub['name']], user_profile)
            (removed, not_subscribed) = bulk_remove_subscriptions([user_profile], streams)

        narrow_stream, created = create_stream_if_needed(user_profile.realm,
                                                         stream,
                                                         invite_only=True)
        if created:
            # make support ADMIN of stream
            do_add_subscription(admin_profile, narrow_stream)
            do_change_is_admin(admin_profile, True)
            do_add_subscription(support_profile, narrow_stream)
        do_add_subscription(user_profile, narrow_stream)

        narrow = [["stream", narrow_stream.name]]
        narrow.append(["topic", narrow_topic])

        try:
            register_ret = do_events_register(user_profile, request.client,
                                              apply_markdown=True, narrow=narrow)
        except Exception as e:
            logging.error("Failed to connect user:%s for %s" % (user_profile.email, str(e)))
            form = create_homepage_form(request)
            form.is_valid()
            form.add_error(None, "Sorry we are having trouble connecting you with out Support staff over chat. You can try again or mail us your query at support@taxspanner.com")
            return render_to_response('zerver/reachout.html',
                                      {'form': form,
                                       'sp_available': bool(available_sp),
                                       'current_url': request.get_full_path,},
                                      context_instance=RequestContext(request))

        # customer has is retrying to connect to support on same day
        user_has_messages = (register_ret['max_message_id'] != -1)
        # Reset our don't-spam-users-with-email counter since the
        # user has since logged in
        if not user_profile.last_reminder is None:
            user_profile.last_reminder = None
            user_profile.save(update_fields=["last_reminder"])

        needs_tutorial = first_in_realm = prompt_for_invites = False

        if user_profile.pointer == -1 and user_has_messages:
            # Put the new user's pointer at the bottom
            #
            # This improves performance, because we limit backfilling of messages
            # before the pointer.  It's also likely that someone joining an
            # organization is interested in recent messages more than the very
            # first messages on the system.

            register_ret['pointer'] = register_ret['max_message_id']
            user_profile.last_pointer_updater = request.session.session_key

        if user_profile.pointer == -1:
            latest_read = None
        else:
            try:
                latest_read = UserMessage.objects.get(user_profile=user_profile,
                                                      message__id=user_profile.pointer)
            except UserMessage.DoesNotExist:
                # Don't completely fail if your saved pointer ID is invalid
                logging.warning("%s has invalid pointer %s" % (user_profile.email, user_profile.pointer))
                latest_read = None

        desktop_notifications_enabled = True
        notifications_stream = narrow_stream.name

        # Pass parameters to the client-side JavaScript code.
        # These end up in a global JavaScript Object named 'page_params'.
        page_params = dict(
            voyager               = settings.VOYAGER,
            debug_mode            = settings.DEBUG,
            test_suite            = settings.TEST_SUITE,
            poll_timeout          = settings.POLL_TIMEOUT,
            login_page            = settings.HOME_NOT_LOGGED_IN,
            password_auth_enabled = password_auth_enabled(user_profile.realm),
            have_initial_messages = user_has_messages,
            subbed_info           = register_ret['subscriptions'],
            unsubbed_info         = register_ret['unsubscribed'],
            email_dict            = register_ret['email_dict'],
            people_list           = [],
            bot_list              = register_ret['realm_bots'],
            initial_pointer       = register_ret['pointer'],
            initial_presences     = register_ret['presences'],
            initial_servertime    = time.time(), # Used for calculating relative presence age
            fullname              = user_profile.full_name,
            email                 = user_profile.email,
            domain                = user_profile.realm.domain,
            realm_name            = register_ret['realm_name'],
            realm_invite_required = register_ret['realm_invite_required'],
            realm_invite_by_admins_only = register_ret['realm_invite_by_admins_only'],
            realm_restricted_to_domain = register_ret['realm_restricted_to_domain'],
            enter_sends           = user_profile.enter_sends,
            left_side_userlist    = False,
            referrals             = [],
            realm_emoji           = register_ret['realm_emoji'],
            needs_tutorial        = needs_tutorial,
            first_in_realm        = first_in_realm,
            prompt_for_invites    = prompt_for_invites,
            notifications_stream  = notifications_stream,

            # Stream message notification settings:
            stream_desktop_notifications_enabled =
            user_profile.enable_stream_desktop_notifications,
            stream_sounds_enabled = user_profile.enable_stream_sounds,

            # Private message and @-mention notification settings:
            desktop_notifications_enabled = desktop_notifications_enabled,
            sounds_enabled =
            user_profile.enable_sounds,
            enable_offline_email_notifications =
            user_profile.enable_offline_email_notifications,
            enable_offline_push_notifications =
            user_profile.enable_offline_push_notifications,
            twenty_four_hour_time = register_ret['twenty_four_hour_time'],

            enable_digest_emails  = False,
            event_queue_id        = register_ret['queue_id'],
            last_event_id         = register_ret['last_event_id'],
            max_message_id        = register_ret['max_message_id'],
            unread_count          = approximate_unread_count(user_profile),
            furthest_read_time    = sent_time_in_epoch_seconds(latest_read),
            staging               = settings.ZULIP_COM_STAGING or settings.DEVELOPMENT,
            alert_words           = register_ret['alert_words'],
            muted_topics          = [],
            realm_filters         = [],
            is_admin              = False,
            can_create_streams    = False,
            name_changes_disabled = name_changes_disabled(user_profile.realm),
            has_mobile_devices    = num_push_devices_for_user(user_profile) > 0,
            autoscroll_forever = user_profile.autoscroll_forever,
            default_desktop_notifications = user_profile.default_desktop_notifications,
            avatar_url            = avatar_url(user_profile),
            mandatory_topics      = user_profile.realm.mandatory_topics,
            show_digest_email     = user_profile.realm.show_digest_email,
        )

        if narrow_stream is not None:
            # In narrow_stream context, initial pointer is just latest message
            recipient = get_recipient(Recipient.STREAM, narrow_stream.id)
            try:
                initial_pointer = Message.objects.filter(recipient=recipient).order_by('id').reverse()[0].id
            except IndexError:
                initial_pointer = -1
            page_params["narrow_stream"] = narrow_stream.name
            if narrow_topic is not None:
                page_params["narrow_topic"] = narrow_topic
            page_params["narrow"] = [dict(operator=term[0], operand=term[1]) for term in narrow]
            page_params["max_message_id"] = initial_pointer
            page_params["initial_pointer"] = initial_pointer
            page_params["have_initial_messages"] = (initial_pointer != -1)

        statsd.incr('views.chat_with_support')
        show_invites = False

        product_name = 'Product-Name'
        page_params['product_name'] = product_name
        request._log_data['extra'] = "[%s]" % (register_ret["queue_id"],)
        response = render_to_response('zerver/support_chat.html',
                                      {'user_profile': user_profile,
                                       'page_params' : simplejson.encoder.JSONEncoderForHTML().encode(page_params),
                                       'nofontface': is_buggy_ua(request.META["HTTP_USER_AGENT"]),
                                       'avatar_url': avatar_url(user_profile) if user_profile else None,
                                       'show_debug':
                                            settings.DEBUG and ('show_debug' in request.GET),
                                       'show_invites': show_invites,
                                       'sp_online': sp_online,
                                       'is_admin': False,
                                       'show_webathena': False,
                                       'enable_feedback': settings.ENABLE_FEEDBACK,
                                       'embedded': narrow_stream is not None,
                                       'product_name': product_name
                                   },
                                    context_instance=RequestContext(request))
        patch_cache_control(response, no_cache=True, no_store=True, must_revalidate=True)
        return response
    form = create_homepage_form(request)
    return render_to_response('zerver/reachout.html',
                              {'form': form,
                               'sp_available': bool(available_sp),
                               'current_url': request.get_full_path,},
                              context_instance=RequestContext(request))

