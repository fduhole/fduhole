from django.shortcuts import  get_object_or_404
from django.contrib import auth
from django.db.models import Q
from django.contrib.auth.models import User, Group
from django.contrib.auth.hashers import make_password, check_password
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from django.core.cache import cache
from django.core.mail import send_mail

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework.authtoken.models import Token

from .utils import *
from .models import *
from .serializer import *
import logging, base64, httpx, random
from datetime import datetime

class RegisterView(APIView):
    '''
    URL: register/

    '''

    def get(self, request):
        
        username = request.query_params.get('username')
        email = request.query_params.get('email')
        usage = request.query_params.get('usage')

        if username and email:

            if usage == 'change_password':
                if not User.objects.filter(username=username): return Response({'msg': '用户不存在！'}, status=status.HTTP_404_NOT_FOUND)
                user = User.objects.get(username=username)
                if not (email == user.profile.encrypted_email or check_password(email, user.profile.encrypted_email)): return Response({'msg': '请使用自己的邮箱'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                if User.objects.filter(username=username): return Response({'data': 1, 'msg': '该用户名已注册！'})

                # 检查邮箱是否已注册
                # for u in User.objects.all():
                #     if check_password(email, u.first_name):
                #         return Response({'data': 2, 'msg': '该邮箱已注册！'})

            # 检查邮箱是否在白名单内
            domain = email[email.find('@')+1:]
            if not domain in settings.WHITELIST: return Response({'data': 3, 'msg': '邮箱不在白名单内！'})

            code = random.randint(100000, 999999)
            cache.set(username, code, 300)
            return Response(mail(recipient=email, code=code, mode=usage))

        if username:
            # 检查用户名是否已注册
            if User.objects.filter(username=username):
                return Response({'data': 1, 'msg': '该用户名已注册！'})
            else: return Response({'data': 0, 'msg': '该用户名未注册！'})

        if email:
            # 检查邮箱是否在白名单内
            # logging.error('开始检查邮箱')
            domain = email[email.find('@')+1:]
            if not domain in settings.WHITELIST: return Response({'data': 3, 'msg': '邮箱不在白名单内！'})
            # 检查邮箱是否已注册
            # for u in User.objects.all():
            #     logging.error(u.username)
            #     if check_password(email, u.first_name):
            #         return Response({'data': 2, 'msg': '该邮箱已注册！'})
            return Response({'data': 0, 'msg': '该邮箱未注册！'})

        return Response({}, status=status.HTTP_400_BAD_REQUEST)
       
    def post(self, request):
        # 获取数据
        username = request.data.get('username')
        password = request.data.get('password')
        email = request.data.get('email')
        code = request.data.get('code')
        api_key = request.data.get('api-key')

        if not email: return Response({'msg': '需要提供用户邮箱'}, status=status.HTTP_400_BAD_REQUEST)

        if api_key:
            if not api_key in settings.API_KEY: 
                return Response({}, status=status.HTTP_401_UNAUTHORIZED)
            
            username = request.data.get('ID')
            if not username: return Response({'msg': '需要提供用户 ID'}, status=status.HTTP_400_BAD_REQUEST)
            
            if not User.objects.filter(username=username): # 若未注册，创建用户
                # 检查邮箱是否在白名单内
                domain = email[email.find('@')+1:]
                if not domain in settings.WHITELIST: return Response({'data': 3, 'msg': '邮箱不在白名单内！'})

                # 检查邮箱是否已注册
                # with open('conf/email.txt', 'r') as f:
                #     email_list = f.read().split(' ')
                #     if email in email_list: return Response({'msg': '该邮箱已被注册'}, status=status.HTTP_400_BAD_REQUEST)
                
                # 记录邮箱
                with open('conf/email.txt', 'a+') as f:
                    f.write(email + ' ')

                # email = make_password(email)
                password = random_str(16)
                user = User.objects.create_user(username=username, password=password)
                user.groups.add(1)
                user.save()
                profile = UserProfile(user=user, encrypted_email=email, has_input_email=True, registered_from_app=True)
                profile.save()
                Token.objects.create(user=user)

            user = User.objects.get(username=username)
            token = Token.objects.get(user=user)
            return Response({
                'username': username,
                'token': token.key,
            })

        if code:
            # 检查用户名是否已注册
            if User.objects.filter(username=username):
                return Response({'data': 1, 'msg': '该用户名已注册！'})
            
            # 检查邮箱是否在白名单内
            domain = email[email.find('@')+1:]
            if not domain in settings.WHITELIST: return Response({'data': 3, 'msg': '邮箱不在白名单内！'})

            # 检查邮箱是否已注册
            with open('conf/email.txt', 'r') as f:
                email_list = f.read().split(' ')
                if email in email_list: return Response({'msg': '该邮箱已被注册'}, status=status.HTTP_400_BAD_REQUEST)
            
            # 检查验证码
            try:
                code = int(code)
            except:
                return Response({}, status=status.HTTP_400_BAD_REQUEST)

            if not cache.get(username) == code: return Response({'data': 4, 'msg': '验证码错误'}, status=status.HTTP_401_UNAUTHORIZED)

            with open('conf/email.txt', 'a+') as f:
                f.write(email + ' ')
            # email = make_password(email)
            user = User.objects.create_user(username=username, password=password)
            user.groups.add(1)
            user.save()
            profile = UserProfile(user=user, encrypted_email=email, has_input_email=True)
            profile.save()
            Token.objects.create(user=user)

            return Response({'data': 0, 'msg': '注册成功, 跳转至登录页面'})

        return Response({}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request):
        '''
        修改密码
        '''
        username = request.data.get('username')
        password = request.data.get('password')
        code = request.data.get('code')

        try:
            code = int(code)
            assert cache.get(username) == code
        except:
            return Response({'msg': '验证码错误'}, status=status.HTTP_401_UNAUTHORIZED)

        try: user = User.objects.get(username=username)
        except: return Response({'msg': '用户不存在！'}, status=status.HTTP_404_NOT_FOUND)

        user.set_password(password)
        user.save()

        old_token = Token.objects.get(user=user)
        old_token.delete()
        Token.objects.create(user=user)
        new_token = Token.objects.get(user=user)
        
        return Response({
            'username': username,
            'token': new_token.key
        })

class LoginView(APIView):
    '''
    POST: 登录
        Args:
            username
            password
            
    GET: 登出
        Args: 
    '''
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = auth.authenticate(username=username, password=password)
        if user is not None:
            auth.login(request, user)
            return Response({'msg': '%s 登录成功！' % username})
        else:
            return Response({'msg': '用户名或密码错误！'}, status=status.HTTP_401_UNAUTHORIZED)
    
    def get(self, request):
            username = request.user.username
            auth.logout(request)
            return Response({'msg': '%s 已登出！' % username})

class DiscussionsView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):

        discussion_id = request.query_params.get('discussion_id')
        tag_name = request.query_params.get('tag_name')
        page = request.query_params.get('page')
        order = request.query_params.get('order')

        if discussion_id:
            discussion = get_object_or_404(Discussion, pk=discussion_id)
            if discussion.disabled: return Response({'msg': '该内容已被删除', 'code': -1})
            serializer = DiscussionSerializer(discussion)
            return Response(serializer.data)

        elif tag_name: # 默认按更新时间排序
            if order == 'last_created':
                discussions = get_object_or_404(Tag, name=tag_name).discussion_set.order_by('-date_created').filter(disabled__exact=False)
            else:
                discussions = get_object_or_404(Tag, name=tag_name).discussion_set.order_by('-date_updated').filter(disabled__exact=False)
            
        else: 
            if not page: return Response({'msg': '需要提供page参数'}, status=status.HTTP_400_BAD_REQUEST)
            page = int(page)
            interval = settings.INTERVAL
            if order == 'last_created':
                discussions = Discussion.objects.order_by('-date_created').filter(disabled__exact=False)[(page - 1) * interval : page * interval]
            else:
                discussions = Discussion.objects.order_by('-date_updated').filter(disabled__exact=False)[(page - 1) * interval : page * interval]

        serializer = DiscussionSerializer(discussions, many=True)
        return Response(serializer.data)

    def post(self, request):

        content = request.data.get('content')
        if not content.strip(): return Response({'msg': '内容不能为空！'}, status=status.HTTP_400_BAD_REQUEST)
        is_folded = False
        tags = request.data.get('tags')
        if not tags:
            tags = [{
                'name': '默认',
                'color': 'grey',
            }]
        if len(tags) >  5: return Response({'msg': '标签不能多于5个'}, status=status.HTTP_400_BAD_REQUEST)
        for tag in tags:
            if len(tag['name'].strip()) >  8: return Response({'msg': '标签名不能超过8个字符'}, status=status.HTTP_400_BAD_REQUEST)
            if not tag['name'].strip(): return Response({'msg': '标签名不能为空'}, status=status.HTTP_400_BAD_REQUEST)
            if not tag['color'] in settings.COLORLIST: return Response({'msg': '标签颜色不符合规范'}, status=status.HTTP_400_BAD_REQUEST)
            if tag['name'][0] == '*': is_folded = True 
    
        # 创建discussion， 创建tag并添加至discussion
        discussion = Discussion(count=0, is_folded = is_folded)
        discussion.save()
        
        # 增/改 tags 并绑定至 discussion
        for tag in tags:
            new_tag = Tag.objects.filter(name=tag['name'])
            if new_tag:
                new_tag = new_tag[0]
                new_tag.count = new_tag.count + 1
                new_tag.save()
            else:
                new_tag = Tag(name=tag['name'], count=1, color=tag['color'])  # tag 的颜色为随机的 material design 标准主色   eg.'red'
                new_tag.save()

            discussion.tag.add(new_tag)

        # create a post
        anonyname = random_name()
        post = Post(username=anonyname, content=content, discussion_id=discussion.pk)
        post.save()

        # create a mapping
        mapping = Mapping(username=request.user, anonyname=anonyname, discussion=discussion)
        mapping.save()

        # save the discussion
        # discussion.first_post = post
        discussion.save()

        serializer = DiscussionSerializer(discussion)
        return Response(serializer.data)

class PostsView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        post_id = request.query_params.get('post_id')
        discussion_id = request.query_params.get('id')
        page = request.query_params.get('page')
        order = request.query_params.get('order')
        search = request.query_params.get('search')
        interval = settings.INTERVAL

        if post_id:
            post_id = int(post_id)
            post = get_object_or_404(Post, pk=post_id)
            if post.disabled: return Response({'msg': '该内容已被删除', 'code': -1})
            serializer = PostSerializer(post, context={'user': request.user})
            return Response(serializer.data)
        elif search:
            posts = Post.objects.filter(content__icontains=search, disabled__exact=False).order_by('-date_created')
        else:
            discussion_id = int(discussion_id)
            d = get_object_or_404(Discussion, pk=discussion_id)
    
            if order: 
                order = int(order)
                posts = d.post_set.order_by('date_created').filter(disabled__exact=False)[order:]
                
            if page:
                page = int(page)
                posts = d.post_set.order_by('date_created').filter(disabled__exact=False)[(page - 1) * interval : page * interval]

        serializer = PostSerializer(posts, many=True, context={'user': request.user})
        return Response(serializer.data)

    def post(self, request):

        content = request.data.get('content')
        discussion_id = request.data.get('discussion_id')
        post_id = request.data.get('post_id')
        
        if not content: return Response({'msg': '内容不能为空！'}, status=status.HTTP_400_BAD_REQUEST)
        if not discussion_id: return Response({'msg': 'discussion id 不能为空！'}, status=status.HTTP_400_BAD_REQUEST)

        discussion = get_object_or_404(Discussion, pk=discussion_id)
        mappings = discussion.name_mapping
        user = request.user
        realname = user.username

        try:
            mapping = mappings.get(username=user)
            anonyname = mapping.anonyname
        except:
            while True:
                anonyname = random_name()
                if mappings.filter(anonyname=anonyname):
                    continue
                else:
                    mapping = Mapping(username=user, anonyname=anonyname, discussion=discussion)
                    mapping.save()
                    break

        reply_to = None
        if post_id : reply_to = post_id

        post = Post(username=anonyname, content=content, discussion_id=discussion_id, reply_to=reply_to)
        post.save()
        
        discussion.count = discussion.count + 1
        discussion.save()

        serializer = PostSerializer(post, context={'user': request.user})
        return Response(serializer.data)
    
    def put(self, request):
        post_id = int(request.data.get('post_id'))
        content = request.data.get('content')
        reply_to = request.data.get('reply_to')

        post = get_object_or_404(Post, id=post_id)
        if post.discussion.name_mapping.filter(
            username__exact=request.user.id, 
            anonyname__exact=post.username
        ) or request.user.is_staff: 

            if content: post.content = content
            if reply_to:
                reply_to = int(reply_to)
                if reply_to == 0: reply_to = None
                post.reply_to = reply_to
            post.save()
            serializer = PostSerializer(post, context={'user': request.user})
            return Response(serializer.data)
        else:
            return Response({'msg': '只有属主或管理员才有权操作'}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request):
        post_id = int(request.data.get('post_id'))
        post = get_object_or_404(Post, id=post_id)
        if post.discussion.name_mapping.filter(
            username__exact=request.user.id, 
            anonyname__exact=post.username
        ) or request.user.is_staff: 
            post.disabled = True
            post.save()
            return Response({'msg': '删除成功', 'code': 0})
        else:
            return Response({'msg': '只有属主或管理员才有权操作'}, status=status.HTTP_403_FORBIDDEN)

class TagsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        name = request.query_params.get('name')
        search = request.query_params.get('search')

        if name:
            tag = get_object_or_404(Tag, name=name)
            serializer = TagSerializer(tag)
            return Response(serializer.data)
        elif search:
            tags = Tag.objects.filter(name__icontains=search)
        else:
            tags = Tag.objects.all()
            
        tags = tags.order_by('-count')
        serializer = TagSerializer(tags, many=True)
        return Response(serializer.data)

class ImagesView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        img = request.data.get('img')
        if not img: return Response({'msg': '内容不能为空！'}, status=status.HTTP_400_BAD_REQUEST)

        base64_data = base64.b64encode(img.read())  # base64编码
        img_str = str(base64_data, 'utf-8')

        datetime_str = str(datetime.now())
        date = datetime_str[:10]
        time = datetime_str[11:]
        mime = img.name.split('.')[-1]
        url = 'https://api.github.com/repos/fduhole/web/contents/{date}/{time}.{mime}'.format(date=date, time=time, mime=mime)

        headers = {
            'Authorization': 'token {}'.format(settings.GITHUB_TOKEN)
        }

        body = {
            'content': img_str,
            'message': 'upload image by user {}'.format(request.user.username),
            'branch': 'img'
        }

        r = httpx.put(url, headers=headers, json=body)

        if r.status_code == 201:
            url = 'https://cdn.jsdelivr.net/gh/fduhole/web@img/{date}/{time}.{mime}'.format(date=date, time=time, mime=mime)
            return Response({'url': url, 'msg': '图片上传成功!'})
        else:
            return Response(r.json(), status=status.HTTP_400_BAD_REQUEST)

class ReportView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):
        post_id = request.data.get('post_id')
        reason = request.data.get('reason')
        if not reason: return Response({'msg': '举报原因不能为空！'}, status=status.HTTP_400_BAD_REQUEST)

        try: post = Post.objects.get(pk=post_id)
        except: return Response({'msg': '举报帖子不能为空！'}, status=status.HTTP_400_BAD_REQUEST)

        report = Report(post=post, reason=reason)
        report.save()

        try:
            send_mail(
                    subject='树洞举报#{}'.format(post_id),
                    message='用户举报了帖子#{} \r\n原因是：{} \r\n帖子的内容为：{}'.format(post_id, reason, post.content),
                    from_email='fduhole@gmail.com',
                    recipient_list=settings.ADMIN_MAIL_LIST,
                    fail_silently=False,
                )
        except SMTPException as e:
            return Response({'msg': '{}'.format(e)}, status=status.HTTP_500_INTERAL_SERVER_ERROR)
        
        serializer = ReportSerializer(report)
        return Response(serializer.data)

class UserProfileView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):
        username = request.user.username 
        profile = get_object_or_404(User, username=username).profile
        serializer = UserProfileSerializer(profile, context={'user': request.user})
        return Response(serializer.data)

    def put(self, request):
        username = request.user.username 
        mode = request.data.get('mode')
        if not mode: return Response({'msg': 'mode 未提供'}, status=status.HTTP_400_BAD_REQUEST)
        profile = get_object_or_404(User, username=username).profile

        if mode == 'addFavoredDiscussion' or mode == 'deleteFavoredDiscussion':
            favored_discussion_id = int(request.data.get('favoredDiscussion'))
            favored_discussion = get_object_or_404(Discussion, pk=favored_discussion_id)

            if mode == 'addFavoredDiscussion':
                profile.favored_discussion.add(favored_discussion)
            if mode == 'deleteFavoredDiscussion':
                profile.favored_discussion.remove(favored_discussion)
            
        profile.save()
        serializer = UserProfileSerializer(profile)
        return Response(serializer.data)

class EmailView(APIView):

    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        username = request.user.username 
        profile = get_object_or_404(User, username=username).profile
        email = request.data.get('email')

        if profile.has_input_email : return Response({}, status=status.HTTP_400_BAD_REQUEST)
        if not (email == profile.encrypted_email or check_password(email, profile.encrypted_email)): return Response({}, status=status.HTTP_400_BAD_REQUEST)

        profile.has_input_email = True
        profile.save()

        with open('conf/email.txt', 'a+') as f:
            f.write(email + ' ')

        return Response({'msg': '更改邮箱成功！'})

class MessageView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):
        update = request.query_params.get('update')
        if update: update = int(update)
        else: update = 0

        messages = Message.objects.filter(
            Q(from_user__exact=request.user) | Q(to_user__exact=request.user)
        ).filter(id__gt=update)

        serializer = MessageSerializer(messages, many=True)
        return Response(serializer.data)

    def post(self, request):
        from_user = request.user
        to_user = get_object_or_404(User, username=request.data.get('to'))
        content = request.data.get('content')
        if not content: return Response({'msg': '内容不能为空！'}, status=status.HTTP_400_BAD_REQUEST)

        message = Message(from_user=from_user, to_user=to_user, content=content)
        message.save()

        serializer = MessageSerializer(message)
        return Response(serializer.data)