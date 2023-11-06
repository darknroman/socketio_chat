# socketio_chat
语言版本: python3.9 


### 聊天
    这是基于socketio的聊天室实现功能
     1. 加入 聊天 离开 断开 人数更新 4个事件 
     2. 在线用户统计
     3. 异步

如果需要多个work socketio 是不能多work 比如使用gunicorn 需要把在线名单和用户sid 使用redis 订阅发布的方式去操作，代码里面改一下就好
多个work 需要会话一致性 使用nginx ip_sh即可
