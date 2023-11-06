from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room, send
from datetime import timedelta
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import time
import logging
from logging.handlers import RotatingFileHandler

async_mode = "eventlet"
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'xxxxxxxx'  # 设置一个密钥，用于签发和验证JWT Token
jwt = JWTManager(app)
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, message_queue='redis://127.0.0.1:6379/0', cors_allowed_origins="*",
                    manage_session=True, async_mode=async_mode, engineio_logger=True, allowed_upgrades=True)

# 日志配置
log_file = "log/socketio.log"
logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)
logging_handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=5)
logging_handler.setLevel(logging.DEBUG)
logging_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
logging_handler.setFormatter(logging_formatter)
logger.addHandler(logging_handler)

sensitive_words = [
 "敏感词添加，或者可以改成在redis获取"
]

# 使用字典来跟踪每个房间的参与人数
room_participants = {}

# 存储用户会话
req_sid = {}

# 获取在线人数时需要验证jwt
users = {
    "keys": ["xxxxxxx"]
}


# 登录路由，验证密钥，并生成JWT Token
@app.route('/api/v1/get_permissions', methods=['POST'])
def get_permissions():
    key = request.json.get('key')
    if key in users["keys"]:
        expires = timedelta(minutes=10)
        access_token = create_access_token(identity=key, expires_delta=expires)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401


# 统计人数返回后台
@app.route('/api/online', methods=['POST'])
@jwt_required()
def online():
    print(room_participants)
    return {"msg": room_participants, "code": 200}


def ip_addr(proxy_ip, ipaddr):
    if proxy_ip:
        return ipaddr
    else:
        return proxy_ip


# 生成房间号使用 雪花
def generate_unique_room_id():
    class Snowflake:
        def __init__(self, datacenter_id, worker_id):
            self.datacenter_id = datacenter_id
            self.worker_id = worker_id
            self.sequence = 0
            self.last_timestamp = -1

        def generate_id(self):
            timestamp = self._get_timestamp()

            if timestamp < self.last_timestamp:
                raise Exception("Invalid system clock!")

            if timestamp == self.last_timestamp:
                self.sequence = (self.sequence + 1) & 4095
                if self.sequence == 0:
                    timestamp = self._wait_next_millis(self.last_timestamp)
            else:
                self.sequence = 0

            self.last_timestamp = timestamp

            new_id = ((timestamp - 1288834974657) << 22) | (self.datacenter_id << 17) | (
                    self.worker_id << 12) | self.sequence
            return new_id

        def _get_timestamp(self):
            return int(time.time() * 1000)

        def _wait_next_millis(self, last_timestamp):
            timestamp = self._get_timestamp()
            while timestamp <= last_timestamp:
                timestamp = self._get_timestamp()
            return timestamp

    # 示例用法
    snowflake = Snowflake(datacenter_id=0, worker_id=0)
    generated_id = snowflake.generate_id()
    return generated_id


@app.route('/api/CreatePrivateRoom', methods=["POST"])
@jwt_required()
def private():
    if request.method == "POST":
        data = request.get_json()
        username = data["username"]
        anchor = data["anchor"]
        room_id = generate_unique_room_id()
        return jsonify({"code": 200, "result": {"message": "创建房间号成功", "room_id": room_id}})
    else:
        return "需要POST请求"


@app.route('/api/closure', methods=['POST'])
@jwt_required()
def closure():
    try:
        if request.method == "POST":
            data = request.get_json()
            room_id = data["room_id"]
            app.logger.info(f"请求data===>>>{data}")
            logger.info(f"删除前 房间列表 {room_participants}")
            if room_id in room_participants:
                del room_participants[room_id]
                ip = ip_addr(request.headers.get('X-Forwarded-For'), request.remote_addr)
                logger.info(f"删除房间==>> {room_participants[room_id]}")
                return jsonify(
                    {"code": 200, "result": [{"message": "房间删除成功", "room_id": data["room_id"], "ip": ip}]})
            else:
                return jsonify({"code": 200, "result": [{"message": "房间不存在"}]})
    except KeyError as e:
        logger.info(f"删除成功==>> {e}")
        data = request.get_json()
        print(room_participants)
        return jsonify({"code": 200, "result": [{"message": "房间删除成功", "room_id": data["room_id"]}]})
    except TypeError as e:
        logger.error("房间不存在出现异常")
        return jsonify({"message": "房间不存在", "room_id": e})


@app.route('/api/bot', methods=['POST'])
@jwt_required()
def bot():
    try:
        data = request.get_json()
        room_id = data["roomIds"]
        username = data["username"]
        message = data["message"]
        customize = data["customize"]
        length = len(room_id)
        ip = ip_addr(request.headers.get('X-Forwarded-For'), request.remote_addr)
        if length == 1:
            emit("message", {"message": message, "username": username, "customize": customize},
                 room=room_id[0],
                 namespace='/')
            logger.info(f"机器人发消息===>> {ip} 消息==>> {message}")
            return jsonify({'code': 200, "message": "发送成功", "result": {"message": "发送成功", "room_id": room_id}})
        else:
            for i in room_id:
                emit("message", {"message": message, "username": username, "customize": customize}, room=i,
                     namespace='/')
            return jsonify({'code': 200, "message": "发送成功", "result": {"message": "发送成功", "room_id": room_id}})
    except KeyError as e:
        data = request.get_json()
        room_id = data["roomIds"]
        logger.error(f"参数异常===>> {e}")
        return jsonify({"code": 400, "message": "发送失败", "result": {"message": "发送成功", "room_id": room_id}})
    except TypeError as e:
        logger.error(f"类型异常===>> {e}")


@socketio.on('join')
def handle_join(data):
    username = data['username']
    room_id = data['room_id']
    userid = data['userid']
    customize = None
    if "customize" in data:
        customize = data["customize"]
    sid = request.sid

    if room_id not in room_participants:
        room_participants[room_id] = []

    if username not in [participant.get('username') for participant in room_participants[room_id]]:
        logger.info(f"用户不在房间中,加入房间,")
        room_participants[room_id].append({
            'username': username,
            'customize': customize
        })
        print(room_participants)
        req_sid[sid] = username
        logger.info(req_sid)
        logger.info(f"用户 {username} 加入房间 ===>> {room_id}")

    try:
        join_room(room_id)
        logger.info("加入房间:{}<<-->>{}".format(room_id, username))
        message = f"您已加入房间 {room_id}"
        emit('message',
             {'username': username, 'message': message, 'typy': 'joinMsg', 'userid': userid, 'customize': customize},
             room=room_id, namespace='/')

        emit('participants_update', {'room_id': room_id, 'count': len(room_participants[room_id])}, room=room_id,
             namespace='/')
    except (KeyError, TypeError) as e:
        logger.error(f"加入房间事件出现异常===>> {e}")


@socketio.on('message')
def handle_message(data):
    message = data['message']
    username = data['username']
    room_id = data['room_id']
    customize = None
    if "customize" in data:
        customize = data["customize"]
    msg_id = data['msgId']
    ty_pe = data['type']
    try:
        for word in sensitive_words:
            message = message.replace(word, '*' * len(word))
        logger.info(f"发送消息 {message} ===>> 用户 {username}  == >> 房间 {room_id}")
        emit('message',
             {'username': username, 'message': message, "customize": customize, "msgId": msg_id, "typy": ty_pe},
             room=room_id, namespace='/')
    except KeyError as e:
        logger.error(f"没有传完整参数导致异常 ==>> {e}")
    except TypeError as e:
        logger.error(f"参数类型错误导致异常 ===>>> {e}")


@socketio.on('leave')
def handle_leave(data):
    username = data.get('username')  # 获取用户名
    room_id = data.get('room_id')
    sid = request.sid
    customize = None
    if "customize" in data:
        customize = data["customize"]

    if room_id in room_participants:  # 检查房间是否存在于字典中
        if username in [participant.get('username') for participant in room_participants[room_id]]:
            logger.info(f"删除用户会话{req_sid[sid]},")

            for participant in room_participants[room_id]:
                if participant.get('username') == username:
                    room_participants[room_id].remove(participant)
                    break

            del req_sid[sid]

            if len(room_participants[room_id]) == 0:  # 如果房间的用户名列表为空
                del room_participants[room_id]  # 从字典中删除该房间

            # 向房间内的所有用户发送 'participants_update' 事件，以更新房间的参与人数
            emit('participants_update',
                 {'room_id': room_id, 'count': len(room_participants.get(room_id, [])), "customize": customize},
                 room=room_id, namespace='/')

            message = username + '离开了房间'  # 生成离开房间的消息
            logger.info(f"用户离开房间 ===>> {username}")
            emit('message', {'username': username, 'message': message, "customize": customize}, room=room_id,
                 namespace='/')
            # 向房间内的其他用户发送消息，告知该用户已离开房间
        else:
            logger.info("用户不在房间中")
    else:
        logger.info("房间不存在")


@socketio.on('participants_update')
def handle_participants_update(data):
    room_id = data['room_id']
    count = data['count']
    emit('participants_update', {'room_id': room_id, 'count': count}, room=room_id, namespace='/')


@socketio.on('image')
def handle_image(data):
    username = data['username']
    room_id = data['room_id']
    image_data = data['image']
    customize = None
    if "customize" in data:
        customize = data["customize"]
    logger.info(f"用户发送礼物, ==>> {username} 房间===>>{room_id}")
    emit("message", {"message": image_data, "username": username, "customize": customize}, room=room_id, namespace='/')


@socketio.on('ping')
def handle_ping(data):
    try:
        message = data["message"]  # 响应消息
        emit('ping', {"message": message, "typy": "pingMsg"})
    except KeyError as e:
        logger.error(f"ping事件异常 ===>> 消息导致异常===>> {e}")


@socketio.on('connect')
def connect():
    message = {"message": "连接成功"}
    emit('connect', message)


@socketio.on('disconnect')
def handle_disconnect():
    disconnected_sid = request.sid

    try:
        username = req_sid.pop(disconnected_sid, None)
        logger.info(f"从会话删除用户 {username}, {disconnected_sid}")
        if username:
            logger.info(f"断开连接用户: {username}")
            logger.info(f"{req_sid}")

            for room_id, participants in room_participants.items():
                users_to_remove = []
                for participant in participants:
                    if username in participant.get('username', ''):
                        users_to_remove.append(participant)

                for user_to_remove in users_to_remove:
                    participants.remove(user_to_remove)
                    logger.info(f"从房间 {room_id} 删除用户: {username}")


        else:
            logger.error(f"无法找到断开连接的用户的会话标识符: {disconnected_sid}")
    except Exception as e:
        logger.error(f"处理断开连接事件时出现异常: {e}")


if __name__ == '__main__':
    socketio.run(app, port=5000)
